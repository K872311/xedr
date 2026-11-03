package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// runAgent 注册后按周期采集并实时回传，直到 ctx 取消。
func runAgent(ctx context.Context, cfg Config, cfgPath string) error {
	_ = ensureDir(cfg.StateDir)
	setupFileLog(cfg.StateDir)
	checkUpgradeWatchdog(cfg)

	api := newClient(cfg)
	tl := newTimelineWatcher()
	box := newOutbox(cfg.StateDir)
	globalCfg = cfg
	globalAPI = api
	loadEmbeddedMemoryRules()
	loadEmbeddedEVM()
	go func() { _ = syncMemoryYaraRules(memoryScanSettingsSnapshot().RulesRev) }()
	eventThrottle := newEventThrottle()
	inv := newInventory(box.st)
	var deltaCap atomic.Bool
	box.onReject = func(kind outboxKind, payload map[string]any, msg string) {
		if kind == outSnapshotDelta || kind == outSnapshot {
			mod := asString(payload["module"])
			gen, _ := strconv.ParseInt(asString(payload["generation"]), 10, 64)
			log.Printf("[%s] 清单 generation=%d 被拒（%s），下一轮发全量", mod, gen, msg)
			inv.invalidate(mod, gen)
		}
	}
	setProtectStateDir(cfg.StateDir)
	// 先启原生 ETW：成功则不再拉 WMI PowerShell 进程监控（否则双重采集 + 每进程 SHA256 会拖死测试机）
	etw := newETWWatcher()
	etw.start(ctx)
	defer etw.stop()
	setSensorPipeline("starting", "winevent", "")
	startSensorHealLoop(ctx, etw)
	etwMode := etw.waitMode(4 * time.Second)
	captureETWStatusFn = func() (string, bool) {
		m := etw.status()
		return m, m == "etw_native" || m == "etw_evt"
	}
	startCmdBackfillLoop(ctx)
	watch := newProcessWatcher()
	wmiProc := etwMode != "etw_native" || integrationEnabled("wmi_process")
	if wmiProc {
		watch.start(ctx)
		log.Printf("process watcher: ETW=%s，WMI 进程监控=%v", etwMode, integrationEnabled("wmi_process") || etwMode != "etw_native")
	} else {
		log.Printf("process watcher: ETW 原生已接管，跳过 WMI")
	}
	defer watch.stop()
	// winevent 延后启动，避免与 ETW/注册/首轮采集抢 CPU
	logTailGlobal = newLogTailWatcher()
	logTailGlobal.start(ctx)
	wevt := newWinEventWatcher()
	wevt.bookmarkDir = filepath.Join(cfg.StateDir, "bookmarks")
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Second):
		}
		wevt.start(ctx)
	}()
	defer wevt.stop()
	persist := newPersistWatcher()
	wmiPersist := newWMIPersistWatcher()
	wmiPersist.start(ctx)
	regw := newRegWatcher(box.st)
	globalRegWatcher = regw
	regOn := regw.start(ctx)
	applyRegistryFIMSync(regw)
	defer regw.stop()
	persist.setRegistryRealtime(regOn)
	go persist.startLoop(ctx)
	fim := newFIMWatcher(box.st, cfg.StateDir)
	defer fim.stop()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				procEntities.gc(livePIDSet())
			}
		}
	}()
	kern := newKernelWatcher()
	kernelOn := kern.start(ctx)
	defer kern.stop()
	devw := newDeviceWatcher()
	if integrationEnabled("device") {
		devw.start(ctx)
	}
	// 原生 ETW 已覆盖进程/网络/文件落地，关掉 6 秒一轮的快照差分（否则反复 PowerShell 验签/扫盘）
	if etwMode == "etw_native" {
		tl.setEnabled(false)
		tl.setFileEnabled(false)
		tl.setNetEnabled(false)
		log.Printf("timeline snapshot-diff: 已关闭（由 ETW/FIM 接管）")
	}
	sensor := "etw+winevent"
	if wmiProc {
		sensor = "etw+wmi+winevent"
	}
	if kernelOn {
		sensor = "kernel+" + sensor
	}

	hn := hostname()
	ip := primaryIP()
	log.Printf("forensic-agent %s  host=%s ip=%s → %s (outbox=%d sensor=%s)", agentVersion, hn, ip, cfg.ServerURL, box.pending(), sensor)

	box.cmdPurge()
	health := newHealthCollector()
	health.sensorsFn = func() map[string]any {
		s := map[string]any{
			"etw": etw.status(), "kernel": kernelOn, "mode": sensor,
			"registry_realtime": regOn, "fim": fim.running(), "entities": procEntities.size(),
			"entities_rev":      procEntities.revision(),
			"capture_status":    captureStatusSnapshot(),
			"components":        componentHealthSnapshot(),
			"telemetry":         telemetryMetricsSnapshot(),
			"sensor_pipeline":   sensorPipelineSnapshot(),
			"winevent_channels": len(winevtChannelDefsFiltered()),
			"winevent_manifest": winevtChannelManifest(),
			"host_metrics":      hostMetricsSnapshot(),
			"elastic_parity":    elasticParitySnapshot(),
			"dynamic_fim":       dynamicFIMCount(),
		}
		s["capture_health"] = computeCaptureHealthScore(s)
		return s
	}
	health.authMode = func() string {
		if s, _ := api.credential(); s != "" {
			return "agent_secret"
		}
		return "shared_key"
	}
	protoSelected := 1
	health.protoFn = func() int { return protoSelected }

	// 模块采集与差分时间线在独立 goroutine 里跑（单个模块可能耗时数十秒），
	// 主循环只负责心跳/命令/实时传感器转发；共享的周期与 agent_id 用锁保护。
	var ivMu, aidMu sync.Mutex
	setIv := func(k string, v int) {
		ivMu.Lock()
		cfg.Intervals[k] = v
		ivMu.Unlock()
	}
	ivOf := func(mod string) time.Duration {
		ivMu.Lock()
		defer ivMu.Unlock()
		return cfg.interval(mod)
	}
	aidNow := func() string {
		aidMu.Lock()
		defer aidMu.Unlock()
		return cfg.AgentID
	}

	// 已有独立凭据则优先使用；失效（换机/吊销/轮换丢失）时回落共享密钥重新注册
	if cfg.Secret != "" && cfg.AgentID != "" {
		api.setCredential(cfg.Secret, cfg.AgentID)
	}
	// 凭据被服务端拒绝：丢弃本地凭据，改用共享密钥重新换取
	dropSecret := func(why error) {
		log.Printf("独立凭据被拒绝（%v），回落共享密钥重新注册", why)
		api.setCredential("", "")
		cfg.Secret, cfg.SecretBlob = "", ""
		if cfgPath != "" {
			_ = cfg.saveAgentID(cfgPath)
		}
	}
	// 注册成功后接收服务端新签发的凭据：DPAPI 加密落盘并立即启用
	adoptRegistration := func(r *registerResp) {
		aidMu.Lock()
		cfg.AgentID = r.AgentID
		aidMu.Unlock()
		protoSelected = r.ProtocolSelected
		if r.Warning != "" {
			log.Printf("协议告警: %s", r.Warning)
		}
		if r.AgentSecret != "" {
			if blob, err := protectSecret(r.AgentSecret); err == nil {
				cfg.Secret, cfg.SecretBlob = r.AgentSecret, blob
				api.setCredential(r.AgentSecret, r.AgentID)
				if cfgPath != "" {
					if e := cfg.saveAgentID(cfgPath); e != nil {
						log.Printf("保存独立凭据失败: %v", e)
					}
				}
				log.Printf("已获得独立凭据（DPAPI 保护）")
			} else {
				log.Printf("凭据加密失败，本次仍使用共享密钥: %v", err)
			}
		} else if cfg.Secret != "" {
			api.setCredential(cfg.Secret, r.AgentID)
		}
		useV2 := r.ProtocolSelected >= 2 && hasCap(r.EnabledCaps, "ingest.v2")
		box.useV2.Store(useV2)
		deltaCap.Store(useV2 && hasCap(r.EnabledCaps, "inventory.delta"))
		if b, err := json.Marshal(map[string]any{"proto": r.ProtocolSelected, "caps": r.EnabledCaps}); err == nil {
			box.st.kvSet("negotiated", string(b))
		}
	}
	// cachedRegistration 服务端不可达时用上次协商结果离线启动（采集照常落 outbox，联网后补发）
	cachedRegistration := func() *registerResp {
		if cfg.AgentID == "" || cfg.Once {
			return nil
		}
		var n struct {
			Proto int      `json:"proto"`
			Caps  []string `json:"caps"`
		}
		if json.Unmarshal([]byte(box.st.kvGet("negotiated")), &n) != nil {
			return nil
		}
		return &registerResp{AgentID: cfg.AgentID, ProtocolSelected: n.Proto, EnabledCaps: n.Caps}
	}
	offline := false

	var reg *registerResp
	backoff := 3 * time.Second
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		r, err := api.Register(hn, osFamily(), primaryIP(), agentVersion, cfg.AgentID)
		if err != nil && isAuthError(err) {
			if s, _ := api.credential(); s != "" {
				dropSecret(err)
				continue
			}
		}
		if err == nil && r != nil && r.AgentID != "" {
			reg = r
			break
		}
		if c := cachedRegistration(); c != nil && !isAuthError(err) {
			log.Printf("服务端不可达（%v），以缓存身份 %s 离线启动，联网后补注册", err, c.AgentID)
			reg, offline = c, true
			break
		}
		log.Printf("register 重试中: %v（%s 后再试）", err, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 2*time.Minute {
			backoff *= 2
		}
	}
	adoptRegistration(reg)
	if cfgPath != "" {
		_ = cfg.saveAgentID(cfgPath)
	}
	log.Printf("registered agent_id=%s modules=%v build=%s protocol=%d v2=%v server_caps=%v",
		cfg.AgentID, cfg.Modules, buildID, reg.ProtocolSelected, box.useV2.Load(), reg.ServerCaps)
	if !cfg.Once {
		go box.run(ctx, api)
	}

	for k, v := range reg.IntervalsSec {
		if v > 0 {
			setIv(k, v)
		}
	}

	refreshCh := make(chan struct{}, 1)
	responseEnabled := true
	fimWanted, fimPaths := true, []string(nil)
	var ruleFIMPaths []string
	fimApplied := ""

	// syncFIM 按策略启停 FIM；自定义目录或规则目录变化时重启监控
	syncFIM := func() {
		if cfg.Once {
			return
		}
		dyn := snapshotDynamicFIMPaths()
		all := append(append(append([]string(nil), fimPaths...), ruleFIMPaths...), dyn...)
		want := fmt.Sprintf("%v|%s", fimWanted, strings.Join(all, ";"))
		if want == fimApplied {
			return
		}
		fimApplied = want
		if fim.running() {
			fim.stop()
		}
		if fimWanted {
			fim.setExtra(all)
			fim.start(ctx)
		}
	}

	applyPolicy := func(pol map[string]any, rev int) {
		if pol == nil {
			return
		}
		if v, ok := pol["fim_enabled"].(bool); ok {
			fimWanted = v
		}
		if arr, ok := pol["fim_paths"].([]any); ok {
			fimPaths = nil
			for _, x := range arr {
				if s := strings.TrimSpace(asString(x)); s != "" {
					fimPaths = append(fimPaths, s)
				}
			}
		}
		if iv, ok := pol["intervals_sec"].(map[string]any); ok {
			for k, v := range iv {
				switch n := v.(type) {
				case float64:
					if n > 0 {
						setIv(k, int(n))
					}
				case int:
					if n > 0 {
						setIv(k, n)
					}
				}
			}
		}
		if v, ok := pol["response_enabled"].(bool); ok {
			responseEnabled = v
		}
		if v, ok := pol["timeline_process"].(bool); ok {
			tl.setEnabled(v)
		}
		if v, ok := pol["timeline_file"].(bool); ok {
			tl.setFileEnabled(v)
		}
		if v, ok := pol["timeline_network"].(bool); ok {
			tl.setNetEnabled(v)
		}
		if v, ok := pol["self_protect"].(bool); ok {
			setSelfProtect(v)
			if kern.active() {
				pid := uint32(0)
				if v {
					pid = uint32(os.Getpid())
				}
				if err := kern.protectSelf(pid); err != nil {
					log.Printf("kernel protect: %v", err)
				}
			}
		}
		applyMemoryScanPolicy(pol)
		applyIntegrationsPolicy(pol)
		applyLogTailPolicy(pol)
		applyWineventChannelsPolicy(pol)
	}
	ruleFIMSyncFn = func(paths []string) {
		setRuleFIMPathsFromSync(paths, &ruleFIMPaths)
	}

	// 所有上行数据一律先落盘 outbox，再由后台发送器批量投递（崩溃/断网都不丢）
	ackReliable := func(id string, ok bool, result map[string]any) {
		queueHeartbeatAck(id, ok, result)
		box.enqueue(outAck, 100, map[string]any{"id": id, "ok": ok, "result": result})
	}

	pushTimeline := func(events []map[string]any) {
		events = filterTimelineEvents(events)
		if len(events) == 0 {
			return
		}
		annotateEntities(events)
		enrichTimelineEventsECS(events)
		raw := make([]any, 0, len(events))
		for _, e := range events {
			raw = append(raw, e)
		}
		box.enqueue(outTimeline, 80, map[string]any{
			"agent_id": aidNow(), "hostname": hostname(), "events": raw,
		})
	}

	responseEvent := func(sev, title, detail string, prio int) {
		box.enqueue(outEvent, prio, map[string]any{
			"agent_id": aidNow(), "module": "response", "severity": sev,
			"title": title, "detail": detail,
		})
	}
	emitCommandOutcome := func(action string, ok bool, detail string, _ map[string]any) {
		act := strings.ToLower(strings.TrimSpace(action))
		if ok {
			responseEvent("info", "处置成功："+act, detail, 70)
			return
		}
		responseEvent("high", "处置失败："+act, detail, 90)
	}

	handleCommands := func(cmds []agentCommand) {
		for _, cmd := range cmds {
			// 1) 已有回执：只重放 ACK，不重复执行（lease 过期重投 / ACK 丢失）
			if rc := box.cmdReceipt(cmd.ID); rc != nil {
				if rc.Status == "done" {
					log.Printf("command %s 已执行过，重放 ACK", cmd.ID)
					ackReliable(cmd.ID, rc.OK, rc.Result)
					continue
				}
				// started 但没有结果：上次执行中途崩溃
				if nonIdempotentAction(strings.ToLower(cmd.Action)) {
					res := map[string]any{"error": "上次执行被中断，非幂等动作不会自动重跑，请核实后重新下发", "interrupted": true}
					box.cmdFinish(cmd.ID, false, res)
					ackReliable(cmd.ID, false, res)
					continue
				}
			}
			// 2) 超过截止时间不再执行
			if commandExpired(cmd.Deadline) {
				res := map[string]any{"error": "deadline exceeded，命令已过期未执行"}
				box.cmdBegin(cmd.ID, cmd.Action)
				box.cmdFinish(cmd.ID, false, res)
				ackReliable(cmd.ID, false, res)
				continue
			}
			if !responseEnabled &&
				cmd.Action != "refresh_modules" && cmd.Action != "upgrade" && cmd.Action != "uninstall_agent" && cmd.Action != "scan_memory" {
				res := map[string]any{"error": "response disabled by policy"}
				box.cmdBegin(cmd.ID, cmd.Action)
				box.cmdFinish(cmd.ID, false, res)
				ackReliable(cmd.ID, false, res)
				continue
			}
			if !cmdSchedulerTry(cmd.Action) {
				res := map[string]any{"error": "命令调度：与维护/扫描任务互斥，稍后重试"}
				box.cmdBegin(cmd.ID, cmd.Action)
				box.cmdFinish(cmd.ID, false, res)
				ackReliable(cmd.ID, false, res)
				continue
			}
			defer cmdSchedulerDone(cmd.Action)
			log.Printf("exec command %s action=%s attempt=%d", cmd.ID, cmd.Action, cmd.Attempt)
			box.cmdBegin(cmd.ID, cmd.Action)
			res, err := execCommand(cfg, cmd)
			if err != nil {
				log.Printf("command %s failed: %v", cmd.ID, err)
				out := map[string]any{"error": err.Error(), "result": res}
				box.cmdFinish(cmd.ID, false, out)
				ackReliable(cmd.ID, false, out)
				emitCommandOutcome(cmd.Action, false, err.Error(), res)
				continue
			}
			box.cmdFinish(cmd.ID, true, res)
			ackReliable(cmd.ID, true, res)
			emitCommandOutcome(cmd.Action, true, mustJSON(res), res)
			if cmd.Action == "refresh_modules" {
				select {
				case refreshCh <- struct{}{}:
				default:
				}
			}
		}
	}

	// 策略：先应用本地 LKG（离线重启也保持上次有效策略），之后由心跳驱动原子生效/试用/回滚
	bindEvmStore(box.st)
	_ = loadEvmLKGOffline()
	pm := newPolicyManager(box.st, func(p map[string]any) {
		applyPolicy(p, 0)
		syncFIM()
	})
	globalPolicyManager = pm
	pm.boot()
	startRootcheckLoop(ctx, box, aidNow)
	startSCALoop(ctx, box, aidNow)
	go func() {
		time.Sleep(2 * time.Second)
		maybeSyncFromServer(api, cfg.AgentID, 1<<30, pm, syncFIM)
	}()

	healthSnap := func() map[string]any {
		s := health.snapshot(box)
		s["policy"] = pm.state()
		s["fleet"] = fleetSnapshot(pm)
		s["host"] = hostMetadata()
		if ud := upgradeDetailsSnapshot(cfg); ud != nil {
			s["upgrade_details"] = ud
		}
		return s
	}
	doHeartbeat := func() (*heartbeatResp, error) {
		snap := healthSnap()
		hb, err := api.Heartbeat(cfg.AgentID, primaryIP(), snap, pm)
		if err != nil && isAuthError(err) {
			if s, _ := api.credential(); s != "" {
				dropSecret(err)
				// 立即用共享密钥重新注册换取新凭据，再重试一次心跳
				if r, e2 := api.Register(hostname(), osFamily(), primaryIP(), agentVersion, cfg.AgentID); e2 == nil {
					adoptRegistration(r)
					hb, err = api.Heartbeat(cfg.AgentID, primaryIP(), snap, pm)
				}
			}
		}
		if err == nil {
			heartbeatBackoffOK()
			cpu, _ := numberOf(snap["cpu_pct"])
			rss, _ := numberOf(snap["rss_mb"])
			pm.heartbeatOK(cpu, rss)
			markUpgradeHealthy(cfg)
		} else {
			heartbeatBackoffFail()
		}
		return hb, err
	}

	reportAll := func() {
		hb, err := doHeartbeat()
		if err != nil {
			log.Printf("heartbeat: %v", err)
		} else if hb != nil {
			noteServerRevs(hb.SyncRev, hb.PolicyRev)
			if len(hb.AckedCommandIDs) > 0 {
				confirmHeartbeatAcks(hb.AckedCommandIDs)
			}
			for k, v := range hb.IntervalsSec {
				if v > 0 {
					setIv(k, v)
				}
			}
			pm.offer(hb.PolicyRev, hb.Policy)
			maybeSyncFromServer(api, cfg.AgentID, hb.SyncRev, pm, syncFIM)
			handleCommands(hb.Commands)
		}
		if !cfg.Once {
			return // 常驻模式由采集 goroutine 首轮全量采集，主循环不等
		}
		var wg sync.WaitGroup
		sem := make(chan struct{}, 2)
		for _, mod := range cfg.Modules {
			mod := mod
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				reportModule(box, inv, cfg.AgentID, mod, false)
			}()
		}
		wg.Wait()
	}

	reportAll()
	syncFIM() // 无任何策略时按默认启动 FIM
	pushTimeline([]map[string]any{{
		"etype": "sensor_status", "summary": "传感器模式: " + sensor, "severity": "info",
		"ts":     time.Now().Format("2006-01-02T15:04:05"),
		"detail": map[string]any{"sensor": sensor, "kernel": kernelOn, "etw": etw.status(), "version": agentVersion, "build_id": buildID},
	}})
	if cfg.Once {
		// once 没有后台发送器，同步发完再退出
		for i := 0; i < 5 && box.pending() > 0; i++ {
			box.flush(api)
			time.Sleep(300 * time.Millisecond)
		}
		log.Printf("once 模式完成（outbox 剩余 %d）", box.pending())
		return nil
	}

	for _, mod := range cfg.Modules {
		log.Printf("schedule %s every %s", mod, ivOf(mod))
	}

	// 模块采集：首轮全量（lastRun 为空），之后按周期；refresh_modules 命令触发立即全量
	// software/hotfix/driver 启动即全量会与传感器抢磁盘/CPU，首轮先占位等满周期再采
	heavyFirst := map[string]bool{"software": true, "hotfix": true, "driver": true, "browser": true}
	go func() {
		lastRun := map[string]time.Time{}
		boot := time.Now()
		// 首轮错开：启动 45s 后开始，每个模块间隔 20s，避免与 FIM/ETW 初始化同时拉起多个 PowerShell
		for i, mod := range cfg.Modules {
			if heavyFirst[mod] {
				continue
			}
			firstAt := boot.Add(45*time.Second + time.Duration(i)*20*time.Second)
			lastRun[mod] = firstAt.Add(-ivOf(mod))
		}
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		runDue := func(force bool) {
			for _, mod := range cfg.Modules {
				if ctx.Err() != nil {
					return
				}
				now := time.Now()
				if last, ok := lastRun[mod]; ok && !force && now.Sub(last) < ivOf(mod) {
					continue
				}
				if !force {
					if _, ok := lastRun[mod]; !ok && heavyFirst[mod] {
						lastRun[mod] = boot
						continue
					}
				}
				reportModule(box, inv, aidNow(), mod, deltaCap.Load() && box.useV2.Load())
				lastRun[mod] = time.Now()
			}
		}
		runDue(false)
		for {
			select {
			case <-ctx.Done():
				return
			case <-refreshCh:
				runDue(true)
			case <-t.C:
				runDue(false)
			}
		}
	}()
	// 快照差分时间线（ETW 不可用时的兜底）：采集慢，同样不阻塞主循环
	go func() {
		t := time.NewTicker(6 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				tl.tickQueued(api, cfg, pushTimeline)
			}
		}
	}()

	hbSec := 3
	hb := time.NewTicker(time.Duration(hbSec) * time.Second)
	defer hb.Stop()
	liveTick := time.NewTicker(1 * time.Second)
	defer liveTick.Stop()

	// pushLive 汇总各实时传感器缓冲并落 outbox
	pushLive := func() {
		live := watch.drain()
		live = append(live, etw.drain()...)
		live = append(live, wevt.drain()...)
		live = append(live, persist.drain()...)
		live = append(live, wmiPersist.drain()...)
		live = append(live, regw.drain()...)
		live = append(live, fim.drain()...)
		if logTailGlobal != nil {
			live = append(live, logTailGlobal.drain()...)
		}
		live = append(live, kern.drain()...)
		if integrationEnabled("device") {
			live = append(live, devw.drain()...)
		}
		// 过滤纯状态心跳，避免刷屏；保留首条 etw_status
		filtered := make([]map[string]any, 0, len(live))
		for _, ev := range live {
			et, _ := ev["etype"].(string)
			if et == "etw_status" || et == "winevent_status" {
				sum, _ := ev["summary"].(string)
				if strings.Contains(sum, "不可用") {
					continue
				}
			}
			filtered = append(filtered, ev)
		}
		filtered = normalizeLiveProcessEvents(filtered)
		filtered = processLiveEvents(filtered, cfg, responseEnabled, eventThrottle)
		for _, ev := range filtered {
			notePayloadFromEvent(ev)
			correlateProcessWithPayload(ev)
			if !integrationEnabled("memory_scan") {
				continue
			}
			if res := runTriggeredMemoryScan(ev); res != nil {
				if n, _ := res["finding_count"].(int); n > 0 {
					enqueueMemoryFindings(box, aidNow(), res)
				} else if fn, ok := res["finding_count"].(float64); ok && int(fn) > 0 {
					enqueueMemoryFindings(box, aidNow(), res)
				}
			}
		}
		// 载荷临时 FIM：动态路径变化时重挂 FIM（与策略路径合并）
		syncFIM()
		pushTimeline(filtered)
	}

	var lastMemScheduledScan time.Time
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ms := memoryScanSettingsSnapshot()
				if ms.Mode != memModeYaraScheduled {
					continue
				}
				iv := ms.ScheduleInterval
				if iv <= 0 {
					iv = 1800
				}
				if time.Since(lastMemScheduledScan) < time.Duration(iv)*time.Second {
					continue
				}
				lastMemScheduledScan = time.Now()
				res, err := scanMemory(map[string]any{"trigger": "schedule"})
				if err != nil {
					continue
				}
				if fc, _ := res["finding_count"].(int); fc > 0 {
					enqueueMemoryFindings(box, aidNow(), res)
				}
			}
		}
	}()

	reRegister := func() bool {
		r, err := api.Register(hostname(), osFamily(), primaryIP(), agentVersion, cfg.AgentID)
		if err != nil {
			log.Printf("re-register: %v", err)
			return false
		}
		adoptRegistration(r)
		if cfgPath != "" {
			_ = cfg.saveAgentID(cfgPath)
		}
		log.Printf("re-registered agent_id=%s", cfg.AgentID)
		return true
	}

	for {
		if offline {
			select {
			case <-ctx.Done():
				log.Println("agent 停止")
				return nil
			case <-hb.C:
				// 离线启动：每个心跳周期补一次注册，成功后进入正常流程
				if reRegister() {
					offline = false
				}
			case <-liveTick.C:
				pushLive()
			}
			continue
		}
		select {
		case <-ctx.Done():
			log.Println("agent 停止")
			return nil
		case <-hb.C:
			out, err := doHeartbeat()
			if err != nil {
				log.Printf("heartbeat: %v", err)
				if strings.Contains(err.Error(), "未知") {
					reRegister()
				} else if isCredentialRejected(err) {
					// 服务端记录被删 / 数据库重建：独立凭据已失效，退回接入密钥重新注册
					api.setCredential("", cfg.AgentID)
					reRegister()
				}
			} else {
				noteServerRevs(out.SyncRev, out.PolicyRev)
				if len(out.AckedCommandIDs) > 0 {
					confirmHeartbeatAcks(out.AckedCommandIDs)
				}
				for k, v := range out.IntervalsSec {
					if v > 0 {
						setIv(k, v)
					}
				}
				pm.offer(out.PolicyRev, out.Policy)
				applyHeartbeatPolicyPatch(out.Policy)
				pullMemoryYaraIfNeeded(out.MemoryYaraRev)
				maybeSyncFromServer(api, cfg.AgentID, out.SyncRev, pm, syncFIM)
				handleCommands(out.Commands)
				if out.RuleFIMPaths != nil {
					rp := out.RuleFIMPaths
					if len(rp) > 20 {
						rp = rp[:20]
					}
					if strings.Join(rp, ";") != strings.Join(ruleFIMPaths, ";") {
						ruleFIMPaths = append([]string(nil), rp...)
						log.Printf("规则监控目录: %v", ruleFIMPaths)
						syncFIM()
					}
				}
				if out.HeartbeatSec >= 3 && out.HeartbeatSec <= 120 && out.HeartbeatSec != hbSec {
					hbSec = out.HeartbeatSec
					hb.Reset(time.Duration(hbSec) * time.Second)
				}
			}
		case <-liveTick.C:
			pushLive()
		}
	}
}

// annotateEntities 给带 pid 的事件补进程实体；进程创建类事件附带完整实体字段。
func annotateEntities(events []map[string]any) {
	for _, ev := range events {
		d, _ := ev["detail"].(map[string]any)
		if d == nil {
			continue
		}
		e := procEntities.annotate(d, parseLocalTS(asString(ev["ts"])))
		if e == nil {
			continue
		}
		switch asString(ev["etype"]) {
		case "process_create", "process_create_live", "process_create_etw":
			mergeInto(d, procEntities.fieldsOf(e))
			if cmd := strings.TrimSpace(asString(d["command_line"])); cmd != "" {
				procEntities.applyCmdLine(uint32(asInt(d["pid"])), parseLocalTS(asString(ev["ts"])), cmd, asString(d["user"]))
			}
		case "process_exit":
			procEntities.markExited(e.ID, 0)
		}
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	if len(b) > 1500 {
		return string(b[:1500])
	}
	return string(b)
}

func hasCap(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

func reportModule(box *outbox, inv *inventory, agentID, module string, deltaOK bool) {
	items, err := collectModule(module)
	if err != nil {
		log.Printf("[%s] collect: %v", module, err)
		box.enqueue(outEvent, 90, map[string]any{
			"agent_id": agentID, "module": module, "severity": "high",
			"title": "采集失败：" + module, "detail": err.Error(),
		})
		return
	}
	if items == nil {
		items = []any{}
	}
	p := inv.plan(module, agentID, items, deltaOK)
	if p.skip {
		return
	}
	// 先落盘 outbox：全量会取代同模块旧全量与未发出的增量
	box.enqueue(p.kind, 50, p.payload)
	if p.kind == outSnapshotDelta {
		ups, _ := p.payload["upserts"].([]map[string]any)
		rms, _ := p.payload["removes"].([]string)
		log.Printf("[%s] queued delta gen=%v +%d -%d (共 %d)", module, p.payload["generation"], len(ups), len(rms), len(items))
	} else {
		log.Printf("[%s] queued full gen=%v %d items", module, p.payload["generation"], len(items))
	}
}
