package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// 轻量「类 ETW」：进程/文件/网络差分，推入时间线（无需驱动）。
type timelineWatcher struct {
	mu         sync.Mutex
	prevPID    map[int]string
	prevProc   map[int]map[string]any // 上一轮进程元数据（退出事件补 guid）
	prevFile   map[string]string      // path -> modified
	prevNet    map[string]bool        // remote key
	enabled    bool
	netOn      bool
	fileOn     bool
}

func newTimelineWatcher() *timelineWatcher {
	return &timelineWatcher{
		prevPID:  map[int]string{},
		prevProc: map[int]map[string]any{},
		prevFile: map[string]string{},
		prevNet:  map[string]bool{},
		enabled:  true,
		netOn:    true,
		fileOn:   true,
	}
}

func (w *timelineWatcher) setEnabled(on bool) {
	w.mu.Lock()
	w.enabled = on
	w.mu.Unlock()
}

func (w *timelineWatcher) setFileEnabled(on bool) {
	w.mu.Lock()
	w.fileOn = on
	w.mu.Unlock()
}

func (w *timelineWatcher) setNetEnabled(on bool) {
	w.mu.Lock()
	w.netOn = on
	w.mu.Unlock()
}

func (w *timelineWatcher) tick(api *APIClient, cfg Config) {
	w.tickQueued(api, cfg, func(events []map[string]any) {
		if err := api.Timeline(cfg.AgentID, hostname(), events); err != nil {
			log.Printf("timeline: %v", err)
		} else {
			log.Printf("timeline uploaded %d events", len(events))
		}
	})
}

func (w *timelineWatcher) tickQueued(api *APIClient, cfg Config, push func([]map[string]any)) {
	w.mu.Lock()
	on := w.enabled
	w.mu.Unlock()
	if !on {
		return
	}
	w.mu.Lock()
	fileOn, netOn := w.fileOn, w.netOn
	w.mu.Unlock()
	var events []map[string]any
	events = append(events, w.diffProcesses()...)
	if fileOn {
		events = append(events, w.diffFiles()...)
	}
	if netOn {
		events = append(events, w.diffNetwork()...)
	}
	if len(events) == 0 {
		return
	}
	push(events)
}

func (w *timelineWatcher) diffProcesses() []map[string]any {
	// 差分只需 PID/名称，禁止走 enrichPEMeta / Modules（否则每 6 秒拉起 PowerShell）
	items, err := collectProcessesLite()
	if err != nil {
		return nil
	}
	cur := map[int]string{}
	meta := map[int]map[string]any{}
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		pid := asInt(m["pid"])
		name := asString(m["name"])
		if pid <= 0 || name == "" {
			continue
		}
		cur[pid] = name
		meta[pid] = m
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []map[string]any
	if len(w.prevPID) == 0 {
		w.prevPID = cur
		w.prevProc = meta
		return nil
	}
	now := time.Now().Format("2006-01-02T15:04:05")
	for pid, name := range cur {
		if _, ok := w.prevPID[pid]; ok {
			continue
		}
		m := meta[pid]
		sum := "进程创建: " + name
		sev := "info"
		path := asString(m["path"])
		if pathLooksHot(path) {
			sev = "medium"
			sum = "可疑路径进程创建: " + name
		}
		detail := map[string]any{
			"pid": pid, "name": name, "path": path,
			"ppid": m["ppid"], "parent_name": m["parent_name"],
			"command_line": m["command_line"], "user": m["user"],
			"signed": m["signed"],
			"create_time": m["create_time"], "process_guid": m["process_guid"],
			"parent_guid": m["parent_guid"], "elevated": m["elevated"], "integrity": m["integrity"],
		}
		attachIdentityToDetail(detail, asString(m["create_time"]))
		out = append(out, map[string]any{
			"etype":    "process_create",
			"summary":  sum,
			"severity": sev,
			"ts":       now,
			"detail":   detail,
		})
	}
	for pid, name := range w.prevPID {
		if _, ok := cur[pid]; ok {
			continue
		}
		detail := map[string]any{"pid": pid, "name": name}
		if m := w.prevProc[pid]; m != nil {
			detail["process_guid"] = m["process_guid"]
			detail["create_time"] = m["create_time"]
			detail["ppid"] = m["ppid"]
			detail["parent_guid"] = m["parent_guid"]
			attachIdentityToDetail(detail, asString(m["create_time"]))
		} else {
			attachIdentityToDetail(detail, "")
		}
		out = append(out, map[string]any{
			"etype":    "process_exit",
			"summary":  "进程退出: " + name,
			"severity": "info",
			"ts":       now,
			"detail":   detail,
		})
	}
	w.prevPID = cur
	w.prevProc = meta
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

func (w *timelineWatcher) diffFiles() []map[string]any {
	// 文件差分由 FIM 实时通道负责；这里再扫盘会与传感器叠加打满磁盘
	items, err := collectFilesLite()
	if err != nil {
		return nil
	}
	cur := map[string]string{}
	meta := map[string]map[string]any{}
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		p := asString(m["path"])
		if p == "" {
			continue
		}
		mod := asString(m["modified"])
		cur[p] = mod
		meta[p] = m
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.prevFile) == 0 {
		w.prevFile = cur
		return nil
	}
	now := time.Now().Format("2006-01-02T15:04:05")
	var out []map[string]any
	for p, mod := range cur {
		old, ok := w.prevFile[p]
		if ok && old == mod {
			continue
		}
		if isAgentSelfNoisePath(p) {
			continue
		}
		m := meta[p]
		name := asString(m["name"])
		etype := "file_write"
		title := "文件更新: " + name
		sev := "info"
		if !ok {
			etype = "file_create"
			title = "文件创建: " + name
			sev = "medium"
			if pathLooksHot(p) {
				title = "可疑目录文件创建: " + name
				sev = "high"
			}
		} else if pathLooksHot(p) {
			sev = "medium"
			title = "可疑目录文件更新: " + name
		}
		detail := map[string]any{
			"path": p, "name": m["name"], "ext": m["ext"],
			"size": m["size"], "size_kb": m["size_kb"], "modified": mod,
			"created": m["created"], "directory": m["directory"], "location": m["location"],
			"sha256": m["sha256"], "signed": m["signed"], "signer": m["signer"],
			"company": m["company"], "file_version": m["file_version"],
		}
		out = append(out, map[string]any{
			"etype":    etype,
			"summary":  title,
			"severity": sev,
			"ts":       now,
			"detail":   detail,
		})
	}
	w.prevFile = cur
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func pathLooksHot(p string) bool {
	l := strings.ToLower(p)
	if isAgentSelfNoisePath(l) {
		return false
	}
	// 不含整段 AppData：Chrome/Teams/商店应用常驻其中，会造成大量「可疑路径」误报
	for _, skip := range []string{`\recent\`, `\inetcache\`, `\microsoft\windows\inetcache\`, `\packages\`, `\windowsapps\`} {
		if strings.Contains(l, skip) {
			return false
		}
	}
	for _, k := range []string{`\temp\`, `\tmp\`, `\users\public\`, `\downloads\`} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

// 端侧噪声文件：Agent 自写临时脚本 + Windows PowerShell 策略探针等，不当作「可疑目录文件创建」。
func isAgentSelfNoisePath(p string) bool {
	l := strings.ToLower(strings.TrimSpace(p))
	if l == "" {
		return false
	}
	base := l
	if i := strings.LastIndexAny(l, `\/`); i >= 0 {
		base = l[i+1:]
	}
	for _, pre := range agentSelfNoisePrefixes {
		if strings.HasPrefix(base, pre) || strings.Contains(l, pre) {
			return true
		}
	}
	// Windows Constrained Language / 执行策略探针：__PSScriptPolicyTest_xxxx(.xxx).ps1
	if strings.Contains(l, "psscriptpolicytest") {
		return true
	}
	return false
}

// Agent 自写临时脚本前缀（PowerShell / ETW / WMI / 看门狗等）。
var agentSelfNoisePrefixes = []string{
	"fa-ps-", "fa-etw-", "fa-wevt-", "fa-watch-", "fa-upg-",
}

// isTimelineNoiseEvent 上报前总闸：摘要/路径/文件名任一命中即丢弃。
func isTimelineNoiseEvent(ev map[string]any) bool {
	if ev == nil {
		return true
	}
	sum := strings.ToLower(asString(ev["summary"]))
	if strings.Contains(sum, "psscriptpolicytest") {
		return true
	}
	for _, pre := range agentSelfNoisePrefixes {
		if strings.Contains(sum, pre) {
			return true
		}
	}
	detail, _ := ev["detail"].(map[string]any)
	if detail == nil {
		return false
	}
	for _, k := range []string{"path", "name", "image", "FileName", "TargetFilename", "module", "module_name"} {
		if isAgentSelfNoisePath(asString(detail[k])) {
			return true
		}
	}
	return false
}

func filterTimelineEvents(events []map[string]any) []map[string]any {
	if len(events) == 0 {
		return events
	}
	out := make([]map[string]any, 0, len(events))
	for _, ev := range events {
		if isTimelineNoiseEvent(ev) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

func (w *timelineWatcher) diffNetwork() []map[string]any {
	items, err := collectNetwork()
	if err != nil {
		return nil
	}
	cur := map[string]bool{}
	meta := map[string]map[string]any{}
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		remote := asString(m["remote"])
		if remote == "" || remote == "*:*" || strings.HasPrefix(remote, "0.0.0.0") || strings.HasPrefix(remote, "[::]") {
			continue
		}
		// 忽略本机环回
		if strings.HasPrefix(remote, "127.") || strings.HasPrefix(remote, "[::1]") {
			continue
		}
		key := asString(m["proto"]) + "|" + remote + "|" + asString(m["state"])
		cur[key] = true
		meta[key] = m
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.prevNet) == 0 {
		w.prevNet = cur
		return nil
	}
	now := time.Now().Format("2006-01-02T15:04:05")
	var out []map[string]any
	for key, m := range meta {
		if w.prevNet[key] {
			continue
		}
		remote := asString(m["remote"])
		sev := "info"
		sum := "网络外联: " + remote
		if looksExternal(remote) {
			sev = "medium"
			sum = "新外联: " + remote
		}
		out = append(out, map[string]any{
			"etype":    "network_connect",
			"summary":  sum,
			"severity": sev,
			"ts":       now,
			"detail": map[string]any{
				"remote": remote, "local": m["local"], "proto": m["proto"],
				"state": m["state"], "pid": m["pid"], "process_name": m["process_name"],
			},
		})
	}
	w.prevNet = cur
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func looksExternal(remote string) bool {
	host := remote
	if i := strings.LastIndex(remote, ":"); i > 0 {
		host = remote[:i]
	}
	host = strings.Trim(host, "[]")
	if strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") || strings.HasPrefix(host, "127.") {
		return false
	}
	if strings.HasPrefix(host, "172.") {
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			var n int
			fmt.Sscanf(parts[1], "%d", &n)
			if n >= 16 && n <= 31 {
				return false
			}
		}
	}
	return true
}
