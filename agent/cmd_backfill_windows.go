//go:build windows

package main

import (
	"context"
	"strings"
	"sync"
	"time"
)

type procCreateSlot struct {
	ts       string
	at       int64
	ev       map[string]any
	sent     bool
	merged   bool
	slotID   uint64
}

var procCreateSlotSeq uint64

var (
	procCreateMu sync.Mutex
	procCreates  = map[uint32]*procCreateSlot{} // 每 PID 保留最近一条（短窗口内复用少）
	cmdPatchMu   sync.Mutex
	cmdPatches   []map[string]any
)

func procCreateKey(pid uint32) uint32 { return pid }

func prepareProcessCreateEvent(ev map[string]any) map[string]any {
	if ev == nil {
		return nil
	}
	et := strings.ToLower(asString(ev["etype"]))
	if et != "process_create_etw" && et != "process_create_live" && et != "process_create" {
		return ev
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		return ev
	}
	pid := uint32(asInt(d["pid"]))
	if pid == 0 {
		enrichLOLBinFields(d)
		return ev
	}
	at := parseLocalTS(asString(ev["ts"]))
	if at == 0 {
		at = filetimeOf(time.Now())
	}
	attachHostProcessDetails(d, at)
	enrichLOLBinFields(d)

	// 晚到的 4688/Sysmon：合并到已有 ETW 创建事件
	src := strings.ToLower(asString(d["source"]))
	if src == "security_4688" || src == "sysmon" {
		if merged := mergeLateProcessLog(ev, d, pid); merged {
			return nil
		}
	}

	cmd := strings.TrimSpace(asString(d["command_line"]))
	if cmd != "" {
		procEntities.applyCmdLine(pid, at, cmd, asString(d["user"]))
	}

	procCreateMu.Lock()
	prev := procCreates[procCreateKey(pid)]
	if prev != nil && !prev.merged && time.Since(timeOfFiletime(prev.at)) < 3*time.Minute {
		if strings.TrimSpace(asString(d["command_line"])) == "" {
			pd, _ := prev.ev["detail"].(map[string]any)
			if pd != nil {
				if pc := strings.TrimSpace(asString(pd["command_line"])); pc != "" {
					d["command_line"] = pc
				}
			}
		} else if strings.TrimSpace(asString(d["command_line"])) != "" {
			// 新事件更完整则替换槽位
			prev.ev = ev
			prev.ts = asString(ev["ts"])
		}
	} else {
		procCreateSlotSeq++
		procCreates[procCreateKey(pid)] = &procCreateSlot{ts: asString(ev["ts"]), at: at, ev: ev, slotID: procCreateSlotSeq}
	}
	slot := procCreates[procCreateKey(pid)]
	procCreateMu.Unlock()

	if strings.TrimSpace(asString(d["command_line"])) == "" {
		scheduleCmdBackfill(pid, at, slot)
	} else {
		procEntities.applyCmdLine(pid, at, cmd, asString(d["user"]))
	}
	return ev
}

func mergeLateProcessLog(ev map[string]any, d map[string]any, pid uint32) bool {
	procCreateMu.Lock()
	defer procCreateMu.Unlock()
	slot := procCreates[procCreateKey(pid)]
	if slot == nil || slot.merged {
		return false
	}
	pd, _ := slot.ev["detail"].(map[string]any)
	if pd == nil {
		return false
	}
	lateCmd := strings.TrimSpace(asString(d["command_line"]))
	if lateCmd == "" {
		return false
	}
	if strings.TrimSpace(asString(pd["command_line"])) != "" {
		return true // 已有 cmd，丢弃重复 4688
	}
	pd["command_line"] = lateCmd
	if asString(pd["path"]) == "" {
		pd["path"] = d["path"]
	}
	if asString(pd["name"]) == "" {
		pd["name"] = d["name"]
	}
	if asString(pd["user"]) == "" {
		pd["user"] = d["user"]
	}
	pd["cmd_source_merge"] = d["source"]
	slot.merged = true
	at := slot.at
	procEntities.applyCmdLine(pid, at, lateCmd, asString(pd["user"]))
	if slot.sent {
		enqueueCmdPatch(slot.ev)
	}
	return true
}

func enqueueCmdPatch(ev map[string]any) {
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		return
	}
	patch := map[string]any{
		"etype": "process_cmd_patch", "severity": "info",
		"summary": "进程命令行补全: " + asString(d["name"]),
		"ts":      asString(ev["ts"]),
		"detail": map[string]any{
			"pid": d["pid"], "entity_id": d["entity_id"], "command_line": d["command_line"],
			"user": d["user"], "path": d["path"], "name": d["name"],
		},
	}
	cmdPatchMu.Lock()
	cmdPatches = append(cmdPatches, patch)
	if len(cmdPatches) > 200 {
		cmdPatches = cmdPatches[len(cmdPatches)-200:]
	}
	cmdPatchMu.Unlock()
}

func drainCmdPatches() []map[string]any {
	cmdPatchMu.Lock()
	defer cmdPatchMu.Unlock()
	out := cmdPatches
	cmdPatches = nil
	return out
}

func markProcessCreatesSent(events []map[string]any) {
	procCreateMu.Lock()
	defer procCreateMu.Unlock()
	for _, ev := range events {
		et := strings.ToLower(asString(ev["etype"]))
		if et != "process_create_etw" && et != "process_create_live" && et != "process_create" {
			continue
		}
		d, _ := ev["detail"].(map[string]any)
		if d == nil {
			continue
		}
		pid := uint32(asInt(d["pid"]))
		if slot := procCreates[procCreateKey(pid)]; slot != nil {
			slot.sent = true
		}
	}
}

func normalizeLiveProcessEvents(events []map[string]any) []map[string]any {
	if len(events) == 0 {
		return events
	}
	out := make([]map[string]any, 0, len(events)+8)
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if prepared := prepareProcessCreateEvent(ev); prepared != nil {
			out = append(out, prepared)
		}
	}
	out = append(out, drainCmdPatches()...)
	markProcessCreatesSent(out)
	return out
}

type backfillJob struct {
	pid   uint32
	at    int64
	tries int
}

var (
	backfillCh   chan backfillJob
	backfillOnce sync.Once
)

func startCmdBackfillLoop(ctx context.Context) {
	backfillOnce.Do(func() {
		backfillCh = make(chan backfillJob, 512)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-backfillCh:
					runCmdBackfill(job)
				}
			}
		}()
	})
}

func scheduleCmdBackfill(pid uint32, at int64, slot *procCreateSlot) {
	if backfillCh == nil || pid == 0 || slot == nil {
		return
	}
	delays := []time.Duration{200 * time.Millisecond, time.Second}
	for _, d := range delays {
		delay := d
		go func() {
			select {
			case <-time.After(delay):
				select {
				case backfillCh <- backfillJob{pid: pid, at: at, tries: 3}:
				default:
				}
			}
		}()
	}
}

func onProcessExitForBackfill(pid uint32) {
	if backfillCh == nil || pid == 0 {
		return
	}
	select {
	case backfillCh <- backfillJob{pid: pid, at: 0, tries: 2}:
	default:
	}
}

func runCmdBackfill(job backfillJob) {
	tries, delay := job.tries, 40*time.Millisecond
	if tries <= 0 {
		tries = 3
	}
	cmd, user := queryProcCmdUserRetry(job.pid, tries, delay)
	if cmd == "" && user == "" {
		return
	}
	procCreateMu.Lock()
	slot := procCreates[procCreateKey(job.pid)]
	procCreateMu.Unlock()
	if slot == nil {
		if cmd != "" {
			procEntities.applyCmdLine(job.pid, job.at, cmd, user)
		}
		return
	}
	pd, _ := slot.ev["detail"].(map[string]any)
	if pd == nil {
		return
	}
	if cmd != "" && strings.TrimSpace(asString(pd["command_line"])) == "" {
		pd["command_line"] = cmd
		pd["cmd_backfill"] = true
	}
	if user != "" && asString(pd["user"]) == "" {
		pd["user"] = user
	}
	enrichLOLBinFields(pd)
	at := slot.at
	if at == 0 {
		at = parseLocalTS(asString(slot.ev["ts"]))
	}
	procEntities.applyCmdLine(job.pid, at, cmd, user)
	if slot.sent && cmd != "" {
		enqueueCmdPatch(slot.ev)
	}
}

func attachHostProcessDetails(detail map[string]any, at int64) {
	if detail == nil {
		return
	}
	pid := uint32(asInt(detail["pid"]))
	if pid == 0 {
		return
	}
	ent := procEntities.resolve(pid, at)
	if ent == nil {
		ent = procEntities.annotate(detail, at)
	}
	if ent == nil {
		p, _ := lookupProcInfo(pid)
		if p.Name != "" && asString(detail["host_process"]) == "" {
			detail["host_process"] = p.Name
		}
		return
	}
	if asString(detail["host_process"]) == "" && ent.Name != "" {
		detail["host_process"] = ent.Name
	}
	if asString(detail["process_name"]) == "" && ent.Name != "" {
		detail["process_name"] = ent.Name
	}
	if asString(detail["path"]) == "" && ent.Image != "" {
		detail["path"] = ent.Image
	}
	if asString(detail["command_line"]) == "" && ent.CommandLine != "" {
		detail["command_line"] = ent.CommandLine
	}
}
