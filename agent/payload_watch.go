package main

import (
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 任务/快捷方式载荷 → 短窗关联进程创建；可疑载荷目录自动进 FIM extra。

type pendingPayload struct {
	Path      string
	Source    string // task | shortcut | service | bits
	TaskName  string
	SeenAt    time.Time
	Correlated bool
}

var (
	payloadPendMu sync.Mutex
	payloadPend   []pendingPayload
	dynamicFIMMu  sync.Mutex
	dynamicFIM    = map[string]time.Time{} // path spec -> expire
)

func notePayloadForWatch(path, source, taskName string) {
	path = strings.TrimSpace(path)
	if path == "" || strings.HasPrefix(strings.ToLower(path), "http") {
		return
	}
	path = filepath.Clean(path)
	payloadPendMu.Lock()
	payloadPend = append(payloadPend, pendingPayload{
		Path: path, Source: source, TaskName: taskName, SeenAt: time.Now(),
	})
	if len(payloadPend) > 200 {
		payloadPend = payloadPend[len(payloadPend)-200:]
	}
	payloadPendMu.Unlock()
	if payloadNeedsFIMWatch(path) {
		addDynamicFIMPath(path)
	}
}

func payloadNeedsFIMWatch(path string) bool {
	l := strings.ToLower(path)
	return strings.Contains(l, `\users\public\`) ||
		strings.Contains(l, `\temp\`) ||
		strings.Contains(l, `\tmp\`) ||
		strings.Contains(l, `\appdata\`) ||
		strings.Contains(l, `\programdata\`) ||
		strings.Contains(l, `\downloads\`)
}

func addDynamicFIMPath(filePath string) {
	dir := filepath.Dir(filePath)
	if dir == "" || len(dir) <= 3 {
		return
	}
	// 目录监控一层可执行；用 |exe,dll,scr 规格
	spec := dir + `|exe,dll,scr,sys,com`
	dynamicFIMMu.Lock()
	dynamicFIM[spec] = time.Now().Add(2 * time.Hour)
	// 顺带盯具体文件所在目录递归一层
	dynamicFIMMu.Unlock()
}

func snapshotDynamicFIMPaths() []string {
	dynamicFIMMu.Lock()
	defer dynamicFIMMu.Unlock()
	now := time.Now()
	var out []string
	for k, exp := range dynamicFIM {
		if now.After(exp) {
			delete(dynamicFIM, k)
			continue
		}
		out = append(out, k)
	}
	return out
}

func dynamicFIMCount() int {
	return len(snapshotDynamicFIMPaths())
}

// correlateProcessWithPayload 进程创建时，若短窗内有匹配载荷则 enrich 事件。
func correlateProcessWithPayload(ev map[string]any) {
	if ev == nil {
		return
	}
	et := strings.ToLower(asString(ev["etype"]))
	if !strings.Contains(et, "process_create") && et != "process_create_live" {
		return
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		return
	}
	img := strings.ToLower(filepath.Clean(asString(d["path"])))
	if img == "" {
		img = strings.ToLower(filepath.Clean(asString(d["image"])))
	}
	if img == "" {
		return
	}
	payloadPendMu.Lock()
	defer payloadPendMu.Unlock()
	now := time.Now()
	kept := payloadPend[:0]
	for _, p := range payloadPend {
		if now.Sub(p.SeenAt) > 5*time.Minute {
			continue
		}
		pl := strings.ToLower(filepath.Clean(p.Path))
		if pl == img || strings.HasSuffix(img, `\`+filepath.Base(pl)) {
			d["correlated_payload"] = p.Path
			d["correlated_source"] = p.Source
			if p.TaskName != "" {
				d["correlated_task"] = p.TaskName
			}
			d["payload_path"] = p.Path
			sum := asString(ev["summary"])
			if !strings.Contains(sum, "关联") {
				ev["summary"] = sum + " · 关联" + p.Source
			}
			if sev := asString(ev["severity"]); sev == "info" || sev == "low" {
				ev["severity"] = "medium"
			}
			p.Correlated = true
			// 仍保留短时，便于多进程
		}
		kept = append(kept, p)
	}
	payloadPend = kept
}

func notePayloadFromEvent(ev map[string]any) {
	if ev == nil {
		return
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		return
	}
	et := strings.ToLower(asString(ev["etype"]))
	src := ""
	switch {
	case strings.Contains(et, "task") || et == "fim_add" || et == "fim_modify":
		if asString(d["task_execute"]) != "" || asString(d["label"]) == "计划任务" || isScheduledTaskDefPath(asString(d["path"])) {
			src = "task"
		}
		if asString(d["shortcut_target"]) != "" || asString(d["shortcut_path"]) != "" {
			src = "shortcut"
		}
	case et == "win_service_install":
		src = "service"
	case et == "win_bits":
		src = "bits"
	case strings.HasPrefix(et, "wmi_persist"):
		src = "wmi"
	}
	if src == "" {
		return
	}
	payload := asString(d["task_execute"])
	if payload == "" {
		payload = asString(d["payload_path"])
	}
	if payload == "" {
		payload = asString(d["shortcut_target"])
	}
	if payload == "" {
		payload = asString(d["service_exe"])
	}
	if payload == "" {
		payload = asString(d["local_path"])
	}
	if payload == "" {
		return
	}
	notePayloadForWatch(payload, src, asString(d["task_name"]))
}
