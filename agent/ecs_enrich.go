package main

import (
	"path/filepath"
	"strings"
)

// enrichTimelineECS 为时间线事件附加 Winlogbeat 风格的 ECS 子集（存于 detail.ecs），便于 SIEM 映射。
func enrichTimelineECS(ev map[string]any) {
	if ev == nil {
		return
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		d = map[string]any{}
		ev["detail"] = d
	}
	if _, ok := d["ecs"]; ok {
		return
	}
	et := strings.ToLower(asString(ev["etype"]))
	ecs := map[string]any{
		"event": map[string]any{
			"kind":     "event",
			"category": ecsCategories(et, d),
			"type":     ecsTypes(et, d),
		},
	}
	if ch := asString(d["channel"]); ch != "" {
		wl := map[string]any{"channel": ch}
		if eid := d["event_id"]; eid != nil {
			wl["event_id"] = eid
		}
		ecs["winlog"] = wl
	}
	if host := asString(d["host"]); host != "" {
		ecs["host"] = map[string]any{"name": host}
	}
	ecsMergeProcess(ecs, d)
	ecsMergeNetwork(ecs, d, et)
	ecsMergeFile(ecs, d, et)
	d["ecs"] = ecs
}

func ecsCategories(et string, d map[string]any) []string {
	switch {
	case strings.Contains(et, "process") || et == "win_ps_scriptblock":
		return []string{"process"}
	case strings.Contains(et, "network") || strings.Contains(et, "dns"):
		return []string{"network"}
	case strings.Contains(et, "file"):
		return []string{"file"}
	case strings.Contains(et, "logon") || strings.Contains(et, "account"):
		return []string{"authentication", "iam"}
	case strings.Contains(et, "service") || strings.Contains(et, "task"):
		return []string{"configuration"}
	case strings.Contains(et, "defender") || strings.Contains(et, "malware"):
		return []string{"malware", "intrusion_detection"}
	default:
		if ch := strings.ToLower(asString(d["channel"])); ch != "" {
			if strings.Contains(ch, "defender") {
				return []string{"malware"}
			}
			if strings.Contains(ch, "security") {
				return []string{"authentication"}
			}
		}
		return []string{"host"}
	}
}

func ecsTypes(et string, d map[string]any) []string {
	if strings.Contains(et, "create") || strings.Contains(et, "install") {
		return []string{"start", "creation"}
	}
	if strings.Contains(et, "connect") {
		return []string{"connection", "start"}
	}
	if strings.Contains(et, "fail") {
		return []string{"denied", "end"}
	}
	return []string{"info"}
}

func ecsMergeProcess(ecs map[string]any, d map[string]any) {
	name := asString(d["name"])
	if name == "" {
		name = filepath.Base(asString(d["path"]))
	}
	if name == "" && d["pid"] == nil {
		return
	}
	p := map[string]any{}
	if name != "" {
		p["name"] = name
	}
	if path := asString(d["path"]); path != "" {
		p["executable"] = path
	}
	if pid := d["pid"]; pid != nil {
		p["pid"] = pid
	}
	if ppid := d["ppid"]; ppid != nil {
		p["parent"] = map[string]any{"pid": ppid}
	}
	if cmd := strings.TrimSpace(asString(d["command_line"])); cmd != "" {
		p["command_line"] = cmd
	}
	if user := asString(d["user"]); user != "" {
		p["user"] = map[string]any{"name": user}
	}
	if len(p) > 0 {
		ecs["process"] = p
	}
}

func ecsMergeNetwork(ecs map[string]any, d map[string]any, et string) {
	if !strings.Contains(et, "network") && !strings.Contains(et, "dns") && d["remote"] == nil {
		return
	}
	n := map[string]any{}
	if r := asString(d["remote"]); r != "" {
		n["destination"] = map[string]any{"address": r}
	}
	if l := asString(d["local"]); l != "" {
		n["source"] = map[string]any{"address": l}
	}
	if len(n) > 0 {
		ecs["network"] = n
	}
}

func ecsMergeFile(ecs map[string]any, d map[string]any, et string) {
	if !strings.Contains(et, "file") {
		return
	}
	path := asString(d["path"])
	if path == "" {
		return
	}
	ecs["file"] = map[string]any{
		"path": path,
		"name": filepath.Base(path),
	}
}

func enrichTimelineEventsECS(events []map[string]any) {
	for _, ev := range events {
		enrichTimelineECS(ev)
	}
}
