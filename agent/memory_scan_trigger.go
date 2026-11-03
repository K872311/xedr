package main

import (
	"strings"
)

func memoryScanTriggeredByEvent(ev map[string]any) (pid int, reason string) {
	if ev == nil {
		return 0, ""
	}
	cfg := memoryScanSettingsSnapshot()
	if cfg.Mode != memModeYaraTriggered {
		return 0, ""
	}
	et := strings.ToLower(asString(ev["etype"]))
	triggered := cfg.Triggers[et]
	if !triggered && strings.Contains(et, "remote_thread") {
		triggered = cfg.Triggers["remote_thread_kernel"]
	}
	if !triggered && (et == "process_access" || strings.Contains(strings.ToLower(asString(ev["summary"])), "lsass")) {
		triggered = cfg.Triggers["process_access"]
	}
	if !triggered && (et == "api_amsi" || et == "amsi_hit" || et == "api_call" || et == "api_hit") {
		if cfg.Triggers["api_amsi"] || cfg.Triggers["api_call"] {
			triggered = true
		}
	}
	if !triggered && et == "evm_hit" && cfg.Triggers["evm_hit"] {
		sev := strings.ToLower(asString(ev["severity"]))
		if sev == "high" || sev == "critical" || sev == "medium" {
			triggered = true
		}
	}
	d, _ := ev["detail"].(map[string]any)
	if !triggered && d != nil {
		// 高危壳→载荷：Public/Temp 载荷、BITS URL、WMI 订阅
		if cfg.Triggers["fim_add"] && (et == "fim_add" || et == "fim_modify") {
			pl := asString(d["task_execute"])
			if pl == "" {
				pl = asString(d["payload_path"])
			}
			if pl == "" {
				pl = asString(d["shortcut_target"])
			}
			if taskSuspiciousExecute(pl) {
				triggered = true
			}
		}
		if cfg.Triggers["win_bits"] && et == "win_bits" {
			url := strings.ToLower(asString(d["remote_url"]))
			loc := asString(d["local_path"])
			if strings.HasPrefix(url, "http") || taskSuspiciousExecute(loc) {
				triggered = true
			}
		}
		if (cfg.Triggers["wmi_persist_add"] || cfg.Triggers["wmi_persist_modify"]) && strings.HasPrefix(et, "wmi_persist") {
			triggered = true
		}
	}
	if !triggered {
		return 0, ""
	}
	if d == nil {
		d, _ = ev["detail"].(map[string]any)
	}
	pid = asInt(d["pid"])
	if pid <= 0 {
		pid = asInt(d["target_pid"])
	}
	if pid <= 0 && strings.Contains(strings.ToLower(asString(ev["summary"])), "lsass") {
		pid = asInt(d["target_pid"])
	}
	// 无 PID 的持久化事件：无法扫内存，跳过
	if pid <= 0 {
		return 0, ""
	}
	return pid, et
}

func runTriggeredMemoryScan(ev map[string]any) map[string]any {
	pid, reason := memoryScanTriggeredByEvent(ev)
	if pid <= 0 {
		return nil
	}
	res, err := scanMemory(map[string]any{"pid": pid, "trigger": reason, "mode": "triggered"})
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	return res
}
