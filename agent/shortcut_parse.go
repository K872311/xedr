package main

import (
	"path/filepath"
	"strings"
)

// shortcutInfo：.lnk / .url 解析结果（共用 FIM / persist / collect）。
type shortcutInfo struct {
	ShortcutPath string
	TargetPath   string
	Arguments    string
	WorkingDir   string
	URL          string
	Kind         string // lnk | url | file
}

func (s shortcutInfo) payload() string {
	if s.URL != "" {
		return s.URL
	}
	return strings.TrimSpace(s.TargetPath)
}

func (s shortcutInfo) commandLine() string {
	p := strings.TrimSpace(s.TargetPath)
	a := strings.TrimSpace(s.Arguments)
	if p == "" {
		return strings.TrimSpace(s.URL)
	}
	if a == "" {
		return p
	}
	return p + " " + a
}

func applyShortcutFields(detail map[string]any, s shortcutInfo) {
	if detail == nil {
		return
	}
	detail["shortcut_path"] = s.ShortcutPath
	detail["shortcut_kind"] = s.Kind
	if s.TargetPath != "" {
		detail["shortcut_target"] = s.TargetPath
		detail["payload_path"] = s.TargetPath
		detail["image"] = s.TargetPath
		detail["matched"] = s.TargetPath
	}
	if s.Arguments != "" {
		detail["shortcut_arguments"] = s.Arguments
	}
	if s.WorkingDir != "" {
		detail["shortcut_workdir"] = s.WorkingDir
		detail["task_workdir"] = s.WorkingDir
	}
	if s.URL != "" {
		detail["shortcut_url"] = s.URL
		detail["payload_path"] = s.URL
		detail["matched"] = s.URL
	}
	if cl := s.commandLine(); cl != "" {
		detail["command_line"] = cl
		detail["task_command_line"] = cl
	}
}

func enrichFIMShortcutEvent(ev map[string]any, path string) {
	if ev == nil {
		return
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".lnk" && ext != ".url" {
		return
	}
	s, ok := parseShortcutFile(path)
	if !ok {
		return
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		d = map[string]any{}
		ev["detail"] = d
	}
	applyShortcutFields(d, s)
	payload := s.payload()
	act := fimActionNames[strings.ToLower(asString(ev["etype"]))]
	if act == "" {
		act = "变更"
	}
	base := filepath.Base(path)
	if payload != "" {
		name := filepath.Base(payload)
		if s.URL != "" {
			name = truncateStr(payload, 64)
		}
		ev["summary"] = "FIM" + act + ": " + name + " [启动项] · 快捷方式 " + base
		d["process_name"] = name
		d["name"] = name
		if taskSuspiciousExecute(payload) || strings.HasPrefix(strings.ToLower(payload), "http") {
			if sev, _ := ev["severity"].(string); sev == "" || sev == "medium" {
				ev["severity"] = "high"
			}
		}
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func isStartupFolderPath(path string) bool {
	l := strings.ToLower(path)
	return strings.Contains(l, `\start menu\programs\startup\`)
}

func isGroupPolicyScriptPath(path string) bool {
	l := strings.ToLower(path)
	if !strings.Contains(l, `\system32\grouppolicy\`) {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf":
		return true
	default:
		return false
	}
}
