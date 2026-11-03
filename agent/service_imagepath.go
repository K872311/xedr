package main

import (
	"path/filepath"
	"strings"
)

// splitImagePath 拆服务 ImagePath：`"C:\a.exe" -arg` → exe + args。
func splitImagePath(raw string) (exe, args string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}
	if strings.HasPrefix(s, `"`) {
		rest := s[1:]
		i := strings.Index(rest, `"`)
		if i >= 0 {
			exe = rest[:i]
			args = strings.TrimSpace(rest[i+1:])
			return exe, args
		}
	}
	// 无引号：第一个空格前视为路径（含空格路径时尽量匹配 .exe/.dll/.sys）
	low := strings.ToLower(s)
	for _, ext := range []string{`.exe`, `.dll`, `.sys`, `.com`} {
		if j := strings.Index(low, ext); j >= 0 {
			end := j + len(ext)
			exe = s[:end]
			args = strings.TrimSpace(s[end:])
			return exe, args
		}
	}
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return s, ""
	}
	return parts[0], strings.TrimSpace(strings.TrimPrefix(s, parts[0]))
}

func enrichServiceInstallDetail(d map[string]any, imagePath string) {
	if d == nil {
		return
	}
	exe, args := splitImagePath(imagePath)
	if exe != "" {
		d["service_exe"] = exe
		d["payload_path"] = exe
		d["image"] = exe
		d["matched"] = exe
		d["name"] = filepath.Base(exe)
	}
	if args != "" {
		d["service_args"] = args
	}
	if imagePath != "" {
		d["path"] = imagePath
		d["command_line"] = imagePath
	}
	if exe != "" && taskSuspiciousExecute(exe) {
		d["suspicious_path"] = true
	}
}

func enrichServiceInstallEvent(ev map[string]any) {
	if ev == nil {
		return
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		return
	}
	ip := asString(d["path"])
	if ip == "" {
		return
	}
	svcName := asString(d["name"])
	if svcName != "" {
		d["service_name"] = svcName
	}
	enrichServiceInstallDetail(d, ip)
	exe := asString(d["service_exe"])
	if exe == "" {
		return
	}
	label := asString(d["service_name"])
	if label == "" {
		label = svcName
	}
	ev["summary"] = "服务安装: " + filepath.Base(exe) + " · " + label
	if d["suspicious_path"] == true {
		ev["severity"] = "high"
	}
}
