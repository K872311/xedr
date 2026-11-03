package main

import (
	"regexp"
	"strings"
)

var reCmdExeQuoted = regexp.MustCompile(`(?i)"([A-Za-z]:\\[^"]+\.(?:exe|dll|bat|cmd|ps1|scr|hta|msi))"`)
var reCmdExeSingle = regexp.MustCompile(`(?i)'([A-Za-z]:\\[^']+\.(?:exe|dll|bat|cmd|ps1|scr|hta|msi))'`)
var reCmdExeBare = regexp.MustCompile(`(?i)([A-Za-z]:\\[^\s"']+\.(?:exe|dll|bat|cmd|ps1|scr|hta|msi))`)

// parseChildImageFromCmdline 从 cmd/bat 启动行提取首个可执行路径（LOLBin 链展示用）。
func parseChildImageFromCmdline(cmd string) string {
	s := strings.TrimSpace(cmd)
	if s == "" {
		return ""
	}
	for _, re := range []*regexp.Regexp{reCmdExeQuoted, reCmdExeSingle, reCmdExeBare} {
		if m := re.FindStringSubmatch(s); len(m) > 1 {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}

func enrichLOLBinFields(detail map[string]any) {
	if detail == nil {
		return
	}
	cmd := strings.TrimSpace(asString(detail["command_line"]))
	if cmd == "" {
		cmd = strings.TrimSpace(asString(detail["command"]))
	}
	if cmd == "" {
		return
	}
	if asString(detail["child_image"]) == "" {
		if p := parseChildImageFromCmdline(cmd); p != "" {
			detail["child_image"] = p
		}
	}
}
