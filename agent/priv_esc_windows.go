//go:build windows

package main

import (
	"fmt"
	"strings"
)

func integrityRank(label string) int {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "system":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func isInteractiveParent(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "explorer.exe", "winlogon.exe", "userinit.exe", "dwm.exe", "sihost.exe",
		"runtimebroker.exe", "taskhostw.exe", "ctfmon.exe":
		return true
	}
	if strings.HasSuffix(n, "word.exe") || strings.HasSuffix(n, "excel.exe") ||
		strings.HasSuffix(n, "powerpnt.exe") || strings.HasSuffix(n, "outlook.exe") {
		return true
	}
	return false
}

// detectPrivEsc 非交互父进程派生出更高完整性 / SYSTEM 子进程（T1134 / 提权面）。
func detectPrivEsc(ppid int, pid int, parentName, childName string) (severity, summary string) {
	if ppid <= 0 || pid <= 0 {
		return "", ""
	}
	pn := strings.ToLower(strings.TrimSpace(parentName))
	if pn == "" || isInteractiveParent(parentName) {
		return "", ""
	}
	// 常见合法链：services.exe → svchost（仍由其他规则覆盖异常 shell）
	if pn == "services.exe" && strings.EqualFold(childName, "svchost.exe") {
		return "", ""
	}
	_, pInteg := queryTokenMeta(uint32(ppid))
	_, cInteg := queryTokenMeta(uint32(pid))
	if cInteg == "" || pInteg == "" {
		return "", ""
	}
	pr, cr := integrityRank(pInteg), integrityRank(cInteg)
	if cr <= pr {
		return "", ""
	}
	child := strings.TrimSpace(childName)
	if child == "" {
		child = fmt.Sprintf("pid:%d", pid)
	}
	parent := strings.TrimSpace(parentName)
	if parent == "" {
		parent = fmt.Sprintf("ppid:%d", ppid)
	}
	if cInteg == "System" && pInteg != "System" {
		return "high", fmt.Sprintf("提权检测：%s → %s（父 %s / 子 SYSTEM）", parent, child, pInteg)
	}
	if cr >= pr+2 {
		return "medium", fmt.Sprintf("完整性提升：%s → %s（%s → %s）", parent, child, pInteg, cInteg)
	}
	return "", ""
}

func privEscFromProcessEvent(ev map[string]any) map[string]any {
	if ev == nil {
		return nil
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		return nil
	}
	ppid := asInt(d["ppid"])
	pid := asInt(d["pid"])
	parent := asString(d["parent_name"])
	child := asString(d["name"])
	ts := asString(ev["ts"])
	return maybePrivEscTimelineEvent(ppid, pid, parent, child, ts)
}

func maybePrivEscTimelineEvent(ppid int, pid int, parentName, childName, ts string) map[string]any {
	sev, sum := detectPrivEsc(ppid, pid, parentName, childName)
	if sev == "" {
		return nil
	}
	_, pInteg := queryTokenMeta(uint32(ppid))
	_, cInteg := queryTokenMeta(uint32(pid))
	return map[string]any{
		"etype":    "priv_escalation",
		"summary":  sum,
		"severity": sev,
		"ts":       ts,
		"detail": map[string]any{
			"source":       "token",
			"pid":          pid,
			"ppid":         ppid,
			"name":         childName,
			"parent_name":  parentName,
			"integrity":    cInteg,
			"parent_integrity": pInteg,
			"mitre":        []string{"T1134"},
		},
	}
}
