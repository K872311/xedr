package main

import (
	"strings"
)

type preventionRule struct {
	Integration string
	Condition   string
	Message     string
}

// forensic-agent.spec.yml 中 preventions 的运行时子集（完整定义见 specs/forensic-agent.spec.yml）。
var defaultPreventions = []preventionRule{
	{Integration: "memory_scan", Condition: "user.admin", Message: "内存扫描建议以管理员权限运行 Agent"},
	{Integration: "wmi_process", Condition: "os.windows", Message: "WMI 进程订阅仅支持 Windows"},
	{Integration: "etw", Condition: "os.windows", Message: "原生 ETW 采集仅支持 Windows"},
}

func evaluatePreventions(integration string) (blocked bool, message string) {
	name := strings.ToLower(strings.TrimSpace(integration))
	meta := hostMetadata()
	isWin := strings.EqualFold(asString(meta["os_family"]), "windows") || runtimeGOOSWindows()
	isAdmin := processIsElevated()
	for _, r := range defaultPreventions {
		if r.Integration != name {
			continue
		}
		switch r.Condition {
		case "user.admin":
			if !isAdmin {
				return true, r.Message
			}
		case "os.windows":
			if !isWin {
				return true, r.Message
			}
		}
	}
	return false, ""
}

func runtimeGOOSWindows() bool {
	return strings.EqualFold(asString(hostMetadata()["os_family"]), "windows")
}

func processIsElevated() bool {
	if elevatedFn != nil {
		return elevatedFn()
	}
	return true
}

var elevatedFn func() bool
