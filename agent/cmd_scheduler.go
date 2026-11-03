package main

import (
	"strings"
	"sync"
)

// 互斥组：升级/reload 与内存扫描/隔离不同时跑。
var (
	cmdSchedMu sync.Mutex
	cmdBusy    = map[string]bool{}
)

func cmdGroup(action string) string {
	a := strings.ToLower(action)
	switch a {
	case "upgrade", "rollback_upgrade", "cancel_upgrade", "uninstall_agent", "refresh_modules":
		return "maintenance"
	case "scan_memory":
		return "scan"
	case "isolate_network", "unisolate_network", "kill_process", "quarantine_file":
		return "response"
	case "collect_diagnostics":
		return "diag"
	default:
		return "other"
	}
}

func cmdSchedulerTry(action string) bool {
	g := cmdGroup(action)
	cmdSchedMu.Lock()
	defer cmdSchedMu.Unlock()
	for k := range cmdBusy {
		if k == g {
			continue
		}
		if (k == "maintenance" && g == "response") || (k == "maintenance" && g == "scan") {
			return false
		}
	}
	cmdBusy[g] = true
	return true
}

func cmdSchedulerDone(action string) {
	cmdSchedMu.Lock()
	delete(cmdBusy, cmdGroup(action))
	cmdSchedMu.Unlock()
}
