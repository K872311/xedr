package main

import (
	"log"
	"strings"
	"sync"
)

// memoryScanMode：off | heuristic | yara_on_demand | yara_triggered | yara_scheduled
const (
	memModeOff           = "off"
	memModeHeuristic     = "heuristic"
	memModeYaraDemand    = "yara_on_demand"
	memModeYaraTriggered = "yara_triggered"
	memModeYaraScheduled = "yara_scheduled"
)

type memoryScanSettings struct {
	Mode              string
	RulesRev          string
	MaxProcesses      int
	MaxRegionReadKB   int
	ScheduleInterval  int
	Triggers          map[string]bool
	ExcludeSignedVend map[string]bool
}

var (
	memScanMu sync.RWMutex
	memScan   = memoryScanSettings{
		Mode:             memModeYaraTriggered,
		RulesRev:         "2026.10.31.1",
		MaxProcesses:     20,
		MaxRegionReadKB:  512,
		ScheduleInterval: 1800,
		Triggers: map[string]bool{
			"remote_thread_kernel": true,
			"process_access":       true,
			"image_load_etw":       true,
			"priv_escalation":      true,
			"evm_hit":              true,
			"api_amsi":             true,
			"amsi_hit":             true,
			"api_call":             true,
			"api_hit":              true,
			"wmi_persist_add":      true,
			"wmi_persist_modify":   true,
			"win_bits":             true,
			"win_service_install":  true,
			"win_task_create":      true,
			"fim_add":              true,
		},
		ExcludeSignedVend: map[string]bool{
			"microsoft corporation": true,
			"google llc":            true,
		},
	}
)

func applyMemoryScanPolicy(pol map[string]any) {
	raw, ok := pol["memory_scan"].(map[string]any)
	if !ok || raw == nil {
		return
	}
	memScanMu.Lock()
	prevRev := memScan.RulesRev
	if m := strings.TrimSpace(asString(raw["mode"])); m != "" {
		switch strings.ToLower(m) {
		case memModeOff, memModeHeuristic, memModeYaraDemand, memModeYaraTriggered, memModeYaraScheduled:
			memScan.Mode = strings.ToLower(m)
		}
	}
	if r := strings.TrimSpace(asString(raw["rules_rev"])); r != "" {
		memScan.RulesRev = r
	}
	if n, ok := numberOf(raw["max_processes_per_run"]); ok && n > 0 {
		memScan.MaxProcesses = int(n)
		if memScan.MaxProcesses > 80 {
			memScan.MaxProcesses = 80
		}
	}
	if n, ok := numberOf(raw["max_region_read_kb"]); ok && n > 0 {
		memScan.MaxRegionReadKB = int(n)
		if memScan.MaxRegionReadKB > 4096 {
			memScan.MaxRegionReadKB = 4096
		}
	}
	if n, ok := numberOf(raw["schedule_interval_sec"]); ok && n >= 300 {
		memScan.ScheduleInterval = int(n)
	}
	if arr, ok := raw["triggers"].([]any); ok {
		tr := map[string]bool{}
		for _, x := range arr {
			s := strings.ToLower(strings.TrimSpace(asString(x)))
			if s != "" {
				tr[s] = true
			}
		}
		if len(tr) > 0 {
			memScan.Triggers = tr
		}
	}
	if arr, ok := raw["exclude_signed_vendor"].([]any); ok {
		ex := map[string]bool{}
		for _, x := range arr {
			s := strings.ToLower(strings.TrimSpace(asString(x)))
			if s != "" {
				ex[s] = true
			}
		}
		memScan.ExcludeSignedVend = ex
	}
	wantRev := memScan.RulesRev
	memScanMu.Unlock()
	if wantRev != prevRev {
		log.Printf("memory_scan rules_rev → %s", wantRev)
	}
	_ = syncMemoryYaraRules(wantRev)
}

// applyHeartbeatPolicyPatch 策略 rev 未变时仍合并心跳里会更新的字段（YARA rev、内存扫描参数等）。
func applyHeartbeatPolicyPatch(pol map[string]any) {
	if pol == nil {
		return
	}
	if ms, ok := pol["memory_scan"].(map[string]any); ok {
		applyMemoryScanPolicy(map[string]any{"memory_scan": ms})
	}
}

func pullMemoryYaraIfNeeded(rev string) {
	rev = strings.TrimSpace(rev)
	if rev == "" {
		return
	}
	cur := memoryScanSettingsSnapshot().RulesRev
	if rev == cur && memRulesRev == rev {
		return
	}
	applyMemoryScanPolicy(map[string]any{"memory_scan": map[string]any{"rules_rev": rev}})
}

func memoryScanSettingsSnapshot() memoryScanSettings {
	memScanMu.RLock()
	defer memScanMu.RUnlock()
	cp := memScan
	cp.Triggers = map[string]bool{}
	for k, v := range memScan.Triggers {
		cp.Triggers[k] = v
	}
	cp.ExcludeSignedVend = map[string]bool{}
	for k, v := range memScan.ExcludeSignedVend {
		cp.ExcludeSignedVend[k] = v
	}
	return cp
}

func memoryScanActive() bool {
	m := memoryScanSettingsSnapshot()
	switch m.Mode {
	case memModeOff:
		return false
	default:
		return true
	}
}

func memoryScanUsesYara(m memoryScanSettings) bool {
	switch m.Mode {
	case memModeYaraDemand, memModeYaraTriggered, memModeYaraScheduled:
		return true
	default:
		return false
	}
}
