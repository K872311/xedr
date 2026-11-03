package main

import (
	"strings"
	"sync"
)

// winevent 通道策略：critical 默认集；策略 winevent_channels 可追加/覆盖。
var (
	winevtPolMu   sync.RWMutex
	winevtPolIDs  []string // 空 = 用内置全量 defs
	winevtPolMode = "all"  // all | critical | custom
)

var winevtCriticalIDs = []string{
	"security", "sysmon", "powershell", "defender", "system", "taskscheduler",
}

// 高敏分组可追加（策略 winevent_channels 或 composable 注入）
var winevtHighSensExtraIDs = []string{
	"bits", "applocker", "firewall", "wmi", "powershell_operational",
}

func applyWineventChannelsPolicy(pol map[string]any) {
	if pol == nil {
		return
	}
	mode := strings.ToLower(strings.TrimSpace(asString(pol["winevent_channel_mode"])))
	var ids []string
	if arr, ok := pol["winevent_channels"].([]any); ok {
		for _, x := range arr {
			if s := strings.ToLower(strings.TrimSpace(asString(x))); s != "" {
				ids = append(ids, s)
			}
		}
	}
	winevtPolMu.Lock()
	defer winevtPolMu.Unlock()
	if mode == "" {
		if len(ids) > 0 {
			mode = "custom"
		} else {
			mode = "all"
		}
	}
	winevtPolMode = mode
	winevtPolIDs = ids
}

func winevtChannelDefsFiltered() []winevtChannel {
	all := winevtChannelDefs()
	winevtPolMu.RLock()
	mode := winevtPolMode
	ids := append([]string(nil), winevtPolIDs...)
	winevtPolMu.RUnlock()
	want := map[string]bool{}
	switch mode {
	case "critical":
		for _, id := range winevtCriticalIDs {
			want[id] = true
		}
		for _, id := range ids { // 可追加
			want[id] = true
		}
	case "high_sens", "high-sensitivity":
		for _, id := range winevtCriticalIDs {
			want[id] = true
		}
		for _, id := range winevtHighSensExtraIDs {
			want[id] = true
		}
		for _, id := range ids {
			want[id] = true
		}
	case "custom":
		if len(ids) == 0 {
			return all
		}
		for _, id := range ids {
			want[id] = true
		}
	default:
		return all
	}
	var out []winevtChannel
	for _, c := range all {
		if want[strings.ToLower(c.ID)] {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return all
	}
	return out
}
