package main

import (
	"strings"
	"sync"
	"time"
)

// 按进程+事件类型节流，避免 ETW 洪峰刷爆 outbox。
type eventThrottle struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newEventThrottle() *eventThrottle {
	return &eventThrottle{m: map[string]time.Time{}}
}

func (t *eventThrottle) allow(ev map[string]any, minGap time.Duration) bool {
	if t == nil || ev == nil {
		return true
	}
	et := strings.ToLower(asString(ev["etype"]))
	if et == "" {
		return true
	}
	// 高危与检出类不限流
	switch et {
	case "evm_hit", "ptm_hit", "amsi_hit", "api_hit", "api_amsi", "api_call", "memory_rule", "memory_yara", "fim_add", "fim_modify",
		"win_account_create", "win_logon_fail", "persist_add", "registry_set",
		"process_create_etw", "process_create_live", "process_create", "process_exit_etw",
		"process_cmd_patch", "win_ps_scriptblock", "image_load_etw":
		return true
	}
	d, _ := ev["detail"].(map[string]any)
	pid := asInt(d["pid"])
	key := et + "|" + asString(pid)
	if pid == 0 {
		sum := asString(ev["summary"])
		n := 48
		if len(sum) < n {
			n = len(sum)
		}
		key = et + "|" + sum[:n]
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) > 12000 {
		for k, at := range t.m {
			if now.Sub(at) > 10*time.Minute {
				delete(t.m, k)
			}
		}
	}
	if at, ok := t.m[key]; ok && now.Sub(at) < minGap {
		return false
	}
	t.m[key] = now
	return true
}
