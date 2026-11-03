package main

import (
	"sync"
	"time"
)

// cproto.State 对齐（upgrade_details.state）
const (
	cStateUpgrading = 7
	cStateRollback  = 8
)

var upgradeLive struct {
	mu      sync.RWMutex
	phase   string // DOWNLOADING | VERIFYING | REPLACING | UPGRADING | ROLLBACK | WATCHDOG
	version string
	action  string
	started time.Time
}

func setUpgradePhase(phase, version, action string) {
	upgradeLive.mu.Lock()
	defer upgradeLive.mu.Unlock()
	upgradeLive.phase = phase
	if version != "" {
		upgradeLive.version = version
	}
	if action != "" {
		upgradeLive.action = action
	}
	if upgradeLive.started.IsZero() {
		upgradeLive.started = time.Now().UTC()
	}
}

func clearUpgradePhase() {
	upgradeLive.mu.Lock()
	defer upgradeLive.mu.Unlock()
	upgradeLive.phase = ""
	upgradeLive.version = ""
	upgradeLive.action = ""
	upgradeLive.started = time.Time{}
}

func upgradePhaseSnapshot() map[string]any {
	upgradeLive.mu.RLock()
	defer upgradeLive.mu.RUnlock()
	if upgradeLive.phase == "" {
		return nil
	}
	st := cStateUpgrading
	name := upgradeLive.phase
	switch upgradeLive.phase {
	case "ROLLBACK", "WATCHDOG", "WATCHDOG_PENDING":
		st = cStateRollback
	case "DOWNLOADING", "VERIFYING", "REPLACING":
		st = cStateConfiguring
	}
	return map[string]any{
		"state":          st,
		"state_name":     name,
		"action":         upgradeLive.action,
		"target_version": upgradeLive.version,
		"started_at":     upgradeLive.started.Format(time.RFC3339),
	}
}
