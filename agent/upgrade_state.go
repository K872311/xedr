//go:build windows

package main

import (
	"encoding/json"
	"os"
	"time"
)

// upgradeDetailsSnapshot 对齐 Elastic state.yaml upgrade_details（诊断/心跳）。
func upgradeDetailsSnapshot(cfg Config) map[string]any {
	p := upgradePendingPath(cfg)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var meta upgradePending
	if json.Unmarshal(b, &meta) != nil {
		return nil
	}
	stName := "UPGRADING"
	stInt := cStateUpgrading
	if time.Now().Unix() > meta.Deadline {
		stName = "WATCHDOG"
		stInt = cStateRollback
	}
	if _, err := os.Stat(upgradeHealthyPath(cfg)); err == nil {
		stName = "VERIFYING"
		stInt = cStateConfiguring
	}
	out := map[string]any{
		"state":          stInt,
		"state_name":     stName,
		"action":         "UPGRADE",
		"target_version": meta.Version,
		"deadline_unix":  meta.Deadline,
		"created_at":     meta.CreatedAt,
		"watchdog_sec":   upgradeWatchdogSec,
	}
	if live := upgradePhaseSnapshot(); live != nil {
		for k, v := range live {
			out[k] = v
		}
	}
	return out
}
