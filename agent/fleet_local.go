package main

import (
	"sync"
)

// Fleet 对齐：本地已收敛 rev + PolicyApplied + 心跳内联 command ack 缓冲。
var (
	fleetMu sync.RWMutex

	lastSeenServerSyncRev   int
	lastSeenServerPolicyRev int
	appliedSyncRev          int
	heartbeatAckMu          sync.Mutex
	heartbeatAckBuf         []map[string]any
)

func noteServerRevs(syncRev, policyRev int) {
	fleetMu.Lock()
	defer fleetMu.Unlock()
	if syncRev > 0 {
		lastSeenServerSyncRev = syncRev
	}
	if policyRev > 0 {
		lastSeenServerPolicyRev = policyRev
	}
}

func noteAppliedSyncRev(rev int) {
	fleetMu.Lock()
	defer fleetMu.Unlock()
	if rev > appliedSyncRev {
		appliedSyncRev = rev
	}
}

func localSyncRev() int {
	fleetMu.RLock()
	defer fleetMu.RUnlock()
	return appliedSyncRev
}

func policyApplied(pm *policyManager) bool {
	fleetMu.RLock()
	defer fleetMu.RUnlock()
	return policyAppliedLocked(pm)
}

func policyAppliedLocked(pm *policyManager) bool {
	if pm == nil {
		return false
	}
	st := pm.state()
	status, _ := st["status"].(string)
	if status != policyStatusOK {
		return false
	}
	if lastSeenServerSyncRev <= 0 {
		return true
	}
	return appliedSyncRev >= lastSeenServerSyncRev
}

func fleetSnapshot(pm *policyManager) map[string]any {
	ps := pm.state()
	appliedRev, _ := ps["applied_rev"].(int)
	if appliedRev == 0 {
		if f, ok := numberOf(ps["applied_rev"]); ok {
			appliedRev = int(f)
		}
	}
	fleetMu.RLock()
	defer fleetMu.RUnlock()
	fleetState := 2 // HEALTHY
	msg := ""
	pa := policyAppliedLocked(pm)
	if !pa {
		fleetState = 1 // CONFIGURING
		msg = "策略或同步块尚未完全收敛"
	}
	m := map[string]any{
		"fleet_state":            fleetState,
		"fleet_message":          msg,
		"policy_applied":           pa,
		"local_sync_rev":           appliedSyncRev,
		"local_policy_rev":         appliedRev,
		"server_sync_rev":          lastSeenServerSyncRev,
		"server_policy_rev":        lastSeenServerPolicyRev,
		"sync_parts":             syncPartsSnapshot(),
		"telemetry":              telemetryMetricsSnapshot(),
		"sensor_pipeline":        sensorPipelineSnapshot(),
	}
	return m
}

func queueHeartbeatAck(id string, ok bool, result map[string]any) {
	if id == "" {
		return
	}
	heartbeatAckMu.Lock()
	defer heartbeatAckMu.Unlock()
	if len(heartbeatAckBuf) >= 20 {
		heartbeatAckBuf = heartbeatAckBuf[1:]
	}
	heartbeatAckBuf = append(heartbeatAckBuf, map[string]any{
		"id": id, "ok": ok, "result": result,
	})
}

func drainHeartbeatAcks() []map[string]any {
	heartbeatAckMu.Lock()
	defer heartbeatAckMu.Unlock()
	if len(heartbeatAckBuf) == 0 {
		return nil
	}
	out := make([]map[string]any, len(heartbeatAckBuf))
	copy(out, heartbeatAckBuf)
	heartbeatAckBuf = heartbeatAckBuf[:0]
	return out
}

func confirmHeartbeatAcks(ids []string) {
	if len(ids) == 0 {
		return
	}
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	heartbeatAckMu.Lock()
	defer heartbeatAckMu.Unlock()
	keep := heartbeatAckBuf[:0]
	for _, a := range heartbeatAckBuf {
		id, _ := a["id"].(string)
		if set[id] {
			continue
		}
		keep = append(keep, a)
	}
	heartbeatAckBuf = keep
}
