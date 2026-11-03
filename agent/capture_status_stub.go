//go:build !windows

package main

func probeCaptureEnvironment() map[string]any {
	return map[string]any{
		"etw_session_ok": false, "audit_4688_enabled": false, "sysmon_present": false,
		"platform": "non-windows",
	}
}

func captureStatusSnapshot() map[string]any {
	m := probeCaptureEnvironment()
	m["entities_rev"] = procEntities.revision()
	return m
}

func componentHealthSnapshot() []map[string]any { return nil }
