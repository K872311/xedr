//go:build !windows

package main

func collectDiagnosticsBundle(cfg Config) (map[string]any, error) {
	return map[string]any{
		"ok": true, "platform": "non-windows", "version": agentVersion,
	}, nil
}
