//go:build windows

package main

import (
	"fmt"
	"strings"
)

func liveQueryManifest() []map[string]any {
	return []map[string]any{
		{"name": "processes", "osquery_analog": "processes"},
		{"name": "services", "osquery_analog": "services"},
		{"name": "listening_ports", "osquery_analog": "listening_ports"},
		{"name": "scheduled_tasks", "osquery_analog": "scheduled_tasks"},
		{"name": "startup_items", "osquery_analog": "startup_items"},
		{"name": "users", "osquery_analog": "users"},
		{"name": "network_connections", "osquery_analog": "process_open_sockets"},
		{"name": "drivers", "osquery_analog": "drivers"},
		{"name": "installed_software", "osquery_analog": "programs"},
		{"name": "hotfixes", "osquery_analog": "patches"},
	}
}

func liveQueryExec(params map[string]any) (map[string]any, error) {
	if err := remoteOpsGate("live_query"); err != nil {
		return nil, err
	}
	table := strings.ToLower(strings.TrimSpace(asString(params["table"])))
	if table == "" {
		return nil, fmt.Errorf("live_query requires table (see health.live_query_tables)")
	}
	limit := 500
	if v, ok := params["limit"].(float64); ok && v > 0 {
		limit = int(v)
	}
	if v, ok := params["limit"].(int); ok && v > 0 {
		limit = v
	}
	var (
		items []any
		err   error
	)
	switch table {
	case "processes":
		items, err = collectProcessesLite()
	case "services":
		items, err = collectServices()
	case "listening_ports":
		items, err = collectListen()
	case "scheduled_tasks":
		items, err = collectTasks()
	case "startup_items":
		items, err = collectStartup()
	case "users":
		items, err = collectUsers()
	case "network_connections":
		items, err = collectNetwork()
	case "drivers":
		items, err = collectDrivers()
	case "installed_software":
		items, err = collectSoftware()
	case "hotfixes":
		items, err = collectHotfix()
	default:
		return nil, fmt.Errorf("unknown table %q", table)
	}
	if err != nil {
		return nil, err
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return map[string]any{
		"schema":         "forensic_v1",
		"table":          table,
		"row_count":      len(items),
		"rows":           items,
		"osquery_analog": liveQueryAnalog(table),
	}, nil
}

func liveQueryAnalog(table string) string {
	for _, t := range liveQueryManifest() {
		if strings.EqualFold(asString(t["name"]), table) {
			return asString(t["osquery_analog"])
		}
	}
	return ""
}
