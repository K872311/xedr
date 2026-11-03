package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// cproto.State 对齐 Elastic diagnostics state.yaml
const (
	cStateStarting    = 0
	cStateConfiguring = 1
	cStateHealthy     = 2
	cStateDegraded    = 3
	cStateFailed      = 4
)

func integrationComponentIDs() []string {
	return []string{
		"etw", "winevent", "wmi_process", "fim", "registry", "evm", "ptm",
		"amsi", "api_etw", "memory_scan", "rootcheck", "sca", "persist", "device",
	}
}

func buildComponentsExpected() []map[string]any {
	var out []map[string]any
	for _, id := range integrationComponentIDs() {
		if !integrationEnabled(id) {
			continue
		}
		out = append(out, map[string]any{
			"id": id,
			"units": map[string]any{
				"input-" + id: map[string]any{"enabled": true},
			},
		})
	}
	return out
}

func componentRuntimeState(id string) (state int, msg string) {
	on := integrationEnabled(id)
	if !on {
		return cStateStopped, "disabled by policy"
	}
	switch id {
	case "etw":
		if captureETWStatusFn != nil {
			mode, ok := captureETWStatusFn()
			if !ok && mode != "stopped" && mode != "" {
				return cStateDegraded, mode
			}
			if !ok {
				return cStateFailed, mode
			}
		}
		return cStateHealthy, ""
	case "wmi_process":
		if !integrationEnabled("wmi_process") {
			return cStateStopped, ""
		}
		return cStateHealthy, ""
	default:
		if on {
			return cStateHealthy, ""
		}
		return cStateStopped, ""
	}
}

func buildComponentsActual() []map[string]any {
	var out []map[string]any
	for _, id := range integrationComponentIDs() {
		st, msg := componentRuntimeState(id)
		if st == cStateStopped && !integrationEnabled(id) {
			continue
		}
		unit := map[string]any{"state": st, "message": msg}
		out = append(out, map[string]any{
			"id": id,
			"state": map[string]any{
				"state": st, "message": msg,
				"version_info": map[string]any{"name": "forensic-process-runtime"},
			},
			"units": map[string]any{"input-" + id: unit},
		})
	}
	return out
}

func buildStateYAML(pm *policyManager, cfg Config) map[string]any {
	agentSt := cStateHealthy
	msg := ""
	if pm != nil {
		switch pm.state()["status"] {
		case policyStatusProb:
			agentSt, msg = cStateConfiguring, "policy probation"
		case policyStatusReject:
			agentSt, msg = cStateFailed, "policy rejected"
		case policyStatusRB:
			agentSt, msg = cStateDegraded, "policy rolled back"
		}
	}
	comps := buildComponentsActual()
	ud := upgradeDetailsSnapshot(cfg)
	root := map[string]any{
		"state":         agentSt,
		"message":       msg,
		"fleet_state":   fleetSnapshot(pm)["fleet_state"],
		"fleet_message": fleetSnapshot(pm)["fleet_message"],
		"log_level":     "info",
		"components":    comps,
	}
	if ud != nil {
		root["upgrade_details"] = ud
	}
	return root
}

func componentsYAML(name string, comps []map[string]any) string {
	b, _ := json.MarshalIndent(comps, "", "  ")
	return fmt.Sprintf("# %s\n%s\n", name, string(b))
}

func mapToSimpleYAML(m map[string]any) string {
	var b strings.Builder
	writeYAMLMap(&b, m, 0)
	return b.String()
}

func writeYAMLMap(b *strings.Builder, m map[string]any, indent int) {
	pad := strings.Repeat("  ", indent)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		v := m[k]
		switch t := v.(type) {
		case map[string]any:
			b.WriteString(pad + k + ":\n")
			writeYAMLMap(b, t, indent+1)
		case []map[string]any:
			b.WriteString(pad + k + ":\n")
			for _, item := range t {
				b.WriteString(pad + "  -\n")
				writeYAMLMap(b, item, indent+2)
			}
		case []any:
			b.WriteString(pad + k + ":\n")
			for _, item := range t {
				if im, ok := item.(map[string]any); ok {
					b.WriteString(pad + "  -\n")
					writeYAMLMap(b, im, indent+2)
				}
			}
		default:
			b.WriteString(fmt.Sprintf("%s%s: %v\n", pad, k, yamlScalar(v)))
		}
	}
}

func yamlScalar(v any) string {
	switch t := v.(type) {
	case string:
		if strings.ContainsAny(t, ":#{}[]\n") {
			return fmt.Sprintf("%q", t)
		}
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", t)
	}
}

func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

const cStateStopped = 6
