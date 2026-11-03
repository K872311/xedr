package main

import (
	"strings"
)

type arRule struct {
	ID     string         `json:"id"`
	Match  map[string]any `json:"match"`
	Action string         `json:"action"`
	Params map[string]any `json:"params"`
}

var (
	arEnabled bool = true
	arRules   []arRule
)

func loadActiveResponseDoc(doc map[string]any) {
	if doc == nil {
		return
	}
	arEnabled = doc["enabled"] != false
	raw, _ := doc["rules"].([]any)
	var rules []arRule
	for _, x := range raw {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		params, _ := m["params"].(map[string]any)
		match, _ := m["match"].(map[string]any)
		rules = append(rules, arRule{
			ID: asString(m["id"]), Action: strings.ToLower(asString(m["action"])),
			Params: params, Match: match,
		})
	}
	arRules = rules
}

func runActiveResponse(ev map[string]any, cfg Config, responseEnabled bool) {
	if !arEnabled || !responseEnabled || ev == nil {
		return
	}
	for _, r := range arRules {
		if !arMatch(r.Match, ev) {
			continue
		}
		switch r.Action {
		case "notify_only", "":
			continue
		case "scan_memory":
			if !integrationEnabled("memory_scan") {
				continue
			}
			d, _ := ev["detail"].(map[string]any)
			pid := asInt(d["pid"])
			if pid <= 0 {
				continue
			}
			go func(p int) {
				_, _ = scanMemory(map[string]any{"pid": p, "trigger": "active_response"})
			}(pid)
		default:
			if !cmdSchedulerTry(r.Action) {
				continue
			}
			go func(act string, params map[string]any) {
				defer cmdSchedulerDone(act)
				_, _ = execCommand(cfg, agentCommand{Action: act, Params: params})
			}(r.Action, r.Params)
		}
	}
}

func arMatch(match map[string]any, ev map[string]any) bool {
	if match == nil {
		return false
	}
	if et := asString(match["etype"]); et != "" && !strings.EqualFold(et, asString(ev["etype"])) {
		return false
	}
	if mod := asString(match["module"]); mod != "" {
		d, _ := ev["detail"].(map[string]any)
		if !strings.EqualFold(mod, asString(d["module"])) && !strings.EqualFold(mod, asString(ev["module"])) {
			return false
		}
	}
	if sevIn, ok := match["severity_in"].([]any); ok {
		sev := strings.ToLower(asString(ev["severity"]))
		okSev := false
		for _, s := range sevIn {
			if strings.EqualFold(asString(s), sev) {
				okSev = true
				break
			}
		}
		if !okSev {
			return false
		}
	}
	return true
}
