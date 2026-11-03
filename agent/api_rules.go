package main

import (
	"strings"
	"sync"
)

type apiProtRule struct {
	ID                     string   `json:"id"`
	Title                  string   `json:"title"`
	Severity               string   `json:"severity"`
	Kind                   string   `json:"kind"` // amsi_buffer | api_call
	APINames               []string `json:"api_names"`
	ProcessNames           []string `json:"process_names"`
	AppNames               []string `json:"app_names"`
	BufferAll              []string `json:"buffer_all"`
	MinBackgroundCallCount int      `json:"min_background_call_count"`
	MinMsSinceLastKey      int      `json:"min_ms_since_last_key"`
	HookFilterTypes        []int    `json:"hook_filter_types"`
	ExcludeSignedTrusted   bool     `json:"exclude_signed_trusted"`
	SearchFilterAll        []string `json:"search_filter_all"`
	SearchFilterAny        []string `json:"search_filter_any"`
	OperationContains      []string `json:"operation_contains"`
	ExcludeUserIDs         []string `json:"exclude_user_ids"`
	Enabled                bool     `json:"enabled"`
}

var (
	apiRulesMu sync.RWMutex
	apiRules   []apiProtRule
	apiRulesRev string
)

func loadAPIRulesDocument(doc map[string]any) {
	if doc == nil {
		return
	}
	raw, ok := doc["rules"].([]any)
	if !ok {
		return
	}
	var rules []apiProtRule
	for _, x := range raw {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		var hookTypes []int
		for _, v := range anySlice(m["hook_filter_types"]) {
			if n, ok := numberOf(v); ok {
				hookTypes = append(hookTypes, int(n))
			}
		}
		rules = append(rules, apiProtRule{
			ID: asString(m["id"]), Title: asString(m["title"]), Severity: asString(m["severity"]),
			Kind: strings.ToLower(asString(m["kind"])),
			APINames:       stringsFromAnySlice(m["api_names"]),
			ProcessNames:   stringsFromAnySlice(m["process_names"]),
			AppNames:       stringsFromAnySlice(m["app_names"]),
			BufferAll:      stringsFromAnySlice(m["buffer_all"]),
			MinBackgroundCallCount: int(numberOfDefault(m["min_background_call_count"], 0)),
			MinMsSinceLastKey:      int(numberOfDefault(m["min_ms_since_last_key"], 0)),
			HookFilterTypes:        hookTypes,
			ExcludeSignedTrusted: m["exclude_signed_trusted"] == true,
			SearchFilterAll:      stringsFromAnySlice(m["search_filter_all"]),
			SearchFilterAny:      stringsFromAnySlice(m["search_filter_any"]),
			OperationContains:    stringsFromAnySlice(m["operation_contains"]),
			ExcludeUserIDs:       stringsFromAnySlice(m["exclude_user_ids"]),
			Enabled:              m["enabled"] != false,
		})
	}
	apiRulesMu.Lock()
	apiRules = rules
	apiRulesRev = asString(doc["rev"])
	apiRulesMu.Unlock()
}

func numberOfDefault(v any, def float64) float64 {
	if n, ok := numberOf(v); ok {
		return n
	}
	return def
}

func loadAMSIDocument(doc map[string]any) {
	loadAPIRulesDocument(doc)
}

func apiRulesEvaluate(ev map[string]any) []map[string]any {
	if ev == nil {
		return nil
	}
	et := strings.ToLower(asString(ev["etype"]))
	if et != "api_amsi" && et != "api_call" {
		return nil
	}
	apiRulesMu.RLock()
	rules := append([]apiProtRule(nil), apiRules...)
	apiRulesMu.RUnlock()
	if len(rules) == 0 {
		return nil
	}
	d, _ := ev["detail"].(map[string]any)
	apiName := strings.ToLower(asString(d["api_name"]))
	buf := strings.ToLower(asString(d["buffer"]))
	pname := strings.ToLower(asString(d["process_name"]))
	if pname == "" {
		pname = strings.ToLower(asString(d["name"]))
	}
	app := strings.ToLower(asString(d["app_name"]))
	trusted := processDetailTrusted(d)
	bg := asInt(d["background_call_count"])
	msKey := asInt(d["ms_since_last_key"])
	filterType := asInt(d["hook_filter_type"])
	searchFilter := strings.ToLower(asString(d["search_filter"]))
	operation := strings.ToLower(asString(d["operation"]))
	userID := strings.ToUpper(asString(d["user_id"]))

	var out []map[string]any
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		wantKind := r.Kind
		if wantKind == "" {
			wantKind = "amsi_buffer"
		}
		if et == "api_amsi" && wantKind != "amsi_buffer" {
			continue
		}
		if et == "api_call" && wantKind != "api_call" {
			continue
		}
		if !apiRuleMatch(r, apiName, buf, pname, app, trusted, bg, msKey, filterType, searchFilter, operation, userID) {
			continue
		}
		sev := r.Severity
		if sev == "" {
			sev = "high"
		}
		hitType := "amsi_hit"
		if et == "api_call" {
			hitType = "api_hit"
		}
		hitDet := map[string]any{
			"rule_id": r.ID, "rule_title": r.Title, "rule_source": "protections-api",
			"api_name": d["api_name"], "pid": d["pid"], "entity_id": d["entity_id"],
			"source_etype": et, "source_pid": d["pid"],
			"process_name": d["process_name"], "name": d["name"], "path": d["path"],
			"command_line": d["command_line"], "user": d["user"],
		}
		if hitDet["command_line"] == "" {
			hitDet["command_line"] = d["buffer"]
		}
		out = append(out, map[string]any{
			"etype": hitType, "severity": sev,
			"summary": "API: " + r.Title,
			"detail":  hitDet,
		})
	}
	return out
}

func processDetailTrusted(d map[string]any) bool {
	if px, ok := d["process_ext"].(map[string]any); ok {
		if strings.EqualFold(asString(px["reputation"]), "trusted") {
			return true
		}
		if cs, ok := px["code_signature"].(map[string]any); ok && cs["trusted"] == true {
			return true
		}
	}
	return false
}

func apiRuleMatch(r apiProtRule, apiName, buf, pname, app string, trusted bool, bg, msKey, filterType int, searchFilter, operation, userID string) bool {
	if len(r.ExcludeUserIDs) > 0 && userID != "" {
		for _, uid := range r.ExcludeUserIDs {
			if strings.EqualFold(userID, strings.ToUpper(uid)) {
				return false
			}
		}
	}
	if len(r.APINames) > 0 {
		ok := false
		for _, an := range r.APINames {
			if strings.EqualFold(apiName, an) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.ProcessNames) > 0 {
		ok := false
		for _, pn := range r.ProcessNames {
			if strings.EqualFold(pname, pn) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.AppNames) > 0 && !appNameMatches(app, r.AppNames) {
		return false
	}
	if r.ExcludeSignedTrusted && trusted {
		return false
	}
	if r.MinBackgroundCallCount > 0 && bg < r.MinBackgroundCallCount {
		return false
	}
	if r.MinMsSinceLastKey > 0 && msKey < r.MinMsSinceLastKey {
		return false
	}
	if len(r.HookFilterTypes) > 0 {
		ok := false
		for _, ft := range r.HookFilterTypes {
			if ft == filterType {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, frag := range r.BufferAll {
		f := strings.ToLower(strings.Trim(frag, "*"))
		if f == "" || !strings.Contains(buf, f) {
			return false
		}
	}
	if r.Kind == "amsi_buffer" && len(r.BufferAll) == 0 {
		return false
	}
	for _, frag := range r.SearchFilterAll {
		f := strings.ToLower(strings.Trim(frag, "*"))
		if f == "" || !strings.Contains(searchFilter, f) {
			return false
		}
	}
	if len(r.SearchFilterAny) > 0 {
		any := false
		for _, frag := range r.SearchFilterAny {
			f := strings.ToLower(strings.Trim(frag, "*"))
			if f != "" && strings.Contains(searchFilter, f) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	if len(r.OperationContains) > 0 {
		any := false
		for _, frag := range r.OperationContains {
			f := strings.ToLower(strings.Trim(frag, "*"))
			if f != "" && strings.Contains(operation, f) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	if r.Kind == "api_call" && apiName == "ldap_search" && len(r.SearchFilterAll) == 0 && len(r.SearchFilterAny) == 0 {
		return false
	}
	if r.Kind == "api_call" && strings.Contains(apiName, "iwbemservices") && len(r.OperationContains) == 0 && operation == "" {
		return false
	}
	return true
}

func appNameMatches(app string, names []string) bool {
	if app == "" {
		return false
	}
	for _, an := range names {
		if an != "" && strings.Contains(app, strings.ToLower(an)) {
			return true
		}
	}
	return false
}
