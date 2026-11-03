package main

import (
	"regexp"
	"strings"
	"sync"
)

type evmRule struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Severity        string   `json:"severity"`
	Etype           string   `json:"etype"`
	SummaryContains string   `json:"summary_contains"`
	PathPrefixes    []string `json:"path_prefixes"`
	Patterns        []string `json:"patterns"`
	Match           string   `json:"match"`
	SignedFilter         string   `json:"signed_filter"`
	ExcludePatterns      []string `json:"exclude_patterns"`
	ParentNameContains   string   `json:"parent_name_contains"`
	BuildingBlock        bool     `json:"building_block"`
}

var (
	evmMu    sync.RWMutex
	evmRules []evmRule
	evmRev   string
)

func loadEVMDocument(doc map[string]any) {
	if doc == nil {
		return
	}
	raw, ok := doc["rules"].([]any)
	if !ok {
		return
	}
	var rules []evmRule
	for _, x := range raw {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		pr := stringsFromAnySlice(m["path_prefixes"])
		pats := stringsFromAnySlice(m["patterns"])
		rules = append(rules, evmRule{
			ID: asString(m["id"]), Title: asString(m["title"]), Severity: asString(m["severity"]),
			Etype: strings.ToLower(asString(m["etype"])),
			SummaryContains: asString(m["summary_contains"]),
			PathPrefixes: pr, Patterns: pats, Match: asString(m["match"]),
			SignedFilter: asString(m["signed_filter"]),
			ExcludePatterns: stringsFromAnySlice(m["exclude_patterns"]),
			ParentNameContains: asString(m["parent_name_contains"]),
			BuildingBlock: m["building_block"] == true,
		})
	}
	evmMu.Lock()
	evmRules = rules
	evmRev = asString(doc["rev"])
	evmMu.Unlock()
	if len(rules) > 0 {
		persistEvmLKG(doc)
	}
}

func evmEvaluate(ev map[string]any) []map[string]any {
	evmMu.RLock()
	rules := append([]evmRule(nil), evmRules...)
	evmMu.RUnlock()
	if len(rules) == 0 {
		return nil
	}
	et := strings.ToLower(asString(ev["etype"]))
	sum := strings.ToLower(asString(ev["summary"]))
	d, _ := ev["detail"].(map[string]any)
	path := strings.ToLower(asString(d["path"]))
	if path == "" {
		path = strings.ToLower(asString(d["image"]))
	}
	var out []map[string]any
	for _, r := range rules {
		if r.Etype != "" && r.Etype != et {
			continue
		}
		if r.SummaryContains != "" && !strings.Contains(sum, strings.ToLower(r.SummaryContains)) {
			continue
		}
		if len(r.PathPrefixes) > 0 && !pathScopeAllowed(r.PathPrefixes, path, d) {
			continue
		}
		if len(r.Patterns) > 0 {
			if !evmPatternsMatch(r, sum, path, d) {
				continue
			}
		}
		if len(r.ExcludePatterns) > 0 && evmExcludeMatch(r, sum, path, d) {
			continue
		}
		if pn := strings.ToLower(r.ParentNameContains); pn != "" {
			parent := strings.ToLower(asString(d["parent_name"]))
			if parent == "" {
				if px, ok := d["process_ext"].(map[string]any); ok {
					parent = strings.ToLower(asString(px["parent_name"]))
				}
			}
			if !strings.Contains(parent, pn) {
				continue
			}
		}
		if r.SignedFilter == "unsigned" {
			if evmProcessTrusted(d) {
				continue
			}
		}
		sev := r.Severity
		if sev == "" {
			sev = "medium"
		}
		rsrc := "evm"
		idLow := strings.ToLower(r.ID)
		if strings.HasPrefix(idLow, "elastic-") {
			rsrc = "elastic"
		} else if strings.Contains(idLow, ".prot.evm") {
			rsrc = "protections"
		}
		dhit := map[string]any{
			"rule_id": r.ID, "rule_title": r.Title, "title": r.Title,
			"rule_source": rsrc, "source_etype": et,
			"building_block": r.BuildingBlock, "evm_rev": evmRev,
		}
		if sum := strings.TrimSpace(asString(ev["summary"])); sum != "" {
			dhit["source_summary"] = sum
		}
		if d != nil {
			evmCopyDetailFields(dhit, d)
		}
		if asString(dhit["matched"]) == "" {
			dhit["matched"] = evmBuildMatched(dhit, asString(ev["summary"]))
		}
		out = append(out, map[string]any{
			"etype": "evm_hit", "severity": sev,
			"summary": "EVM: " + r.Title,
			"detail": dhit,
		})
	}
	return out
}

func evmCopyDetailFields(dhit, d map[string]any) {
	if dhit == nil || d == nil {
		return
	}
	if pid := asInt(d["pid"]); pid > 0 {
		dhit["pid"] = pid
	}
	for _, k := range []string{
		"name", "path", "image", "command_line", "parent_name", "process_name",
		"remote", "remote_ip", "domain", "local", "proto", "key", "reg_key",
		"value", "value_name", "operation", "module_name",
	} {
		if v := asString(d[k]); v != "" {
			dhit[k] = v
		}
	}
	if cmd := asString(d["command_line"]); cmd != "" {
		dhit["matched"] = cmd
	}
}

func evmBuildMatched(dhit map[string]any, summary string) string {
	var parts []string
	if s := strings.TrimSpace(summary); s != "" {
		parts = append(parts, s)
	}
	if rm := asString(dhit["remote"]); rm != "" {
		line := rm
		if dom := asString(dhit["domain"]); dom != "" {
			line += " (" + dom + ")"
		}
		parts = append(parts, line)
	}
	k := asString(dhit["reg_key"])
	if k == "" {
		k = asString(dhit["key"])
	}
	if k != "" {
		parts = append(parts, k)
	} else if p := asString(dhit["path"]); p != "" {
		parts = append(parts, p)
	}
	if cmd := asString(dhit["command_line"]); cmd != "" {
		parts = append(parts, cmd)
	}
	return strings.TrimSpace(strings.Join(parts, " · "))
}

func evmProcessTrusted(d map[string]any) bool {
	signed := strings.ToLower(asString(d["signed"]))
	if signed == "valid" || signed == "true" {
		return true
	}
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

func evmExcludeMatch(r evmRule, sum, path string, d map[string]any) bool {
	blob := evmMatchBlob(sum, path, d)
	for _, p := range r.ExcludePatterns {
		p = strings.TrimSpace(p)
		if p != "" && strings.Contains(blob, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func evmMatchBlob(sum, path string, d map[string]any) string {
	b := sum + "\n" + path + "\n" + strings.ToLower(asString(d["command_line"]))
	b += "\n" + strings.ToLower(asString(d["process_name"]))
	b += "\n" + strings.ToLower(asString(d["name"]))
	b += "\n" + strings.ToLower(asString(d["module_name"]))
	b += "\n" + strings.ToLower(asString(d["image"]))
	if px, ok := d["process_ext"].(map[string]any); ok {
		b += "\n" + strings.ToLower(asString(px["parent_name"]))
		b += "\n" + strings.ToLower(asString(px["parent_path"]))
		b += "\n" + strings.ToLower(asString(px["grandparent_name"]))
		b += "\n" + strings.ToLower(asString(px["path"]))
		b += "\n" + strings.ToLower(asString(px["reputation"]))
		if anc, ok := px["ancestry"].([]any); ok {
			for _, x := range anc {
				if m, ok := x.(map[string]any); ok {
					b += "\n" + strings.ToLower(asString(m["path"]))
				}
			}
		}
	}
	b += "\n" + strings.ToLower(asString(d["parent_path"]))
	return b
}

func pathScopeAllowed(prefixes []string, path string, d map[string]any) bool {
	if len(prefixes) == 0 {
		return true
	}
	blob := evmMatchBlob("", path, d)
	for _, p := range prefixes {
		pref := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "/", "\\"))
		if pref == "" {
			continue
		}
		if len(pref) >= 3 && pref[1] == ':' && pref[2] == '\\' {
			if strings.HasPrefix(strings.ToLower(strings.ReplaceAll(path, "/", "\\")), pref) ||
				strings.Contains(blob, pref) {
				return true
			}
			continue
		}
		frag := pref
		if !strings.HasPrefix(frag, "\\") {
			frag = "\\" + strings.Trim(frag, "\\")
		}
		if strings.Contains(blob, pref) || strings.Contains(blob, frag) {
			return true
		}
	}
	return false
}

func evmPatternsMatch(r evmRule, sum, path string, d map[string]any) bool {
	blob := evmMatchBlob(sum, path, d)
	for _, p := range r.Patterns {
		p = strings.TrimSpace(p)
		if p == "" || p == "*" {
			return true
		}
		if r.Match == "regex" {
			re, err := regexp.Compile("(?i)" + p)
			if err == nil && re.MatchString(blob) {
				return true
			}
			continue
		}
		if strings.Contains(blob, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func loadEmbeddedEVM() {
	loadEVMDocument(map[string]any{
		"rev": "embedded",
		"rules": []any{
			map[string]any{
				"id": "evm.embed.lsass", "title": "LSASS 访问", "severity": "high",
				"etype": "process_access", "summary_contains": "lsass",
			},
			map[string]any{
				"id": "evm.embed.ps_enc", "title": "PowerShell 编码", "severity": "high",
				"etype": "", "summary_contains": "",
				"patterns": []any{"-enc ", "frombase64string"}, "match": "substring",
			},
		},
	})
}
