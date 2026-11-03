package main

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

type ptmRule struct {
	ID           string           `json:"id"`
	Type         string           `json:"type"`
	Title        string           `json:"title"`
	Severity     string           `json:"severity"`
	WindowSec    int              `json:"window_sec"`
	MinCount     int              `json:"min_count"`
	SameEntityID bool             `json:"same_entity_id"`
	Match        map[string]any   `json:"match"`
	Steps        []map[string]any `json:"steps"`
}

var (
	ptmMu    sync.RWMutex
	ptmRules []ptmRule
	ptmHist  []map[string]any
)

func loadPTMDocument(doc map[string]any) {
	raw, _ := doc["rules"].([]any)
	var rules []ptmRule
	for _, x := range raw {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		var steps []map[string]any
		for _, s := range anySlice(m["steps"]) {
			if sm, ok := s.(map[string]any); ok {
				steps = append(steps, sm)
			}
		}
		match, _ := m["match"].(map[string]any)
		rules = append(rules, ptmRule{
			ID: asString(m["id"]), Type: asString(m["type"]), Title: asString(m["title"]),
			Severity: asString(m["severity"]), WindowSec: asInt(m["window_sec"]),
			MinCount: asInt(m["min_count"]), SameEntityID: m["same_entity_id"] == true,
			Match: match, Steps: steps,
		})
	}
	ptmMu.Lock()
	ptmRules = rules
	ptmHist = nil
	ptmMu.Unlock()
}

func ptmObserve(ev map[string]any) []map[string]any {
	if !integrationEnabled("ptm") {
		return nil
	}
	ptmMu.Lock()
	defer ptmMu.Unlock()
	now := time.Now()
	ptmHist = append(ptmHist, map[string]any{"t": now, "ev": ev})
	cutoff := now.Add(-10 * time.Minute)
	i := 0
	for _, h := range ptmHist {
		if t, ok := h["t"].(time.Time); ok && t.After(cutoff) {
			ptmHist[i] = h
			i++
		}
	}
	ptmHist = ptmHist[:i]

	var hits []map[string]any
	for _, r := range ptmRules {
		switch r.Type {
		case "frequency":
			if h := ptmFrequency(r, now); h != nil {
				hits = append(hits, h)
			}
		case "sequence", "entity_sequence":
			if h := ptmSequence(r, now); h != nil {
				hits = append(hits, h)
			}
		}
	}
	return hits
}

func ptmEventEvidence(ev map[string]any) map[string]any {
	out := map[string]any{}
	if ev == nil {
		return out
	}
	if et := asString(ev["etype"]); et != "" {
		out["etype"] = et
	}
	if sum := asString(ev["summary"]); sum != "" {
		out["summary"] = sum
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		return out
	}
	for _, k := range []string{
		"path", "key", "reg_key", "hive", "value", "value_name", "name", "process_name",
		"command_line", "remote", "remote_ip", "domain", "local", "proto", "pid", "parent_name",
		"operation", "image", "module_name",
	} {
		if v := asString(d[k]); v != "" {
			out[k] = v
		}
	}
	if asString(out["reg_key"]) == "" && asString(out["key"]) == "" {
		if p := asString(d["path"]); p != "" && strings.Contains(strings.ToLower(p), `\`) {
			out["reg_key"] = p
			out["path"] = p
		}
	}
	return out
}

func ptmBuildMatched(chain []map[string]any) string {
	var parts []string
	for i, c := range chain {
		if c == nil {
			continue
		}
		s := asString(c["summary"])
		if s == "" {
			s = asString(c["etype"])
		}
		k := asString(c["reg_key"])
		if k == "" {
			k = asString(c["key"])
		}
		if k != "" {
			vn := asString(c["value_name"])
			val := asString(c["value"])
			if vn != "" || val != "" {
				s = strings.TrimSpace(fmt.Sprintf("%s → %s=%s", k, vn, val))
			} else {
				s = k
			}
		} else if p := asString(c["path"]); p != "" && !strings.Contains(s, p) {
			s = strings.TrimSpace(s + " " + p)
		}
		if rm := asString(c["remote"]); rm != "" {
			s = strings.TrimSpace(s + " → " + rm)
			if dom := asString(c["domain"]); dom != "" {
				s += " (" + dom + ")"
			}
		}
		parts = append(parts, fmt.Sprintf("%d) %s", i+1, strings.TrimSpace(s)))
	}
	return strings.Join(parts, " | ")
}

func ptmFrequency(r ptmRule, now time.Time) map[string]any {
	win := time.Duration(r.WindowSec) * time.Second
	if win <= 0 {
		win = 120 * time.Second
	}
	minN := r.MinCount
	if minN <= 0 {
		minN = 3
	}
	n := 0
	var lastEv map[string]any
	var chain []map[string]any
	const maxChain = 12
	for _, h := range ptmHist {
		t, _ := h["t"].(time.Time)
		if now.Sub(t) > win {
			continue
		}
		ev, _ := h["ev"].(map[string]any)
		if ptmMatchRule(r.Match, ev) {
			n++
			lastEv = ev
			if evd := ptmEventEvidence(ev); len(evd) > 0 {
				evd["ts"] = asString(ev["ts"])
				chain = append(chain, evd)
				if len(chain) > maxChain {
					chain = chain[len(chain)-maxChain:]
				}
			}
		}
	}
	if n < minN {
		return nil
	}
	sev := r.Severity
	if sev == "" {
		sev = "high"
	}
	trigger := ptmEventEvidence(lastEv)
	if len(chain) == 0 && len(trigger) > 0 {
		chain = append(chain, trigger)
	}
	return map[string]any{
		"etype": "ptm_hit", "severity": sev, "summary": "PTM: " + r.Title,
		"detail": map[string]any{
			"rule_id": r.ID, "rule_title": r.Title, "count": n, "window_sec": r.WindowSec,
			"trigger": trigger, "chain": chain, "matched": ptmBuildMatched(chain),
		},
	}
}

func ptmSequence(r ptmRule, now time.Time) map[string]any {
	if len(r.Steps) < 2 {
		return nil
	}
	win := time.Duration(r.WindowSec) * time.Second
	if win <= 0 {
		win = 300 * time.Second
	}
	step := 0
	var first time.Time
	var anchorEntity string
	var chain []map[string]any
	sameEnt := r.SameEntityID || r.Type == "entity_sequence"
	for _, h := range ptmHist {
		t, _ := h["t"].(time.Time)
		if now.Sub(t) > win {
			continue
		}
		ev, _ := h["ev"].(map[string]any)
		if !ptmStepMatch(r.Steps[step], ev) {
			continue
		}
		if sameEnt {
			d, _ := ev["detail"].(map[string]any)
			eid := asString(d["entity_id"])
			if eid == "" {
				if px, ok := d["process_ext"].(map[string]any); ok {
					eid = asString(px["entity_id"])
				}
			}
			if step == 0 {
				anchorEntity = eid
			} else if anchorEntity != "" && eid != "" && eid != anchorEntity {
				continue
			}
		}
		if step == 0 {
			first = t
			chain = nil
		}
		chain = append(chain, ptmEventEvidence(ev))
		step++
		if step >= len(r.Steps) {
			sev := r.Severity
			if sev == "" {
				sev = "high"
			}
			return map[string]any{
				"etype": "ptm_hit", "severity": sev, "summary": "PTM: " + r.Title,
				"detail": map[string]any{
					"rule_id": r.ID, "rule_title": r.Title, "steps": len(r.Steps),
					"first": first.Format(time.RFC3339), "chain": chain,
					"matched": ptmBuildMatched(chain),
				},
			}
		}
	}
	return nil
}

func ptmMatchRule(match map[string]any, ev map[string]any) bool {
	if match == nil || ev == nil {
		return false
	}
	et := strings.ToLower(asString(ev["etype"]))
	if want := strings.ToLower(asString(match["etype"])); want != "" && et != want {
		return false
	}
	if sub := asString(match["summary_contains"]); sub != "" {
		if !strings.Contains(strings.ToLower(asString(ev["summary"])), strings.ToLower(sub)) {
			return false
		}
	}
	if pr, ok := match["path_regex"].(string); ok && pr != "" {
		d, _ := ev["detail"].(map[string]any)
		path := asString(d["path"])
		re, err := regexp.Compile("(?i)" + pr)
		if err != nil || !re.MatchString(path) {
			return false
		}
	}
	return true
}

func ptmStepMatch(step map[string]any, ev map[string]any) bool {
	if step == nil {
		return false
	}
	et := strings.ToLower(asString(ev["etype"]))
	if want := strings.ToLower(asString(step["etype"])); want != "" && et != want {
		return false
	}
	if sub := asString(step["summary_contains"]); sub != "" {
		if !strings.Contains(strings.ToLower(asString(ev["summary"])), strings.ToLower(sub)) {
			return false
		}
	}
	if pr, ok := step["path_regex"].(string); ok && pr != "" {
		d, _ := ev["detail"].(map[string]any)
		path := asString(d["path"])
		re, err := regexp.Compile("(?i)" + pr)
		if err != nil || !re.MatchString(path) {
			return false
		}
	}
	d, _ := ev["detail"].(map[string]any)
	if pn := asString(step["parent_name_contains"]); pn != "" {
		parent := strings.ToLower(asString(d["parent_name"]))
		if parent == "" {
			if px, ok := d["process_ext"].(map[string]any); ok {
				parent = strings.ToLower(asString(px["parent_name"]))
			}
		}
		if !strings.Contains(parent, strings.ToLower(pn)) {
			return false
		}
	}
	if buf := asString(step["buffer_contains"]); buf != "" {
		if !strings.Contains(strings.ToLower(asString(d["buffer"])), strings.ToLower(buf)) {
			return false
		}
	}
	if wantAPI := asString(step["api_name"]); wantAPI != "" {
		if !strings.EqualFold(asString(d["api_name"]), wantAPI) {
			return false
		}
	}
	if op := asString(step["operation_contains"]); op != "" {
		if !strings.Contains(strings.ToLower(asString(d["operation"])), strings.ToLower(op)) {
			return false
		}
	}
	if sf := asString(step["search_filter_contains"]); sf != "" {
		if !strings.Contains(strings.ToLower(asString(d["search_filter"])), strings.ToLower(sf)) {
			return false
		}
	}
	if ic := asString(step["image_contains"]); ic != "" {
		img := strings.ToLower(asString(d["path"]))
		if img == "" {
			img = strings.ToLower(asString(d["image"]))
		}
		if img == "" {
			img = strings.ToLower(asString(d["module_name"]))
		}
		if !strings.Contains(img, strings.ToLower(ic)) {
			return false
		}
	}
	if dp := asInt(step["destination_port"]); dp > 0 {
		rp := asInt(d["remote_port"])
		if rp == 0 {
			rp = asInt(d["destination_port"])
		}
		if rp != dp {
			return false
		}
	}
	if wantRep := strings.ToLower(asString(step["reputation_not"])); wantRep != "" {
		rep := ""
		if px, ok := d["process_ext"].(map[string]any); ok {
			rep = strings.ToLower(asString(px["reputation"]))
		}
		if rep == wantRep {
			return false
		}
	}
	return true
}
