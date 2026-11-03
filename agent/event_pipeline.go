package main

import (
	"encoding/json"
	"strings"
	"time"
)

func processLiveEvents(events []map[string]any, cfg Config, responseEnabled bool, throttle *eventThrottle) []map[string]any {
	if len(events) == 0 {
		return events
	}
	out := make([]map[string]any, 0, len(events)+8)
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if !integrationEnabled("evm") {
			// skip evm only
		} else {
			for _, hit := range evmEvaluate(ev) {
				out = append(out, hit)
			}
		}
		if integrationEnabled("ptm") {
			for _, hit := range ptmObserve(ev) {
				out = append(out, hit)
			}
		}
		if integrationEnabled("amsi") || integrationEnabled("api_etw") {
			for _, hit := range apiRulesEvaluate(ev) {
				out = append(out, hit)
			}
		}
		if iocHit := matchEventIOC(ev); iocHit != nil {
			out = append(out, iocHit)
		}
		if throttle != nil && !throttle.allow(ev, 2*time.Second) {
			continue
		}
		out = append(out, ev)
	}
	for _, ev := range out {
		runActiveResponse(ev, cfg, responseEnabled)
	}
	return out
}

func matchEventIOC(ev map[string]any) map[string]any {
	if agentIOCJSON == "" {
		return nil
	}
	var items []map[string]any
	if json.Unmarshal([]byte(agentIOCJSON), &items) != nil {
		return nil
	}
	blob := strings.ToLower(asString(ev["summary"]))
	d, _ := ev["detail"].(map[string]any)
	for _, k := range []string{"path", "command_line", "image", "sha256", "domain", "remote"} {
		blob += "\n" + strings.ToLower(asString(d[k]))
	}
	for _, it := range items {
		v := strings.ToLower(strings.TrimSpace(asString(it["value"])))
		if len(v) < 4 {
			continue
		}
		if strings.Contains(blob, v) {
			sev := asString(it["severity"])
			if sev == "" {
				sev = "high"
			}
			return map[string]any{
				"etype": "ioc_hit", "severity": sev, "summary": "IOC 命中: " + v,
				"detail": map[string]any{"matched": v, "ioc_type": it["type"], "source_etype": ev["etype"]},
			}
		}
	}
	return nil
}
