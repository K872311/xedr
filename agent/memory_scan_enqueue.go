package main

import (
	"encoding/json"
	"strings"
)

func enqueueMemoryFindings(box *outbox, agentID string, res map[string]any) {
	if box == nil || res == nil {
		return
	}
	findings, _ := res["findings"].([]map[string]any)
	if findings == nil {
		if arr, ok := res["findings"].([]any); ok {
			for _, x := range arr {
				if m, ok := x.(map[string]any); ok {
					findings = append(findings, m)
				}
			}
		}
	}
	for _, f := range findings {
		if f == nil {
			continue
		}
		sev := strings.ToLower(asString(f["severity"]))
		if sev == "" {
			sev = "high"
		}
		title := asString(f["summary"])
		if title == "" {
			title = "内存扫描命中：" + asString(f["rule_name"])
		}
		detailBytes, _ := json.Marshal(f)
		box.enqueue(outTimeline, 86, map[string]any{
			"agent_id": agentID, "hostname": hostname(),
			"events": []any{map[string]any{
				"etype":    "memory_scan_hit",
				"summary":  title,
				"severity": sev,
				"ts":       asString(res["ts"]),
				"detail":   f,
			}},
		})
		mod := "memory"
		if f["building_block"] == true {
			mod = "building_block"
			if sev == "critical" || sev == "high" {
				sev = "medium"
			}
		}
		if sev == "high" || sev == "critical" || asString(f["type"]) == "memory_yara" {
			box.enqueue(outEvent, 92, map[string]any{
				"agent_id": agentID, "hostname": hostname(),
				"module": mod, "severity": sev, "title": title,
				"detail": string(detailBytes),
			})
		}
	}
}
