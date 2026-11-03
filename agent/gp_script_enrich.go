package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var gpScriptSuspicious = regexp.MustCompile(`(?i)(powershell|pwsh|frombase64string|-enc\b|iex\s|invoke-expression|downloadstring|bitsadmin|certutil|mshta|wscript|cscript|regsvr32|rundll32|curl\s|wget\s|http[s]?://|\\\\[a-z0-9._-]+\\)`)

func enrichFIMGroupPolicyScript(ev map[string]any, path string) {
	if ev == nil || !isGroupPolicyScriptPath(path) {
		return
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		d = map[string]any{}
		ev["detail"] = d
	}
	snippet, hits := readScriptSnippet(path, 4096)
	if snippet == "" {
		return
	}
	d["script_snippet"] = snippet
	d["script_path"] = path
	if len(hits) > 0 {
		d["script_suspicious"] = hits
		d["matched"] = strings.Join(hits, ",")
		if sev, _ := ev["severity"].(string); sev == "" || sev == "medium" || sev == "info" {
			ev["severity"] = "high"
		}
		ev["summary"] = "FIM" + fimActionOr(ev) + ": " + filepath.Base(path) + " [组策略脚本] · " + hits[0]
	} else {
		ev["summary"] = "FIM" + fimActionOr(ev) + ": " + filepath.Base(path) + " [组策略脚本]"
	}
}

func fimActionOr(ev map[string]any) string {
	a := fimActionNames[strings.ToLower(asString(ev["etype"]))]
	if a == "" {
		return "变更"
	}
	return a
}

func readScriptSnippet(path string, maxBytes int) (string, []string) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return "", nil
	}
	if len(b) > maxBytes {
		b = b[:maxBytes]
	}
	text := string(b)
	// 去掉 NULs
	text = strings.ReplaceAll(text, "\x00", "")
	text = strings.TrimSpace(text)
	if text == "" {
		return "", nil
	}
	lines := strings.Split(text, "\n")
	keep := lines
	if len(keep) > 12 {
		keep = keep[:12]
	}
	snippet := strings.TrimSpace(strings.Join(keep, "\n"))
	if len(snippet) > 800 {
		snippet = snippet[:800] + "…"
	}
	var hits []string
	for _, m := range gpScriptSuspicious.FindAllString(text, 8) {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		dup := false
		for _, h := range hits {
			if strings.EqualFold(h, m) {
				dup = true
				break
			}
		}
		if !dup {
			hits = append(hits, m)
		}
	}
	return snippet, hits
}
