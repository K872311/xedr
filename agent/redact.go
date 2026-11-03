package main

import (
	"regexp"
	"strings"
)

var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization|bearer)\s*[:=]\s*[^\s"']+`),
	regexp.MustCompile(`(?i)"(password|agent_secret|token|api_key)"\s*:\s*"[^"]*"`),
	regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._\-+/=]{8,}`),
	regexp.MustCompile(`(?i)-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----`),
}

func redactSensitive(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, re := range redactPatterns {
		out = re.ReplaceAllStringFunc(out, func(m string) string {
			if i := strings.IndexAny(m, ":="); i >= 0 {
				return m[:i+1] + " **REDACTED**"
			}
			if strings.HasPrefix(strings.ToLower(m), "bearer ") {
				return "Bearer **REDACTED**"
			}
			return "**REDACTED**"
		})
	}
	return out
}

func redactMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "secret") || strings.Contains(lk, "password") || strings.Contains(lk, "token") ||
			strings.Contains(lk, "authorization") || lk == "agent_secret_dpapi" {
			out[k] = "**REDACTED**"
			continue
		}
		switch t := v.(type) {
		case string:
			out[k] = redactSensitive(t)
		case map[string]any:
			out[k] = redactMap(t)
		default:
			out[k] = v
		}
	}
	return out
}
