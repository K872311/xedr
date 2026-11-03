//go:build windows

package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

func evalSCARequirements(reqs []scaRule) bool {
	if len(reqs) == 0 {
		return true
	}
	for _, r := range reqs {
		if !evalSCAExpr(r.Expr) {
			return false
		}
	}
	return true
}

func evalSCACheck(ch scaCheck) (pass bool, detail string) {
	cond := strings.ToLower(strings.TrimSpace(ch.Condition))
	if cond == "" {
		cond = "all"
	}
	var okN int
	for _, r := range ch.Rules {
		ok := evalSCAExpr(r.Expr)
		if cond == "any" && ok {
			return true, ""
		}
		if ok {
			okN++
		}
	}
	if cond == "any" {
		return false, "无任一规则通过"
	}
	if okN == len(ch.Rules) {
		return true, ""
	}
	return false, fmt.Sprintf("%d/%d 规则未通过", len(ch.Rules)-okN, len(ch.Rules))
}

func evalSCAExpr(expr string) bool {
	s := strings.TrimSpace(expr)
	s = strings.Trim(s, "'\"")
	neg := false
	if strings.HasPrefix(strings.ToLower(s), "not ") {
		neg = true
		s = strings.TrimSpace(s[4:])
	}
	ok := evalSCAExprCore(s)
	if neg {
		return !ok
	}
	return ok
}

func evalSCAExprCore(s string) bool {
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, "r:"):
		return evalSCARegistry(s[2:])
	case strings.HasPrefix(low, "c:"):
		return evalSCACommand(s[2:])
	default:
		return false
	}
}

func evalSCARegistry(body string) bool {
	parts := splitSCAArrow(body)
	if len(parts) < 2 {
		return false
	}
	path := strings.TrimSpace(parts[0])
	valName := ""
	matchPart := parts[len(parts)-1]
	if len(parts) >= 3 {
		valName = strings.TrimSpace(parts[1])
	}
	root, sub, err := parseRegRoot(path)
	if err != nil {
		return false
	}
	k, err := registry.OpenKey(root, sub, registry.READ)
	if err != nil {
		return false
	}
	defer k.Close()
	var data string
	if valName == "" || valName == "." {
		// 仅路径存在
		return matchSCAMatcher(matchPart, "present")
	}
	data, _, err = k.GetStringValue(valName)
	if err != nil {
		data = ""
		if v, _, e2 := k.GetIntegerValue(valName); e2 == nil {
			data = strconv.FormatUint(v, 10)
		}
	}
	return matchSCAMatcher(matchPart, data)
}

func evalSCACommand(body string) bool {
	parts := splitSCAArrow(body)
	if len(parts) < 2 {
		return false
	}
	cmdLine := strings.TrimSpace(parts[0])
	matchPart := strings.TrimSpace(parts[len(parts)-1])
	out, err := runSCACommand(cmdLine)
	if err != nil {
		out = err.Error() + "\n" + out
	}
	return matchSCAMatcher(matchPart, out)
}

func runSCACommand(cmdLine string) (string, error) {
	cmdLine = strings.TrimSpace(cmdLine)
	if cmdLine == "" {
		return "", fmt.Errorf("empty command")
	}
	fields := splitCommandFields(cmdLine)
	if len(fields) == 0 {
		return "", fmt.Errorf("empty command")
	}
	return runCmd(25*time.Second, fields[0], fields[1:]...)
}

func splitCommandFields(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && (c == ' ' || c == '\t') {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func splitSCAArrow(s string) []string {
	return strings.Split(s, " -> ")
}

func parseRegRoot(path string) (registry.Key, string, error) {
	p := strings.TrimSpace(path)
	up := strings.ToUpper(p)
	var root registry.Key
	rest := p
	switch {
	case strings.HasPrefix(up, "HKLM\\") || strings.HasPrefix(up, "HKEY_LOCAL_MACHINE\\"):
		root = registry.LOCAL_MACHINE
		rest = p[strings.Index(p, "\\")+1:]
	case strings.HasPrefix(up, "HKCU\\") || strings.HasPrefix(up, "HKEY_CURRENT_USER\\"):
		root = registry.CURRENT_USER
		rest = p[strings.Index(p, "\\")+1:]
	case strings.HasPrefix(up, "HKU\\") || strings.HasPrefix(up, "HKEY_USERS\\"):
		root = registry.USERS
		rest = p[strings.Index(p, "\\")+1:]
	default:
		return 0, "", fmt.Errorf("bad registry path")
	}
	return root, rest, nil
}

func matchSCAMatcher(part, hay string) bool {
	part = strings.TrimSpace(part)
	low := strings.ToLower(part)
	hayFold := strings.ToLower(hay)
	if low == "r:present" || strings.HasPrefix(low, "r:^present") {
		return hay != ""
	}
	if strings.HasPrefix(low, "n:") {
		return matchSCANumeric(part, hay)
	}
	if strings.HasPrefix(low, "r:") {
		pat := strings.TrimSpace(part[2:])
		if strings.HasPrefix(pat, "r:") {
			pat = pat[2:]
		}
		re, err := regexp.Compile("(?is)" + wazuhRegexToGo(pat))
		if err != nil {
			return strings.Contains(hayFold, strings.ToLower(pat))
		}
		return re.FindStringIndex(hay) != nil
	}
	return strings.Contains(hayFold, strings.ToLower(part))
}

func matchSCANumeric(part, hay string) bool {
	// n:PasswordHistorySize = (\d+) compare >= 24
	re := regexp.MustCompile(`(?is)n:([^\s=]+)\s*=\s*\(([^)]+)\)\s*compare\s*([<>!=]+)\s*(-?\d+(?:\.\d+)?)`)
	m := re.FindStringSubmatch(part)
	if len(m) < 5 {
		return false
	}
	subRe, err := regexp.Compile("(?is)" + m[2])
	if err != nil {
		return false
	}
	cap := subRe.FindStringSubmatch(hay)
	if len(cap) < 2 {
		return false
	}
	val, err := strconv.ParseFloat(cap[1], 64)
	if err != nil {
		return false
	}
	thr, _ := strconv.ParseFloat(m[4], 64)
	op := strings.TrimSpace(m[3])
	switch op {
	case ">=":
		return val >= thr
	case "<=":
		return val <= thr
	case ">":
		return val > thr
	case "<":
		return val < thr
	case "==", "=":
		return val == thr
	case "!=":
		return val != thr
	default:
		return false
	}
}

func wazuhRegexToGo(pat string) string {
	pat = strings.TrimSpace(pat)
	if strings.HasPrefix(pat, "r:") {
		pat = pat[2:]
	}
	pat = strings.ReplaceAll(pat, `(?i)`, "")
	pat = strings.ReplaceAll(pat, `\`, `\`)
	return pat
}

func runBundledSCA() []map[string]any {
	var failed []map[string]any
	limit := scaMaxPerRun()
	for _, pol := range scaPoliciesSnapshot() {
		if !evalSCARequirements(pol.Requirements) {
			continue
		}
		batch := scaNextChecks(pol.ID, pol.Checks, limit)
		for _, ch := range batch {
			pass, why := evalSCACheck(ch)
			if pass {
				continue
			}
			id := fmt.Sprintf("%v", ch.ID)
			if id == "" {
				id = pol.ID
			}
			failed = append(failed, map[string]any{
				"id":       "sca." + pol.ID + "." + id,
				"title":    ch.Title,
				"status":   "fail",
				"policy":   pol.ID,
				"detail":   why,
				"mitre":    ch.Mitre,
			})
		}
	}
	return failed
}
