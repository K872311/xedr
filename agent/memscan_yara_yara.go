//go:build yara

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	yara "github.com/hillu/go-yara/v4"
)

var (
	yaraRules   *yara.Rules
	yaraRulesMu sync.RWMutex
)

func reloadYaraCompiledRules(dir string) error {
	var paths []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(strings.ToLower(name), ".yar") || strings.HasSuffix(strings.ToLower(name), ".yara") {
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	if len(paths) == 0 {
		for _, name := range []string{"reflective_loader.yar", "cobalt_strike.yar", "mimikatz.yar", "amsi_bypass.yar"} {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				paths = append(paths, p)
			}
		}
	}
	if len(paths) == 0 {
		yaraRulesMu.Lock()
		yaraRules = nil
		yaraEngineOK = false
		yaraRulesMu.Unlock()
		return nil
	}
	rules, err := yara.ParseRulesFiles(paths...)
	if err != nil {
		yaraEngineOK = false
		return err
	}
	yaraRulesMu.Lock()
	if yaraRules != nil {
		yaraRules.Destroy()
	}
	yaraRules = rules
	yaraEngineOK = true
	yaraRulesMu.Unlock()
	return nil
}

func scanYaraOnRegion(chunk []byte, baseAddr uintptr, pid uint32, procName string) []map[string]any {
	yaraRulesMu.RLock()
	rules := yaraRules
	yaraRulesMu.RUnlock()
	if rules == nil || len(chunk) == 0 {
		return nil
	}
	var matches yara.MatchRules
	scanner, err := yara.NewScanner(rules)
	if err != nil {
		return nil
	}
	if err := scanner.ScanMem(chunk, &matches); err != nil {
		return nil
	}
	var out []map[string]any
	for _, m := range matches {
		sev := "high"
		rid := m.Rule
		if meta := m.Metas; len(meta) > 0 {
			for _, me := range meta {
				switch strings.ToLower(me.Identifier) {
				case "severity":
					sev = me.String
				case "id":
					rid = me.String
				}
			}
		}
		var strs []string
		for _, s := range m.Strings {
			strs = append(strs, fmt.Sprintf("%s:%s", s.Name, truncate(string(s.Data), 80)))
		}
		out = append(out, map[string]any{
			"type":           "memory_yara",
			"rule_id":        rid,
			"rule_name":      m.Rule,
			"severity":       sev,
			"engine":         "yara",
			"address":        fmt.Sprintf("0x%X", baseAddr),
			"pid":            pid,
			"name":           procName,
			"matched_strings": strings.Join(strs, "; "),
			"summary":        fmt.Sprintf("YARA[%s]: %s pid=%d @0x%X", m.Rule, procName, pid, baseAddr),
		})
	}
	return out
}
