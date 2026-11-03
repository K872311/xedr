package main

import (
	_ "embed"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed data/memory_yara_rules.json
var embeddedMemoryYaraJSON []byte

type memYaraRule struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"`
	Mitre          []string `json:"mitre"`
	Strings        []string `json:"strings"`
	BuildingBlock  bool     `json:"building_block"`
	YaraOnly       bool     `json:"yara_only"`
}

type memYaraRulesDoc struct {
	Rev   string        `json:"rev"`
	Rules []memYaraRule `json:"rules"`
}

var (
	memRulesMu   sync.RWMutex
	memRulesRev  string
	memRulesList []memYaraRule
	yaraEngineOK bool
)

func defaultStateDir() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return filepath.Join(p, "ForensicAgent")
	}
	d, _ := os.UserConfigDir()
	if d == "" {
		return "."
	}
	return filepath.Join(d, "ForensicAgent")
}

func memoryYaraDir(cfg Config) string {
	base := strings.TrimSpace(cfg.StateDir)
	if base == "" {
		base = defaultStateDir()
	}
	return filepath.Join(base, "memory-yara")
}

func loadEmbeddedMemoryRules() {
	memRulesMu.Lock()
	defer memRulesMu.Unlock()
	var doc memYaraRulesDoc
	if json.Unmarshal(embeddedMemoryYaraJSON, &doc) != nil {
		return
	}
	memRulesRev = doc.Rev
	memRulesList = doc.Rules
}

func loadMemoryRulesFromDisk(dir string) bool {
	p := filepath.Join(dir, "rules.json")
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	var doc memYaraRulesDoc
	if json.Unmarshal(b, &doc) != nil {
		return false
	}
	memRulesMu.Lock()
	memRulesRev = doc.Rev
	memRulesList = doc.Rules
	memRulesMu.Unlock()
	return true
}

func saveMemoryRulesBundle(dir string, files map[string]string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	return reloadYaraCompiledRules(dir)
}

func syncMemoryYaraRules(wantRev string) error {
	if globalCfg.StateDir == "" && globalCfg.ServerURL == "" {
		return nil
	}
	dir := memoryYaraDir(globalCfg)
	if loadMemoryRulesFromDisk(dir) && memRulesRev == wantRev && wantRev != "" {
		return reloadYaraCompiledRules(dir)
	}
	if globalAPI == nil {
		return nil
	}
	b, err := globalAPI.FetchMemoryYaraBundle(wantRev)
	if err != nil || b == nil || !b.OK {
		if !loadMemoryRulesFromDisk(dir) {
			loadEmbeddedMemoryRules()
		}
		return err
	}
	if err := saveMemoryRulesBundle(dir, b.Files); err != nil {
		log.Printf("memory-yara save: %v", err)
	}
	memRulesMu.Lock()
	memRulesRev = b.Rev
	memRulesMu.Unlock()
	return nil
}

func matchJSONMemoryRules(chunk []byte) []map[string]any {
	memRulesMu.RLock()
	rules := append([]memYaraRule(nil), memRulesList...)
	memRulesMu.RUnlock()
	if len(rules) == 0 {
		loadEmbeddedMemoryRules()
		memRulesMu.RLock()
		rules = append([]memYaraRule(nil), memRulesList...)
		memRulesMu.RUnlock()
	}
	low := strings.ToLower(string(chunk))
	var out []map[string]any
	for _, r := range rules {
		if r.YaraOnly && yaraEngineOK {
			continue
		}
		for _, s := range r.Strings {
			if s == "" {
				continue
			}
			if strings.Contains(low, strings.ToLower(s)) {
				out = append(out, map[string]any{
					"type":            "memory_rule",
					"rule_id":         r.ID,
					"rule_name":       r.Title,
					"severity":        r.Severity,
					"matched_string":  s,
					"engine":          "strings",
					"mitre":           r.Mitre,
					"building_block":  r.BuildingBlock,
				})
				break
			}
		}
	}
	return out
}

// 由 main 在启动时注入，供 sync 使用。
var (
	globalCfg Config
	globalAPI *APIClient
)
