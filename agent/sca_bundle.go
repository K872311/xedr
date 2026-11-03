package main

import (
	"encoding/json"
	"sync"
)

type scaRule struct {
	Kind string `json:"kind"`
	Expr string `json:"expr"`
}

type scaCheck struct {
	ID        any              `json:"id"`
	Title     string           `json:"title"`
	Condition string           `json:"condition"`
	Rules     []scaRule        `json:"rules"`
	Mitre     []string         `json:"mitre"`
}

type scaPolicy struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Platform     string     `json:"platform"`
	Requirements []scaRule  `json:"requirements"`
	Checks       []scaCheck `json:"checks"`
}

type scaBundle struct {
	Version          int         `json:"version"`
	MaxChecksPerRun  int         `json:"max_checks_per_run"`
	Policies         []scaPolicy `json:"policies"`
}

var (
	scaBundleMu sync.RWMutex
	scaBundleDoc scaBundle
	scaRunCursor map[string]int
)

func init() {
	scaRunCursor = map[string]int{}
}

func loadSCABundle(raw map[string]any) {
	if raw == nil {
		return
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return
	}
	var doc scaBundle
	if json.Unmarshal(b, &doc) != nil {
		return
	}
	if doc.MaxChecksPerRun <= 0 {
		doc.MaxChecksPerRun = 48
	}
	scaBundleMu.Lock()
	scaBundleDoc = doc
	scaBundleMu.Unlock()
}

func scaMaxPerRun() int {
	scaBundleMu.RLock()
	n := scaBundleDoc.MaxChecksPerRun
	scaBundleMu.RUnlock()
	if n <= 0 {
		return 48
	}
	return n
}

func scaPoliciesSnapshot() []scaPolicy {
	scaBundleMu.RLock()
	defer scaBundleMu.RUnlock()
	out := make([]scaPolicy, len(scaBundleDoc.Policies))
	copy(out, scaBundleDoc.Policies)
	return out
}

func scaNextChecks(policyID string, checks []scaCheck, limit int) []scaCheck {
	if limit <= 0 || len(checks) == 0 {
		return nil
	}
	scaBundleMu.Lock()
	start := scaRunCursor[policyID]
	if start >= len(checks) {
		start = 0
	}
	end := start + limit
	if end > len(checks) {
		end = len(checks)
	}
	batch := checks[start:end]
	scaRunCursor[policyID] = end
	if scaRunCursor[policyID] >= len(checks) {
		scaRunCursor[policyID] = 0
	}
	scaBundleMu.Unlock()
	return batch
}
