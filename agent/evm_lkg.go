package main

import (
	"encoding/json"
	"sync"
)

const kvEvmLKG = "evm:lkg"

var (
	evmLKGMu sync.Mutex
	evmStore *stateDB
)

func bindEvmStore(st *stateDB) {
	evmLKGMu.Lock()
	evmStore = st
	evmLKGMu.Unlock()
}

func persistEvmLKG(doc map[string]any) {
	if doc == nil {
		return
	}
	evmLKGMu.Lock()
	st := evmStore
	evmLKGMu.Unlock()
	if st == nil {
		return
	}
	b, err := json.Marshal(doc)
	if err != nil || len(b) < 8 {
		return
	}
	st.kvSet(kvEvmLKG, string(b))
}

func loadEvmLKGOffline() bool {
	evmLKGMu.Lock()
	st := evmStore
	evmLKGMu.Unlock()
	if st == nil {
		return false
	}
	raw := st.kvGet(kvEvmLKG)
	if raw == "" {
		return false
	}
	var doc map[string]any
	if json.Unmarshal([]byte(raw), &doc) != nil || doc == nil {
		return false
	}
	loadEVMDocument(doc)
	return len(evmRulesSnapshot()) > 0
}

func evmRulesSnapshot() []evmRule {
	evmMu.RLock()
	defer evmMu.RUnlock()
	return append([]evmRule(nil), evmRules...)
}
