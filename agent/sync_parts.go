package main

import (
	"sync"
	"time"
)

type syncPartRecord struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	At    string `json:"at"`
}

var (
	syncPartsMu sync.RWMutex
	syncParts   = map[string]syncPartRecord{}
	lastSyncErr string
)

func recordSyncPart(name string, ok bool, errMsg string) {
	syncPartsMu.Lock()
	defer syncPartsMu.Unlock()
	syncParts[name] = syncPartRecord{
		OK: ok, Error: errMsg, At: time.Now().UTC().Format(time.RFC3339),
	}
	if !ok && errMsg != "" {
		lastSyncErr = name + ": " + errMsg
	}
}

func syncPartsSnapshot() map[string]any {
	syncPartsMu.RLock()
	defer syncPartsMu.RUnlock()
	parts := map[string]any{}
	allOK := true
	for k, v := range syncParts {
		parts[k] = map[string]any{"ok": v.OK, "error": v.Error, "at": v.At}
		if !v.OK {
			allOK = false
		}
	}
	return map[string]any{
		"parts":   parts,
		"all_ok":  allOK,
		"last_err": lastSyncErr,
	}
}

func applySyncPart(name string, fn func() error) {
	if fn == nil {
		return
	}
	if err := fn(); err != nil {
		recordSyncPart(name, false, err.Error())
		return
	}
	recordSyncPart(name, true, "")
}
