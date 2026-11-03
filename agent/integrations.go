package main

import (
	"sync"
)

var (
	intMu      sync.RWMutex
	integrations = map[string]bool{
		"etw": true, "winevent": true, "wmi_process": false, "fim": true, "registry": true, "persist": true, "device": true,
		"memory_scan": true, "evm": true, "ptm": true, "amsi": true, "api_etw": true,
		"rootcheck": true, "sca": true,
	}
)

func loadIntegrationsDefaults(doc map[string]any) {
	def, _ := doc["defaults"].(map[string]any)
	if def == nil {
		return
	}
	intMu.Lock()
	defer intMu.Unlock()
	for k, v := range def {
		if b, ok := v.(bool); ok {
			integrations[k] = b
		}
	}
}

func applyIntegrationsPolicy(pol map[string]any) {
	raw, ok := pol["integrations"].(map[string]any)
	if !ok {
		return
	}
	intMu.Lock()
	defer intMu.Unlock()
	for k, v := range raw {
		if b, ok := v.(bool); ok {
			integrations[k] = b
		}
	}
}

func integrationEnabled(name string) bool {
	intMu.RLock()
	defer intMu.RUnlock()
	v, ok := integrations[name]
	if !ok {
		return true
	}
	return v
}
