package main

import (
	"encoding/json"
	"log"
	"sync"
)

type syncBundleResp struct {
	OK        bool           `json:"ok"`
	Unchanged bool           `json:"unchanged"`
	SyncRev   int            `json:"sync_rev"`
	Policy    map[string]any `json:"policy"`
	PolicyRev int            `json:"policy_rev"`
	EVM       map[string]any `json:"evm"`
	MemoryYara map[string]any `json:"memory_yara"`
	Whitelist []map[string]any `json:"whitelist"`
	IOC       []map[string]any `json:"ioc"`
	PTM       map[string]any `json:"ptm"`
	AmsiRules map[string]any `json:"amsi_rules"`
	APIRules  map[string]any `json:"api_rules"`
	ActiveResponse map[string]any `json:"active_response"`
	Integrations   map[string]any `json:"integrations"`
	RuleFIMPaths   []string       `json:"rule_fim_paths"`
	FimRegistry    []string       `json:"fim_registry_paths"`
	SCA            map[string]any `json:"sca"`
	Error     string         `json:"error"`
}

var (
	syncMu     sync.Mutex
	lastSyncRev int
)

func (c *APIClient) FetchSync(agentID string, sinceRev int) (*syncBundleResp, error) {
	var out syncBundleResp
	err := c.post("/api/agent/sync", map[string]any{
		"agent_id": agentID, "since_rev": sinceRev,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func applySyncBundle(b *syncBundleResp, pm *policyManager, syncFIM func()) {
	if b == nil || !b.OK || b.Unchanged {
		return
	}
	if b.Policy != nil && b.PolicyRev > 0 {
		pm.offer(b.PolicyRev, b.Policy)
		applyHeartbeatPolicyPatch(b.Policy)
		applyIntegrationsPolicy(b.Policy)
		recordSyncPart("policy", true, "")
	}
	if b.EVM != nil {
		loadEVMDocument(b.EVM)
		recordSyncPart("evm", true, "")
	} else if len(evmRulesSnapshot()) == 0 {
		if loadEvmLKGOffline() {
			recordSyncPart("evm", true, "lkg_offline")
		}
	}
	if b.PTM != nil {
		loadPTMDocument(b.PTM)
		recordSyncPart("ptm", true, "")
	}
	if b.AmsiRules != nil {
		loadAPIRulesDocument(b.AmsiRules)
		recordSyncPart("amsi_rules", true, "")
	}
	if b.APIRules != nil {
		loadAPIRulesDocument(b.APIRules)
		recordSyncPart("api_rules", true, "")
	}
	if b.ActiveResponse != nil {
		loadActiveResponseDoc(b.ActiveResponse)
		recordSyncPart("active_response", true, "")
	}
	if b.Integrations != nil {
		loadIntegrationsDefaults(b.Integrations)
		recordSyncPart("integrations", true, "")
	}
	if len(b.Whitelist) > 0 {
		loadAgentWhitelist(b.Whitelist)
		recordSyncPart("whitelist", true, "")
	}
	if len(b.IOC) > 0 {
		loadAgentIOC(b.IOC)
		recordSyncPart("ioc", true, "")
	}
	if b.MemoryYara != nil {
		if rev := asString(b.MemoryYara["rev"]); rev != "" {
			pullMemoryYaraIfNeeded(rev)
		}
		if filesRaw, ok := b.MemoryYara["files"].(map[string]any); ok && len(filesRaw) > 0 {
			files := map[string]string{}
			for k, v := range filesRaw {
				files[k] = asString(v)
			}
			dir := memoryYaraDir(globalCfg)
			_ = saveMemoryRulesBundle(dir, files)
		}
		recordSyncPart("memory_yara", true, "")
	}
	if len(b.RuleFIMPaths) > 0 {
		applyRuleFIMPaths(b.RuleFIMPaths, syncFIM)
		recordSyncPart("rule_fim", true, "")
	}
	if len(b.FimRegistry) > 0 {
		setRegistryFIMExtras(b.FimRegistry)
		recordSyncPart("fim_registry", true, "")
	} else {
		applyRegistryFIMSync(globalRegWatcher)
	}
	if b.SCA != nil {
		loadSCABundle(b.SCA)
		recordSyncPart("sca", true, "")
	}
	noteAppliedSyncRev(b.SyncRev)
	syncMu.Lock()
	lastSyncRev = b.SyncRev
	syncMu.Unlock()
}

func maybeSyncFromServer(api *APIClient, agentID string, serverSyncRev int, pm *policyManager, syncFIM func()) {
	if serverSyncRev <= 0 {
		return
	}
	syncMu.Lock()
	local := lastSyncRev
	syncMu.Unlock()
	if serverSyncRev <= local {
		return
	}
	b, err := api.FetchSync(agentID, local)
	if err != nil {
		log.Printf("sync: %v", err)
		recordSyncPart("fetch", false, err.Error())
		return
	}
	applySyncBundle(b, pm, syncFIM)
}

func loadAgentWhitelist(items []map[string]any) {
	raw, _ := json.Marshal(items)
	agentWhitelistJSON = string(raw)
}

func loadAgentIOC(items []map[string]any) {
	raw, _ := json.Marshal(items)
	agentIOCJSON = string(raw)
}

var (
	agentWhitelistJSON string
	agentIOCJSON       string
)
