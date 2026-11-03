package main

// elasticParitySnapshot 心跳上报：与 Elastic 各 Beat/Defend 的能力边界（非功能冒充）。
func elasticParitySnapshot() map[string]any {
	return map[string]any{
		"defend_kernel_tier": false,
		"memory_threat_tier": "user_yara_trigger",
		"winlog_tier":        "multi_channel_wevtapi",
		"etw_tier":           "native_builtin",
		"osquery_tier":       "live_query_tables",
		"metricbeat_tier":    "agent_host_basic",
		"filestream_tier":    "fim_log_tail",
		"config_refs": []string{
			"config/agent_elastic_parity.json",
			"config/agent_winlog_channels.json",
			"config/agent_etw_coverage.json",
			"config/agent_live_query_tables.json",
		},
	}
}
