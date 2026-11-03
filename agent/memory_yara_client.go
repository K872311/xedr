package main

type memoryYaraBundleResp struct {
	OK       bool              `json:"ok"`
	Rev      string            `json:"rev"`
	SHA256   string            `json:"sha256"`
	Files    map[string]string `json:"files"`
	Error    string            `json:"error"`
	RuleCount int              `json:"rule_count"`
}

func (c *APIClient) FetchMemoryYaraBundle(rev string) (*memoryYaraBundleResp, error) {
	var out memoryYaraBundleResp
	err := c.post("/api/agent/memory-yara", map[string]any{"rev": rev}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
