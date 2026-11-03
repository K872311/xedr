package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type APIClient struct {
	base   string
	token  string // 共享接入密钥：仅用于首次/重新注册
	client *http.Client

	credMu  sync.RWMutex
	secret  string // 每 Agent 独立凭据（优先使用）
	agentID string
}

// apiError 保留 HTTP 状态，供调用方区分鉴权失败 / 不支持 / 网络故障。
type apiError struct {
	Path   string
	Status int
	Body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s HTTP %d: %s", e.Path, e.Status, truncate(e.Body, 300))
}

func isAuthError(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && (ae.Status == 401 || ae.Status == 403)
}

// isCredentialRejected 仅指凭据无效（401）；403 吊销不应自动重新注册。
func isCredentialRejected(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == 401
}

func isV2Unsupported(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && (ae.Status == 404 || ae.Status == 405)
}

func (c *APIClient) setCredential(secret, agentID string) {
	c.credMu.Lock()
	c.secret, c.agentID = secret, agentID
	c.credMu.Unlock()
}

func (c *APIClient) credential() (string, string) {
	c.credMu.RLock()
	defer c.credMu.RUnlock()
	return c.secret, c.agentID
}

func newClient(cfg Config) *APIClient {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &APIClient{
		base:  cfg.ServerURL,
		token: cfg.Token,
		client: &http.Client{
			Timeout:   45 * time.Second,
			Transport: tr,
		},
	}
}

func (c *APIClient) post(path string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if sec, aid := c.credential(); sec != "" {
		req.Header.Set("Authorization", "Bearer "+sec)
		if aid != "" {
			req.Header.Set("X-Agent-Id", aid)
		}
	} else {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return &apiError{Path: path, Status: resp.StatusCode, Body: string(data)}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

type registerResp struct {
	OK               bool           `json:"ok"`
	AgentID          string         `json:"agent_id"`
	ProtocolVersion  int            `json:"protocol_version"`
	ProtocolSelected int            `json:"protocol_selected"`
	ServerCaps       []string       `json:"server_capabilities"`
	EnabledCaps      []string       `json:"enabled_capabilities"`
	AgentSecret      string         `json:"agent_secret"`
	Warning          string         `json:"protocol_warning"`
	Modules          []string       `json:"modules"`
	IntervalsSec     map[string]int `json:"intervals_sec"`
	Error            string         `json:"error"`
}

func (c *APIClient) Register(hostname, osFamily, ip, version, agentID string) (*registerResp, error) {
	var out registerResp
	body := map[string]any{
		"hostname":  hostname,
		"os_family": osFamily,
		"ip":        ip,
		"version":   version,
		"agent_id":  agentID,
	}
	for k, v := range registerExtras() {
		body[k] = v
	}
	err := c.post("/api/agent/register", body, &out)
	if err != nil {
		return nil, err
	}
	if !out.OK || out.AgentID == "" {
		return nil, fmt.Errorf("register 失败: %s", out.Error)
	}
	return &out, nil
}

type agentCommand struct {
	ID       string         `json:"id"`
	Action   string         `json:"action"`
	Params   map[string]any `json:"params"`
	Attempt  int            `json:"attempt"`
	LeaseSec int            `json:"lease_sec"`
	Deadline string         `json:"deadline"`
}

type heartbeatResp struct {
	OK           bool             `json:"ok"`
	IntervalsSec map[string]int   `json:"intervals_sec"`
	HeartbeatSec int              `json:"heartbeat_sec"`
	Commands     []agentCommand   `json:"commands"`
	Policy       map[string]any   `json:"policy"`
	PolicyRev    int              `json:"policy_rev"`
	Whitelist    []map[string]any `json:"whitelist"`
	// RuleFIMPaths 由「文件规则 + 路径前缀」自动生成的监控目录（如 D:\Tools|r|exe,dll）
	RuleFIMPaths []string `json:"rule_fim_paths"`
	MemoryYaraRev string           `json:"memory_yara_rev"`
	SyncRev       int              `json:"sync_rev"`
	SyncManifest  map[string]any   `json:"sync_manifest"`
	PolicyApplied bool             `json:"policy_applied"`
	AckedCommandIDs []string       `json:"acked_command_ids"`
	Error         string           `json:"error"`
}

type batchResp struct {
	OK       bool     `json:"ok"`
	Acked    []string `json:"acked"`
	Rejected []struct {
		UUID  string `json:"uuid"`
		Error string `json:"error"`
	} `json:"rejected"`
	Duplicates int `json:"duplicates"`
}

// SendBatch 调用 v2 幂等批量上报。身份来自凭据，agent_id 仅作冗余声明。
func (c *APIClient) SendBatch(stream string, events []map[string]any) (*batchResp, error) {
	var out batchResp
	_, aid := c.credential()
	if err := c.post("/api/agent/v2/events/batch", map[string]any{
		"agent_id": aid, "stream": stream, "events": events,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RotateSecret 自助轮换独立凭据。
func (c *APIClient) RotateSecret() (string, error) {
	var out struct {
		OK          bool   `json:"ok"`
		AgentSecret string `json:"agent_secret"`
	}
	_, aid := c.credential()
	if err := c.post("/api/agent/credential/rotate", map[string]any{"agent_id": aid}, &out); err != nil {
		return "", err
	}
	return out.AgentSecret, nil
}

func (c *APIClient) Heartbeat(agentID, ip string, health map[string]any, pm *policyManager) (*heartbeatResp, error) {
	var out heartbeatResp
	body := map[string]any{
		"agent_id": agentID,
		"ip":       ip,
		"agent_ts": fmt.Sprintf("%.3f", float64(time.Now().UnixMilli())/1000),
	}
	if pm != nil {
		ps := pm.state()
		appliedRev, _ := ps["applied_rev"].(int)
		if appliedRev == 0 {
			if f, ok := numberOf(ps["applied_rev"]); ok {
				appliedRev = int(f)
			}
		}
		body["local_sync_rev"] = localSyncRev()
		body["local_policy_rev"] = appliedRev
		body["policy_applied"] = policyApplied(pm)
	}
	if acks := drainHeartbeatAcks(); len(acks) > 0 {
		body["command_acks"] = acks
	}
	if health != nil {
		body["health"] = health
	}
	err := c.post("/api/agent/heartbeat", body, &out)
	if err != nil {
		return nil, err
	}
	if !out.OK {
		return nil, fmt.Errorf("heartbeat 失败: %s", out.Error)
	}
	return &out, nil
}

func (c *APIClient) AckCommand(id string, ok bool, result map[string]any) error {
	var out map[string]any
	return c.post("/api/agent/commands/ack", map[string]any{
		"id":     id,
		"ok":     ok,
		"result": result,
	}, &out)
}

func (c *APIClient) Timeline(agentID, hostname string, events []map[string]any) error {
	events = filterTimelineEvents(events)
	if len(events) == 0 {
		return nil
	}
	var out map[string]any
	return c.post("/api/agent/timeline", map[string]any{
		"agent_id": agentID,
		"hostname": hostname,
		"events":   events,
	}, &out)
}

func (c *APIClient) Snapshot(agentID, module, collectedAt, digest string, items []any) error {
	var out map[string]any
	return c.post("/api/agent/snapshot", map[string]any{
		"agent_id":     agentID,
		"module":       module,
		"collected_at": collectedAt,
		"digest":       digest,
		"items":        items,
	}, &out)
}

func (c *APIClient) Event(agentID, module, severity, title, detail string) error {
	var out map[string]any
	return c.post("/api/agent/event", map[string]any{
		"agent_id":  agentID,
		"module":    module,
		"severity":  severity,
		"title":     title,
		"detail":    detail,
		"hostname":  hostname(),
	}, &out)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
