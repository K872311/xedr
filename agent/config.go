package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const agentVersion = "0.13.1"

type Config struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
	AgentID   string `json:"agent_id"`
	Insecure  bool   `json:"insecure_skip_verify"`
	// 覆盖默认周期（秒）；0 表示用内置默认
	Intervals map[string]int `json:"intervals_sec"`
	StateDir  string         `json:"state_dir"`
	Once      bool           `json:"-"`
	Modules   []string       `json:"modules"`

	// 每 Agent 独立凭据：落盘只存 DPAPI 密文；Secret 为运行期明文，不序列化。
	SecretBlob string `json:"agent_secret_dpapi,omitempty"`
	Secret     string `json:"-"`

	// UpgradePubKey：Ed25519 升级公钥（base64 或 hex:…）；优先于编译期 upgradePubKeyB64。
	UpgradePubKey string `json:"upgrade_pubkey,omitempty"`
}

// loadSecret 解出运行期明文凭据；解不开（换机/损坏）则丢弃，退回共享密钥重新注册换取新凭据。
func (c *Config) loadSecret() {
	if c.SecretBlob == "" {
		return
	}
	s, err := unprotectSecret(c.SecretBlob)
	if err != nil {
		c.Secret, c.SecretBlob = "", ""
		return
	}
	c.Secret = s
}

func defaultModules() []string {
	return []string{
		"sysinfo", "service", "task", "startup", "network", "process", "file", "user",
		"software", "hotfix", "listen", "driver", "browser",
	}
}

// addedModules 新版本新增的模块：旧 agent.json 里写死了模块列表时自动补上。
var addedModules = []string{"driver", "browser"}

func withAddedModules(mods []string) []string {
	have := map[string]bool{}
	for _, m := range mods {
		have[m] = true
	}
	for _, m := range addedModules {
		if !have[m] {
			mods = append(mods, m)
		}
	}
	return mods
}

func defaultIntervals() map[string]int {
	return map[string]int{
		"sysinfo":  300,
		"service":  600,
		"task":     900,
		"startup":  300,
		"network":  60,
		"process":  120,
		"file":     900,
		"user":     300,
		"software": 1800,
		"hotfix":   7200,
		"listen":   300,
		"driver":   1800,
		"browser":  900,
	}
}

// loadConfigFile 仅从 JSON 读配置（服务兜底，不碰 flag）。
func loadConfigFile(path string) (Config, error) {
	cfg := Config{
		Intervals: defaultIntervals(),
		Modules:   defaultModules(),
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	cfg.loadSecret()
	cfg.ServerURL = strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	if cfg.ServerURL == "" {
		return cfg, fmt.Errorf("配置缺少 server_url")
	}
	if cfg.Token == "" {
		return cfg, fmt.Errorf("配置缺少 token")
	}
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Dir(path)
	}
	if abs, e := filepath.Abs(cfg.StateDir); e == nil {
		cfg.StateDir = abs
	}
	if len(cfg.Modules) == 0 {
		cfg.Modules = defaultModules()
	}
	cfg.Modules = withAddedModules(cfg.Modules)
	def := defaultIntervals()
	if cfg.Intervals == nil {
		cfg.Intervals = def
	} else {
		for k, v := range def {
			if cfg.Intervals[k] <= 0 {
				cfg.Intervals[k] = v
			}
		}
	}
	return cfg, nil
}

func writeExampleConfig(path string) {
	ex := Config{
		ServerURL: "http://127.0.0.1:8100",
		Token:     "粘贴平台登录 Token",
		Modules:   defaultModules(),
		Intervals: defaultIntervals(),
	}
	b, _ := json.MarshalIndent(ex, "", "  ")
	_ = os.WriteFile(path, b, 0644)
	fmt.Println("已写出", path)
}

// loadConfig 解析 flags。serviceMode 时默认配置落在 exe 同目录。
func loadConfig(serviceMode bool) (cfg Config, cfgPath string, err error) {
	var (
		server   string
		token    string
		agentID  string
		once     bool
		stateDir string
		modules  string
		writeEx  bool
		insecure bool
	)
	defCfg := "agent.json"
	if serviceMode {
		defCfg = filepath.Join(exeDir(), "agent.json")
	}
	flag.StringVar(&cfgPath, "config", defCfg, "配置文件路径")
	flag.StringVar(&server, "server", "", "EDR 后台地址，如 http://10.0.0.8:8100")
	flag.StringVar(&token, "token", "", "平台 Bearer Token")
	flag.StringVar(&agentID, "id", "", "已有 agent_id（空则首次注册）")
	flag.StringVar(&stateDir, "state", "", "状态/日志目录（默认与配置同目录）")
	flag.StringVar(&modules, "modules", "", "逗号分隔模块，空=全部")
	flag.BoolVar(&once, "once", false, "只采集上报一轮后退出")
	flag.BoolVar(&insecure, "insecure", false, "跳过 TLS 证书校验")
	flag.BoolVar(&writeEx, "write-example", false, "写出 agent.example.json 后退出")
	flag.Parse()

	if writeEx {
		writeExampleConfig("agent.example.json")
		os.Exit(0)
	}

	cfg = Config{
		Intervals: defaultIntervals(),
		Modules:   defaultModules(),
	}
	if cfgPath != "" {
		if !filepath.IsAbs(cfgPath) {
			// 相对路径：优先当前目录，不存在则试 exe 目录（服务场景）
			if _, e := os.Stat(cfgPath); e != nil {
				alt := filepath.Join(exeDir(), cfgPath)
				if _, e2 := os.Stat(alt); e2 == nil {
					cfgPath = alt
				}
			}
		}
		if b, e := os.ReadFile(cfgPath); e == nil {
			_ = json.Unmarshal(b, &cfg)
			cfg.loadSecret()
		} else if serviceMode {
			return cfg, cfgPath, fmt.Errorf("读取配置失败 %s: %w", cfgPath, e)
		}
	}
	if server != "" {
		cfg.ServerURL = strings.TrimRight(server, "/")
	}
	if token != "" {
		cfg.Token = token
	}
	if agentID != "" {
		cfg.AgentID = agentID
	}
	if stateDir != "" {
		cfg.StateDir = stateDir
	}
	if modules != "" {
		cfg.Modules = splitCSV(modules)
	}
	if insecure {
		cfg.Insecure = true
	}
	cfg.Once = once
	cfg.ServerURL = strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	if cfg.ServerURL == "" {
		return cfg, cfgPath, fmt.Errorf("请指定 -server 或在配置里写 server_url")
	}
	if cfg.Token == "" {
		return cfg, cfgPath, fmt.Errorf("请指定 -token 或在配置里写 token")
	}
	if abs, e := filepath.Abs(cfgPath); e == nil {
		cfgPath = abs
	}
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Dir(cfgPath)
	}
	if abs, e := filepath.Abs(cfg.StateDir); e == nil {
		cfg.StateDir = abs
	}
	if len(cfg.Modules) == 0 {
		cfg.Modules = defaultModules()
	}
	cfg.Modules = withAddedModules(cfg.Modules)
	def := defaultIntervals()
	if cfg.Intervals == nil {
		cfg.Intervals = def
	} else {
		for k, v := range def {
			if cfg.Intervals[k] <= 0 {
				cfg.Intervals[k] = v
			}
		}
	}
	return cfg, cfgPath, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c Config) interval(module string) time.Duration {
	sec := c.Intervals[module]
	if sec <= 0 {
		sec = 120
	}
	return time.Duration(sec) * time.Second
}

func (c *Config) saveAgentID(path string) error {
	var raw map[string]any
	b, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(b, &raw)
	}
	if raw == nil {
		raw = map[string]any{}
	}
	if c.ServerURL != "" {
		raw["server_url"] = c.ServerURL
	} else if sv, _ := raw["server_url"].(string); strings.TrimSpace(sv) == "" {
		return fmt.Errorf("拒绝写入配置：缺少 server_url")
	}
	raw["token"] = c.Token
	raw["agent_id"] = c.AgentID
	raw["modules"] = c.Modules
	raw["intervals_sec"] = c.Intervals
	if c.StateDir != "" {
		raw["state_dir"] = c.StateDir
	}
	if c.SecretBlob != "" {
		raw["agent_secret_dpapi"] = c.SecretBlob
	} else {
		delete(raw, "agent_secret_dpapi")
	}
	out, _ := json.MarshalIndent(raw, "", "  ")
	return os.WriteFile(path, out, 0600)
}
