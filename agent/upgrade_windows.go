//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// doUpgrade 下载灰度包、校验 sha256 + Ed25519、替换本程序并武装 watchdog（失败自动回滚 N-1）。
func doUpgrade(cfg Config, params map[string]any) (map[string]any, error) {
	url := strings.TrimSpace(fmt.Sprint(params["url"]))
	wantSHA := strings.ToLower(strings.TrimSpace(fmt.Sprint(params["sha256"])))
	ver := strings.TrimSpace(fmt.Sprint(params["version"]))
	if url == "" || wantSHA == "" {
		return nil, fmt.Errorf("缺少 url 或 sha256")
	}
	setUpgradePhase("DOWNLOADING", ver, "UPGRADE")
	defer clearUpgradePhase()
	if strings.HasPrefix(url, "/") {
		url = strings.TrimRight(cfg.ServerURL, "/") + url
	}

	tmpDir := filepath.Join(cfg.StateDir, "upgrade")
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return nil, err
	}
	tmp := filepath.Join(tmpDir, fmt.Sprintf("fa_%d.exe", time.Now().Unix()))

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	if cfg.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Secret)
		req.Header.Set("X-Agent-Id", cfg.AgentID)
	}
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("下载 HTTP %d: %s", resp.StatusCode, string(b))
	}
	f, err := os.Create(tmp)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 80<<20))
	_ = f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != wantSHA {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("sha256 不匹配 want=%s got=%s", wantSHA[:16], got[:16])
	}
	setUpgradePhase("VERIFYING", ver, "UPGRADE")
	if err := verifyUpgradeSignature(cfg, params, got, ver, n); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}

	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	self, _ = filepath.Abs(self)
	bak := self + ".bak"
	// 保留 N-2 痕迹：现有 .bak 挪到 .bak.prev（尽力而为）
	if st, e := os.Stat(bak); e == nil && !st.IsDir() {
		_ = os.Remove(bak + ".prev")
		_ = os.Rename(bak, bak+".prev")
	}
	setUpgradePhase("REPLACING", ver, "UPGRADE")
	if err := os.Rename(self, bak); err != nil {
		// 被占用：先尽力备份当前 exe，再写旁路脚本替换
		if _, e := os.Stat(bak); e != nil {
			_ = copyFile(self, bak)
		}
		side := filepath.Join(filepath.Dir(self), "forensic-agent.new.exe")
		if err2 := copyFile(tmp, side); err2 != nil {
			return nil, fmt.Errorf("无法替换: %v / %v", err, err2)
		}
		_ = os.Remove(tmp)
		armUpgradeWatchdog(cfg, self, bak, ver)
		script := filepath.Join(tmpDir, "apply.bat")
		bat := fmt.Sprintf("@echo off\r\ntimeout /t 2 /nobreak >nul\r\nmove /y \"%s\" \"%s\"\r\nnet start %s\r\n", side, self, serviceName)
		_ = os.WriteFile(script, []byte(bat), 0700)
		_, _ = runCmd(5*time.Second, "cmd", "/c", "start", "", script)
		return map[string]any{
			"ok": true, "mode": "deferred", "version": ver, "bytes": n, "sha256": got,
			"pending": side, "sig_ok": true, "watchdog_sec": upgradeWatchdogSec,
		}, nil
	}
	if err := copyFile(tmp, self); err != nil {
		_ = os.Rename(bak, self) // 回滚
		return nil, err
	}
	_ = os.Remove(tmp)
	armUpgradeWatchdog(cfg, self, bak, ver)
	setUpgradePhase("UPGRADING", ver, "UPGRADE")
	script := filepath.Join(tmpDir, "restart.bat")
	bat := fmt.Sprintf("@echo off\r\ntimeout /t 2 /nobreak >nul\r\nnet stop %s\r\nnet start %s\r\n", serviceName, serviceName)
	_ = os.WriteFile(script, []byte(bat), 0700)
	_, _ = runCmd(5*time.Second, "cmd", "/c", "start", "", script)
	return map[string]any{
		"ok": true, "mode": "replaced", "version": ver, "bytes": n, "sha256": got, "bak": bak,
		"sig_ok": true, "watchdog_sec": upgradeWatchdogSec,
	}, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	cerr := out.Close()
	if err != nil {
		return err
	}
	return cerr
}
