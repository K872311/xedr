//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	upgradeWatchdogSec     = 180 // 升级后 N 秒内须完成至少一次成功心跳，否则回滚 N-1
	upgradeHealthyFileName = "healthy.marker"
	upgradePendingFileName = "pending.json"
)

type upgradePending struct {
	Version   string `json:"version"`
	Bak       string `json:"bak"`
	Self      string `json:"self"`
	Deadline  int64  `json:"deadline_unix"`
	CreatedAt string `json:"created_at"`
}

func upgradeDir(cfg Config) string {
	return filepath.Join(cfg.StateDir, "upgrade")
}

func upgradePendingPath(cfg Config) string {
	return filepath.Join(upgradeDir(cfg), upgradePendingFileName)
}

func upgradeHealthyPath(cfg Config) string {
	return filepath.Join(upgradeDir(cfg), upgradeHealthyFileName)
}

// armUpgradeWatchdog：替换成功后写入 pending，并拉起独立 bat 兜底（即使新进程秒崩也能回滚）。
func armUpgradeWatchdog(cfg Config, self, bak, version string) {
	_ = os.MkdirAll(upgradeDir(cfg), 0700)
	_ = os.Remove(upgradeHealthyPath(cfg))
	deadline := time.Now().Add(upgradeWatchdogSec * time.Second).Unix()
	meta := upgradePending{
		Version:   version,
		Bak:       bak,
		Self:      self,
		Deadline:  deadline,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(meta, "", "  ")
	_ = os.WriteFile(upgradePendingPath(cfg), b, 0600)

	script := filepath.Join(upgradeDir(cfg), "watchdog_rollback.bat")
	mark := upgradeHealthyPath(cfg)
	bat := fmt.Sprintf("@echo off\r\n"+
		"timeout /t %d /nobreak >nul\r\n"+
		"if exist \"%s\" exit /b 0\r\n"+
		"if not exist \"%s\" exit /b 1\r\n"+
		"net stop %s >nul 2>&1\r\n"+
		"timeout /t 2 /nobreak >nul\r\n"+
		"move /y \"%s\" \"%s\" >nul 2>&1\r\n"+
		"net start %s >nul 2>&1\r\n"+
		"del /f /q \"%s\" >nul 2>&1\r\n",
		upgradeWatchdogSec, mark, bak, serviceName, bak, self, serviceName, upgradePendingPath(cfg))
	_ = os.WriteFile(script, []byte(bat), 0700)
	_, _ = runCmd(5*time.Second, "cmd", "/c", "start", "", script)
	log.Printf("upgrade watchdog armed: %ds bak=%s ver=%s", upgradeWatchdogSec, bak, version)
}

// markUpgradeHealthy：升级后首次心跳成功 → 取消自动回滚。
func markUpgradeHealthy(cfg Config) {
	p := upgradePendingPath(cfg)
	if _, err := os.Stat(p); err != nil {
		return
	}
	_ = os.MkdirAll(upgradeDir(cfg), 0700)
	_ = os.WriteFile(upgradeHealthyPath(cfg), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0600)
	_ = os.Remove(p)
	clearUpgradePhase()
	log.Printf("upgrade watchdog cleared (healthy)")
}

// checkUpgradeWatchdog：服务/进程启动时若 pending 已过期且无 healthy 标记，就地回滚 N-1。
func checkUpgradeWatchdog(cfg Config) {
	p := upgradePendingPath(cfg)
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	if _, err := os.Stat(upgradeHealthyPath(cfg)); err == nil {
		_ = os.Remove(p)
		return
	}
	var meta upgradePending
	if json.Unmarshal(b, &meta) != nil || meta.Bak == "" || meta.Self == "" {
		return
	}
	if time.Now().Unix() < meta.Deadline {
		return
	}
	if _, err := os.Stat(meta.Bak); err != nil {
		_ = os.Remove(p)
		return
	}
	setUpgradePhase("ROLLBACK", meta.Version, "ROLLBACK")
	log.Printf("upgrade watchdog: 超时未健康，回滚 N-1 → %s", meta.Bak)
	tmp := meta.Self + ".watchdog_tmp"
	_ = os.Remove(tmp)
	_ = os.Rename(meta.Self, tmp)
	if err := copyFile(meta.Bak, meta.Self); err != nil {
		_ = os.Rename(tmp, meta.Self)
		log.Printf("upgrade watchdog 回滚失败: %v", err)
		return
	}
	_ = os.Remove(tmp)
	_ = os.Remove(p)
	script := filepath.Join(upgradeDir(cfg), "watchdog_restart.bat")
	bat := fmt.Sprintf("@echo off\r\ntimeout /t 2 /nobreak >nul\r\nnet stop %s\r\nnet start %s\r\n", serviceName, serviceName)
	_ = os.WriteFile(script, []byte(bat), 0700)
	_, _ = runCmd(5*time.Second, "cmd", "/c", "start", "", script)
}
