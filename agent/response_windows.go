//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func execCommand(cfg Config, cmd agentCommand) (map[string]any, error) {
	switch strings.ToLower(cmd.Action) {
	case "kill_process":
		return killProcess(cmd.Params)
	case "quarantine_file":
		return quarantineFile(cfg, cmd.Params)
	case "isolate_network":
		return isolateNetwork(cfg, true)
	case "unisolate_network":
		return isolateNetwork(cfg, false)
	case "refresh_modules":
		return map[string]any{"ok": true, "msg": "will refresh next tick"}, nil
	case "upgrade":
		return doUpgrade(cfg, cmd.Params)
	case "cancel_upgrade":
		return cancelUpgrade(cfg, cmd.Params)
	case "scan_memory":
		return scanMemory(cmd.Params)
	case "restore_file":
		return restoreQuarantine(cfg, cmd.Params)
	case "rollback_upgrade":
		return rollbackUpgrade(cfg, cmd.Params)
	case "uninstall_agent":
		return uninstallAgentRemote(cfg, cmd.Params)
	case "collect_diagnostics":
		return collectDiagnosticsBundle(cfg)
	case "live_query":
		return liveQueryExec(cmd.Params)
	case "reg_read", "fs_list", "fs_stat", "fs_read", "fs_volumes", "run_cmd",
		"shell_open", "shell_write", "shell_poll", "shell_close":
		return remoteOpsExec(cmd.Params, cmd.Action)
	default:
		return nil, fmt.Errorf("未知动作: %s", cmd.Action)
	}
}

// uninstallAgentRemote：先返回成功，再延时卸载服务并可选删除文件（避免指令通道被自己掐断）。
func uninstallAgentRemote(cfg Config, params map[string]any) (map[string]any, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	self, _ = filepath.Abs(self)
	removeFiles := true
	if v, ok := params["remove_files"]; ok {
		switch t := v.(type) {
		case bool:
			removeFiles = t
		case string:
			removeFiles = t != "0" && !strings.EqualFold(t, "false")
		}
	}
	dir := filepath.Join(cfg.StateDir, "upgrade")
	_ = os.MkdirAll(dir, 0700)
	script := filepath.Join(dir, "remote_uninstall.bat")
	// 等几秒让 ACK 上报完成，再 stop/delete 服务；可选删 exe
	bat := fmt.Sprintf("@echo off\r\n"+
		"timeout /t 3 /nobreak >nul\r\n"+
		"net stop %s >nul 2>&1\r\n"+
		"sc delete %s >nul 2>&1\r\n"+
		"timeout /t 2 /nobreak >nul\r\n", serviceName, serviceName)
	if removeFiles {
		bat += fmt.Sprintf("del /f /q \"%s\" >nul 2>&1\r\n", self)
		bat += fmt.Sprintf("del /f /q \"%s.bak\" >nul 2>&1\r\n", self)
	}
	if err := os.WriteFile(script, []byte(bat), 0700); err != nil {
		return nil, err
	}
	_, _ = runCmd(5*time.Second, "cmd", "/c", "start", "", script)
	return map[string]any{
		"ok": true, "scheduled": true, "remove_files": removeFiles, "script": script,
	}, nil
}

func restoreQuarantine(cfg Config, params map[string]any) (map[string]any, error) {
	qdir := filepath.Join(cfg.StateDir, "quarantine")
	destHint := strings.TrimSpace(fmt.Sprint(params["dest"]))
	origHint := strings.TrimSpace(fmt.Sprint(params["original"]))
	entries, err := os.ReadDir(qdir)
	if err != nil {
		return nil, fmt.Errorf("隔离目录不可用: %v", err)
	}
	var metaPath string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		mp := filepath.Join(qdir, e.Name())
		b, rerr := os.ReadFile(mp)
		if rerr != nil {
			continue
		}
		var meta map[string]any
		if json.Unmarshal(b, &meta) != nil {
			continue
		}
		orig := fmt.Sprint(meta["original"])
		dest := fmt.Sprint(meta["dest"])
		if destHint != "" && !strings.EqualFold(dest, destHint) && !strings.EqualFold(filepath.Base(dest), filepath.Base(destHint)) {
			continue
		}
		if origHint != "" && !strings.EqualFold(orig, origHint) {
			continue
		}
		metaPath = mp
		if destHint == "" && origHint == "" {
			// 无指定则取最新一条
		}
		// 使用匹配到的
		if _, err := os.Stat(dest); err != nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(orig), 0755); err != nil {
			return nil, err
		}
		if err := os.Rename(dest, orig); err != nil {
			b2, r2 := os.ReadFile(dest)
			if r2 != nil {
				return nil, fmt.Errorf("回滚失败: %v / %v", err, r2)
			}
			if w2 := os.WriteFile(orig, b2, 0644); w2 != nil {
				return nil, w2
			}
			_ = os.Remove(dest)
		}
		_ = os.Remove(metaPath)
		return map[string]any{"ok": true, "restored": orig, "from": dest}, nil
	}
	return nil, fmt.Errorf("未找到可回滚的隔离文件")
}

func rollbackUpgrade(cfg Config, params map[string]any) (map[string]any, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	self, _ = filepath.Abs(self)
	bak := self + ".bak"
	if _, err := os.Stat(bak); err != nil {
		return nil, fmt.Errorf("无备份可回滚: %s", bak)
	}
	tmp := self + ".rolling"
	_ = os.Remove(tmp)
	if err := os.Rename(self, tmp); err != nil {
		// 占用则旁路
		side := filepath.Join(filepath.Dir(self), "forensic-agent.rollback.exe")
		if err2 := copyFile(bak, side); err2 != nil {
			return nil, fmt.Errorf("回滚失败: %v / %v", err, err2)
		}
		script := filepath.Join(cfg.StateDir, "upgrade", "rollback.bat")
		_ = os.MkdirAll(filepath.Dir(script), 0700)
		bat := fmt.Sprintf("@echo off\r\ntimeout /t 2 /nobreak >nul\r\nmove /y \"%s\" \"%s\"\r\nnet start %s\r\n", side, self, serviceName)
		_ = os.WriteFile(script, []byte(bat), 0700)
		_, _ = runCmd(5*time.Second, "cmd", "/c", "start", "", script)
		return map[string]any{"ok": true, "mode": "deferred", "from": bak}, nil
	}
	if err := copyFile(bak, self); err != nil {
		_ = os.Rename(tmp, self)
		return nil, err
	}
	_ = os.Remove(tmp)
	script := filepath.Join(cfg.StateDir, "upgrade", "rollback_restart.bat")
	_ = os.MkdirAll(filepath.Dir(script), 0700)
	bat := fmt.Sprintf("@echo off\r\ntimeout /t 2 /nobreak >nul\r\nnet stop %s\r\nnet start %s\r\n", serviceName, serviceName)
	_ = os.WriteFile(script, []byte(bat), 0700)
	_, _ = runCmd(5*time.Second, "cmd", "/c", "start", "", script)
	return map[string]any{"ok": true, "mode": "replaced", "from": bak}, nil
}

func killProcess(params map[string]any) (map[string]any, error) {
	pid := 0
	switch v := params["pid"].(type) {
	case float64:
		pid = int(v)
	case int:
		pid = v
	case string:
		pid, _ = strconv.Atoi(strings.TrimSpace(v))
	}
	if pid <= 0 {
		return nil, fmt.Errorf("缺少有效 pid")
	}
	if refuseKillSelf(pid) {
		return nil, fmt.Errorf("拒绝结束自身进程")
	}
	// 管理端带了 process_guid 时必须与现存进程一致，防止 PID 复用误杀
	if g, ok := params["process_guid"].(string); ok && strings.TrimSpace(g) != "" {
		if err := verifyProcessIdentity(pid, g); err != nil {
			return map[string]any{"pid": pid, "process_guid": g, "refused": true}, err
		}
	}
	if isSelfProtect() && pid == os.Getpid() {
		return nil, fmt.Errorf("自保护：禁止结束 Agent")
	}
	out, err := runCmd(20*time.Second, "taskkill", "/F", "/PID", strconv.Itoa(pid))
	if err != nil {
		return map[string]any{"pid": pid, "output": out}, fmt.Errorf("taskkill: %v %s", err, out)
	}
	return map[string]any{"pid": pid, "output": out, "killed": true}, nil
}

func quarantineFile(cfg Config, params map[string]any) (map[string]any, error) {
	path := strings.TrimSpace(fmt.Sprint(params["path"]))
	path = strings.Trim(path, `"'`)
	if path == "" || !strings.Contains(path, `\`) {
		return nil, fmt.Errorf("缺少有效 path")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("文件不存在: %v", err)
	}
	// 管理端给了期望的文件 ID / SHA256 时必须一致，防止同路径文件已被替换
	curID := fileIdentity(path)
	if want, ok := params["file_id"].(string); ok && strings.TrimSpace(want) != "" && curID != "" &&
		!strings.EqualFold(strings.TrimSpace(want), curID) {
		return map[string]any{"path": path, "refused": true, "file_id": curID},
			fmt.Errorf("文件 ID 不一致（期望 %s，实际 %s），文件可能已被替换", want, curID)
	}
	curHash := ""
	if fi, e := os.Stat(path); e == nil && fi.Size() <= 256<<20 {
		curHash = fileSHA256(path)
	}
	if want, ok := params["sha256"].(string); ok && strings.TrimSpace(want) != "" && curHash != "" &&
		!strings.EqualFold(strings.TrimSpace(want), curHash) {
		return map[string]any{"path": path, "refused": true, "sha256": curHash},
			fmt.Errorf("SHA256 不一致（期望 %s…，实际 %s…），文件可能已被替换", truncate(want, 12), truncate(curHash, 12))
	}
	qdir := filepath.Join(cfg.StateDir, "quarantine")
	if err := os.MkdirAll(qdir, 0700); err != nil {
		return nil, err
	}
	base := filepath.Base(path)
	dest := filepath.Join(qdir, fmt.Sprintf("%d_%s", time.Now().Unix(), base))
	meta := map[string]any{
		"original": path,
		"moved_at": time.Now().Format("2006-01-02T15:04:05"),
		"dest":     dest,
		"file_id":  curID,
		"sha256":   curHash,
	}
	if err := os.Rename(path, dest); err != nil {
		// 跨盘失败则复制+删
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, fmt.Errorf("隔离失败: %v / %v", err, rerr)
		}
		if werr := os.WriteFile(dest, b, 0600); werr != nil {
			return nil, werr
		}
		_ = os.Remove(path)
	}
	mb, _ := json.MarshalIndent(meta, "", "  ")
	_ = os.WriteFile(dest+".json", mb, 0600)
	return meta, nil
}

func isolateNetwork(cfg Config, enable bool) (map[string]any, error) {
	rule := "ForensicAgent_EDR_Isolate"
	if !enable {
		out, err := runCmd(30*time.Second, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+rule)
		return map[string]any{"isolated": false, "output": out}, err
	}
	// 先删旧规则再加：阻断所有出站，但放行到管理端主机的流量尽量保留（按 IP）
	_, _ = runCmd(15*time.Second, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+rule)
	serverHost := hostFromURL(cfg.ServerURL)
	args := []string{
		"advfirewall", "firewall", "add", "rule",
		"name=" + rule,
		"dir=out", "action=block", "enable=yes", "profile=any",
	}
	out, err := runCmd(30*time.Second, "netsh", args...)
	if err != nil {
		return map[string]any{"isolated": false, "output": out}, err
	}
	// 放行 DNS / DHCP / 管理端 IP（若可解析）
	allowRules := [][]string{
		{"advfirewall", "firewall", "add", "rule", "name=" + rule + "_DNS", "dir=out", "action=allow", "protocol=UDP", "remoteport=53", "enable=yes"},
		{"advfirewall", "firewall", "add", "rule", "name=" + rule + "_DHCP", "dir=out", "action=allow", "protocol=UDP", "remoteport=67,68", "enable=yes"},
	}
	if serverHost != "" && serverHost != "127.0.0.1" && serverHost != "localhost" {
		allowRules = append(allowRules, []string{
			"advfirewall", "firewall", "add", "rule", "name=" + rule + "_MGMT",
			"dir=out", "action=allow", "remoteip=" + serverHost, "enable=yes",
		})
	}
	extras := []string{}
	for _, a := range allowRules {
		o, e := runCmd(20*time.Second, "netsh", a...)
		extras = append(extras, o)
		if e != nil {
			extras = append(extras, e.Error())
		}
	}
	return map[string]any{"isolated": true, "output": out, "extras": extras, "mgmt": serverHost}, nil
}

func hostFromURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if i := strings.IndexAny(u, "/:"); i >= 0 {
		u = u[:i]
	}
	return u
}
