//go:build windows

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/windows/registry"
)

var (
	remoteOpsEnabled      = true
	remoteOpsReadOnly     = false
	remoteRunCmdEnabled   = true
	remoteShellEnabled    = true
	remoteShellMaxMinutes = 15
	remoteRunCmdWhitelist = []string{
		"dir", "type", "reg", "ipconfig", "netstat", "tasklist", "systeminfo",
		"whoami", "hostname", "net", "sc", "cd", "echo", "where", "findstr",
		"wmic", "driverquery", "tree", "vol",
		"powershell -noprofile -command", "powershell -nop -command",
	}
)

func applyRemoteOpsPolicy(pol map[string]any) {
	if v, ok := pol["remote_ops_enabled"].(bool); ok {
		remoteOpsEnabled = v
	}
	if ro, ok := pol["remote_ops"].(map[string]any); ok {
		if v, ok := ro["enabled"].(bool); ok {
			remoteOpsEnabled = v
		}
		if v, ok := ro["read_only"].(bool); ok {
			remoteOpsReadOnly = v
		}
		if v, ok := ro["run_cmd_enabled"].(bool); ok {
			remoteRunCmdEnabled = v
		}
		if v, ok := ro["shell_enabled"].(bool); ok {
			remoteShellEnabled = v
		}
		if v, ok := ro["shell_max_minutes"].(float64); ok && v > 0 {
			remoteShellMaxMinutes = int(v)
		}
		if arr, ok := ro["run_cmd_whitelist"].([]any); ok && len(arr) > 0 {
			var wl []string
			for _, x := range arr {
				if s := strings.TrimSpace(asString(x)); s != "" {
					wl = append(wl, strings.ToLower(s))
				}
			}
			if len(wl) > 0 {
				remoteRunCmdWhitelist = wl
			}
		}
	}
}

func remoteOpsGate(action string) error {
	if !remoteOpsEnabled {
		return fmt.Errorf("remote_ops disabled by policy")
	}
	switch strings.ToLower(action) {
	case "reg_read", "fs_list", "fs_stat", "fs_read", "fs_volumes", "live_query":
		return nil
	case "run_cmd":
		if remoteOpsReadOnly || !remoteRunCmdEnabled {
			return fmt.Errorf("run_cmd disabled by policy")
		}
	case "shell_open", "shell_write", "shell_poll", "shell_close":
		if !remoteShellEnabled {
			return fmt.Errorf("interactive shell disabled by policy")
		}
	}
	return nil
}

func sanitizeAbsPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("path traversal denied")
	}
	p = filepath.Clean(p)
	if len(p) == 2 && p[1] == ':' {
		p += `\`
	}
	if len(p) < 3 || p[1] != ':' {
		return "", fmt.Errorf("need absolute path like C:\\")
	}
	return p, nil
}

func hiveKey(hive string) (registry.Key, error) {
	switch strings.ToUpper(strings.TrimSpace(hive)) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, nil
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, nil
	case "HKU", "HKEY_USERS":
		return registry.USERS, nil
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, nil
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return registry.CURRENT_CONFIG, nil
	default:
		return 0, fmt.Errorf("unsupported hive: %s", hive)
	}
}

func regRead(params map[string]any) (map[string]any, error) {
	if err := remoteOpsGate("reg_read"); err != nil {
		return nil, err
	}
	hive := asString(params["hive"])
	keyPath := strings.TrimSpace(asString(params["key"]))
	if keyPath == "" {
		return nil, fmt.Errorf("missing key")
	}
	valueName := asString(params["value"])
	root, err := hiveKey(hive)
	if err != nil {
		return nil, err
	}
	k, err := registry.OpenKey(root, keyPath, registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	if valueName != "" {
		val, valType, err := k.GetStringValue(valueName)
		if err != nil {
			b, _, err2 := k.GetBinaryValue(valueName)
			if err2 != nil {
				return nil, err
			}
			return map[string]any{
				"hive": hive, "key": keyPath, "value_name": valueName,
				"type": "binary", "data_hex": hex.EncodeToString(b)[:minInt(4096, len(b)*2)],
				"size": len(b),
			}, nil
		}
		return map[string]any{
			"hive": hive, "key": keyPath, "value_name": valueName,
			"type": fmt.Sprintf("%d", valType), "data": val,
		}, nil
	}
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}
	max := 120
	if m := asInt(params["max_values"]); m > 0 && m < max {
		max = m
	}
	items := make([]map[string]any, 0, minInt(len(names), max))
	for i, vn := range names {
		if i >= max {
			break
		}
		s, _, err := k.GetStringValue(vn)
		if err != nil {
			items = append(items, map[string]any{"name": vn, "type": "other"})
			continue
		}
		if len(s) > 512 {
			s = s[:512] + "…"
		}
		items = append(items, map[string]any{"name": vn, "type": "string", "data": s})
	}
	subkeys, _ := k.ReadSubKeyNames(-1)
	return map[string]any{
		"hive": hive, "key": keyPath, "values": items,
		"subkeys": subkeys[:minInt(len(subkeys), 80)], "truncated": len(names) > max,
	}, nil
}

func fsList(params map[string]any) (map[string]any, error) {
	if err := remoteOpsGate("fs_list"); err != nil {
		return nil, err
	}
	p, err := sanitizeAbsPath(asString(params["path"]))
	if err != nil {
		return nil, err
	}
	max := 200
	if m := asInt(params["max_entries"]); m > 0 && m <= 500 {
		max = m
	}
	ents, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, minInt(len(ents), max))
	for i, e := range ents {
		if i >= max {
			break
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		item := map[string]any{
			"name": e.Name(), "dir": e.IsDir(), "size": fi.Size(),
			"mtime": fi.ModTime().Format(time.RFC3339),
		}
		if e.IsDir() && (params["count_dirs"] == true || asString(params["count_dirs"]) == "1") {
			// 大目录逐子项 ReadDir 会拖垮指令通道，最多统计前 32 个子目录
			if i < 32 {
				if sub, err := os.ReadDir(filepath.Join(p, e.Name())); err == nil {
					item["child_count"] = len(sub)
				}
			}
		}
		items = append(items, item)
	}
	return map[string]any{"path": p, "entries": items, "truncated": len(ents) > max}, nil
}

func fsVolumes(params map[string]any) (map[string]any, error) {
	if err := remoteOpsGate("fs_volumes"); err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, 8)
	for _, letter := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		root := string(letter) + `:\`
		if _, err := os.Stat(root); err != nil {
			continue
		}
		ent := map[string]any{"name": root, "dir": true, "drive": string(letter), "path": root}
		if sub, err := os.ReadDir(root); err == nil {
			ent["child_count"] = len(sub)
		}
		items = append(items, ent)
	}
	return map[string]any{"entries": items, "count": len(items)}, nil
}

func fsStat(params map[string]any) (map[string]any, error) {
	if err := remoteOpsGate("fs_stat"); err != nil {
		return nil, err
	}
	p, err := sanitizeAbsPath(asString(params["path"]))
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"path": p, "size": fi.Size(), "dir": fi.IsDir(),
		"mtime": fi.ModTime().Format(time.RFC3339), "mode": fi.Mode().String(),
	}
	if !fi.IsDir() && fi.Size() > 0 && fi.Size() <= 50*1024*1024 {
		if params["sha256"] == true || asString(params["sha256"]) == "1" {
			// optional hash omitted for speed unless requested — caller uses fs_read for small files
		}
	}
	return out, nil
}

func fsRead(params map[string]any) (map[string]any, error) {
	if err := remoteOpsGate("fs_read"); err != nil {
		return nil, err
	}
	p, err := sanitizeAbsPath(asString(params["path"]))
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("is a directory")
	}
	maxLen := 262144
	if m := asInt(params["max_bytes"]); m > 0 && m <= maxLen {
		maxLen = m
	}
	off := int64(asInt(params["offset"]))
	if off < 0 {
		off = 0
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, maxLen)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	data := buf[:n]
	text := string(data)
	if !utf8.Valid(data) {
		text = ""
	}
	return map[string]any{
		"path": p, "offset": off, "read": n, "size": fi.Size(),
		"text": text, "truncated": off+int64(n) < fi.Size(),
		"base64": "", // keep JSON small; hex for binary preview
		"hex_preview": hex.EncodeToString(data[:minInt(n, 256)]),
	}, nil
}

func dangerousCommandLine(cmdline string) error {
	low := strings.ToLower(cmdline)
	bad := []string{"-enc ", "-encodedcommand", "downloadstring", "invoke-expression", " iex ", "frombase64string", "format-disk", "vssadmin delete", "bcdedit /delete", "reg delete", "reg add", "del /f", "rd /s", "rmdir /s", "format ", "diskpart"}
	for _, b := range bad {
		if strings.Contains(low, b) {
			return fmt.Errorf("command blocked by safety policy")
		}
	}
	return nil
}

// shell 只读策略下允许的 cmd 前缀（调查常用）；非只读模式仅拦截 dangerousCommandLine。
func shellLineAllowed(line string) error {
	if err := dangerousCommandLine(line); err != nil {
		return err
	}
	if !remoteOpsReadOnly {
		return nil
	}
	trim := strings.TrimSpace(line)
	low := strings.ToLower(trim)
	if low == "" {
		return nil
	}
	allowed := []string{
		"dir", "cd", "cd /d", "chdir", "type", "more", "ipconfig", "ipconfig /all",
		"netstat", "tasklist", "systeminfo", "whoami", "hostname", "where", "findstr",
		"reg query", "reg export", "wmic", "driverquery", "ping", "tracert", "path",
		"set", "echo", "help", "cls", "ver", "vol", "tree", "assoc", "ftype", "label",
		"date /t", "time /t", "powershell -noprofile -command", "powershell -nop -command",
	}
	for _, p := range allowed {
		if low == p || strings.HasPrefix(low, p+" ") || strings.HasPrefix(low, p+"\t") {
			return nil
		}
	}
	if low == "date" || low == "time" {
		return nil
	}
	return fmt.Errorf("只读远程运维：不允许「%s」（关闭策略「远程运维只读」后可执行更多命令）", trim)
}

func cmdWhitelistOK(cmdline string) bool {
	trim := strings.TrimSpace(cmdline)
	low := strings.ToLower(trim)
	for _, prefix := range remoteRunCmdWhitelist {
		if low == prefix || strings.HasPrefix(low, prefix+" ") || strings.HasPrefix(low, prefix+"\t") {
			return true
		}
	}
	return false
}

func runCmdRemote(params map[string]any) (map[string]any, error) {
	if err := remoteOpsGate("run_cmd"); err != nil {
		return nil, err
	}
	cmdline := strings.TrimSpace(asString(params["command"]))
	if cmdline == "" {
		return nil, fmt.Errorf("missing command")
	}
	if err := dangerousCommandLine(cmdline); err != nil {
		return nil, err
	}
	if !cmdWhitelistOK(cmdline) {
		return nil, fmt.Errorf("command not in whitelist (configure remote_ops.run_cmd_whitelist)")
	}
	timeout := 90 * time.Second
	if sec := asInt(params["timeout_sec"]); sec > 0 && sec <= 120 {
		timeout = time.Duration(sec) * time.Second
	}
	cwd := strings.TrimSpace(asString(params["cwd"]))
	var out string
	var err error
	if cwd != "" {
		cwd, _ = sanitizeAbsPath(cwd)
	}
	out, err = runCmd(timeout, "cmd.exe", "/C", cmdline)
	if err != nil {
		return map[string]any{"command": cmdline, "exit_error": err.Error(), "output": truncateOut(out)}, nil
	}
	return map[string]any{"command": cmdline, "ok": true, "output": truncateOut(out)}, nil
}

func truncateOut(s string) string {
	const max = 512 * 1024
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n…[truncated]"
}

// --- interactive shell sessions ---

type shellSession struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	buf        bytes.Buffer
	mu         sync.Mutex
	created    time.Time
	lastActive time.Time
}

var (
	shellMu       sync.Mutex
	shellSessions = map[string]*shellSession{}
)

func shellCleanupLoop() {
	for {
		time.Sleep(30 * time.Second)
		shellMu.Lock()
		lim := time.Duration(remoteShellMaxMinutes) * time.Minute
		for id, s := range shellSessions {
			if time.Since(s.lastActive) > lim {
				_ = s.cmd.Process.Kill()
				delete(shellSessions, id)
			}
		}
		shellMu.Unlock()
	}
}

func init() {
	go shellCleanupLoop()
}

func newShellID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func shellOpen(params map[string]any) (map[string]any, error) {
	if err := remoteOpsGate("shell_open"); err != nil {
		return nil, err
	}
	shellMu.Lock()
	defer shellMu.Unlock()
	if len(shellSessions) >= 3 {
		return nil, fmt.Errorf("max shell sessions (3) reached")
	}
	cmd := exec.Command("cmd.exe", "/Q")
	cmd.Env = os.Environ()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	id := newShellID()
	s := &shellSession{cmd: cmd, stdin: stdin, created: time.Now(), lastActive: time.Now()}
	shellSessions[id] = s
	go shellPumpOutput(s, io.MultiReader(stdout, stderr))
	_, _ = io.WriteString(stdin, "@echo off\r\nchcp 65001 >nul\r\n")
	return map[string]any{
		"session_id": id, "expires_minutes": remoteShellMaxMinutes,
	}, nil
}

func shellPumpOutput(s *shellSession, r io.Reader) {
	buf := make([]byte, 8192)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.buf.Write(buf[:n])
			s.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func shellWrite(params map[string]any) (map[string]any, error) {
	if err := remoteOpsGate("shell_write"); err != nil {
		return nil, err
	}
	id := asString(params["session_id"])
	line := asString(params["input"])
	shellMu.Lock()
	s, ok := shellSessions[id]
	shellMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	if line == "" {
		return map[string]any{"session_id": id, "written": 0}, nil
	}
	if err := shellLineAllowed(line); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
	if _, err := io.WriteString(s.stdin, line+"\r\n"); err != nil {
		return nil, err
	}
	return map[string]any{"session_id": id, "written": len(line)}, nil
}

func shellPoll(params map[string]any) (map[string]any, error) {
	if err := remoteOpsGate("shell_poll"); err != nil {
		return nil, err
	}
	id := asString(params["session_id"])
	shellMu.Lock()
	s, ok := shellSessions[id]
	shellMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	s.mu.Lock()
	raw := append([]byte(nil), s.buf.Bytes()...)
	s.buf.Reset()
	s.lastActive = time.Now()
	s.mu.Unlock()
	out := decodeConsoleBytes(raw)
	return map[string]any{"session_id": id, "output": truncateOut(out)}, nil
}

func shellClose(params map[string]any) (map[string]any, error) {
	if err := remoteOpsGate("shell_close"); err != nil {
		return nil, err
	}
	id := asString(params["session_id"])
	shellMu.Lock()
	s, ok := shellSessions[id]
	if ok {
		delete(shellSessions, id)
	}
	shellMu.Unlock()
	if !ok {
	 return map[string]any{"session_id": id, "closed": false}, nil
	}
	_ = s.stdin.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	return map[string]any{"session_id": id, "closed": true}, nil
}

func remoteOpsExec(params map[string]any, action string) (map[string]any, error) {
	switch strings.ToLower(action) {
	case "reg_read":
		return regRead(params)
	case "fs_list":
		return fsList(params)
	case "fs_stat":
		return fsStat(params)
	case "fs_read":
		return fsRead(params)
	case "fs_volumes":
		return fsVolumes(params)
	case "run_cmd":
		return runCmdRemote(params)
	case "shell_open":
		return shellOpen(params)
	case "shell_write":
		return shellWrite(params)
	case "shell_poll":
		return shellPoll(params)
	case "shell_close":
		return shellClose(params)
	default:
		return nil, fmt.Errorf("unknown remote op")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
