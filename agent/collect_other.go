//go:build !windows

package main

import (
	"os"
	"runtime"
	"strings"
	"time"
)

func collectSysinfo() ([]any, error) {
	return []any{map[string]any{
		"hostname":     hostname(),
		"os_family":    osFamily(),
		"goos":         runtime.GOOS,
		"goarch":       runtime.GOARCH,
		"ip":           primaryIP(),
		"agent_ver":    agentVersion,
		"collected_at": time.Now().Format("2006-01-02T15:04:05"),
		"num_cpu":      runtime.NumCPU(),
	}}, nil
}

func collectServices() ([]any, error) {
	raw, _ := runCmd(30*time.Second, "systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain")
	var out []any
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		out = append(out, map[string]any{
			"name":   fields[0],
			"status": fields[2],
		})
	}
	return truncateItems(out), nil
}

func collectTasks() ([]any, error) {
	// cron 摘要：/etc/cron* 文件名列表，轻量即可
	var out []any
	for _, p := range []string{"/etc/crontab", "/etc/cron.d"} {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			ents, _ := os.ReadDir(p)
			for _, e := range ents {
				out = append(out, map[string]any{"task_name": p + "/" + e.Name(), "status": "file"})
			}
		} else {
			out = append(out, map[string]any{"task_name": p, "status": "file"})
		}
	}
	return truncateItems(out), nil
}

func collectStartup() ([]any, error) {
	var out []any
	for _, p := range []string{"/etc/rc.local", "/etc/init.d", "/etc/systemd/system"} {
		if _, err := os.Stat(p); err == nil {
			out = append(out, map[string]any{"location": "fs", "name": p, "command": p})
		}
	}
	return truncateItems(out), nil
}

func collectNetwork() ([]any, error) {
	raw, err := runCmd(20*time.Second, "ss", "-tanp")
	if err != nil || raw == "" {
		raw, _ = runCmd(20*time.Second, "netstat", "-tanp")
	}
	var out []any
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.HasPrefix(fields[0], "State") || strings.HasPrefix(fields[0], "Proto") {
			continue
		}
		item := map[string]any{"raw": strings.Join(fields, " ")}
		if len(fields) >= 5 {
			item["proto"] = fields[0]
			item["local"] = fields[3]
			item["remote"] = fields[4]
		}
		out = append(out, item)
	}
	return truncateItems(out), nil
}

func collectProcessesLite() ([]any, error) { return collectProcesses() }
func collectFilesLite() ([]any, error)     { return collectFiles() }

func collectProcesses() ([]any, error) {
	raw, _ := runCmd(20*time.Second, "ps", "-eo", "pid,ppid,user,comm,args", "--no-headers")
	var out []any
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		cmd := ""
		if len(fields) > 4 {
			cmd = strings.Join(fields[4:], " ")
		}
		out = append(out, map[string]any{
			"pid":          asInt(fields[0]),
			"ppid":         asInt(fields[1]),
			"user":         fields[2],
			"name":         fields[3],
			"command_line": cmd,
		})
	}
	return truncateItems(out), nil
}

func collectFiles() ([]any, error) {
	raw, _ := runCmd(40*time.Second, "bash", "-lc",
		`find /tmp /var/tmp /dev/shm -maxdepth 3 -type f \( -name '*.sh' -o -name '*.elf' -o -name '*.bin' -o -perm -111 \) 2>/dev/null | head -n 200`)
	var out []any
	for _, p := range strings.Split(raw, "\n") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, map[string]any{
			"name": filepathBase(p),
			"path": p,
		})
	}
	return truncateItems(out), nil
}

func collectUsers() ([]any, error) {
	raw, _ := runCmd(10*time.Second, "who")
	var out []any
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		out = append(out, map[string]any{
			"name":   fields[0],
			"source": "session",
			"state":  strings.Join(fields[1:], " "),
		})
	}
	return truncateItems(out), nil
}

func collectDrivers() ([]any, error) { return []any{}, nil }
func collectBrowser() ([]any, error) { return []any{}, nil }

func filepathBase(p string) string {
	i := strings.LastIndexAny(p, `/\`)
	if i < 0 {
		return p
	}
	return p[i+1:]
}
