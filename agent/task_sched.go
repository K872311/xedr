package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type taskAction struct {
	Command          string
	Arguments        string
	WorkingDirectory string
}

type scheduledTaskParsed struct {
	Actions  []taskAction
	Author   string
	Triggers string
	From     string // file | winlog | cache
}

var (
	taskDefCacheMu sync.Mutex
	taskDefCache   = map[string]scheduledTaskParsed{} // key: lower task base name
)

func cacheTaskDefinition(taskKey string, p scheduledTaskParsed) {
	taskKey = strings.ToLower(strings.TrimSpace(taskKey))
	if taskKey == "" {
		return
	}
	taskDefCacheMu.Lock()
	taskDefCache[taskKey] = p
	if len(taskDefCache) > 512 {
		taskDefCache = map[string]scheduledTaskParsed{}
	}
	taskDefCacheMu.Unlock()
}

func lookupTaskDefinition(taskKey string) (scheduledTaskParsed, bool) {
	taskKey = strings.ToLower(strings.TrimSpace(taskKey))
	taskDefCacheMu.Lock()
	p, ok := taskDefCache[taskKey]
	taskDefCacheMu.Unlock()
	return p, ok
}

func isScheduledTaskDefPath(path string) bool {
	l := strings.ToLower(path)
	return strings.Contains(l, `\system32\tasks\`) && !strings.Contains(l, `\system32\tasks\microsoft\`)
}

func taskKeyFromDefPath(path string) string {
	return strings.ToLower(filepath.Base(path))
}

func firstTaskExecute(p scheduledTaskParsed) string {
	for _, a := range p.Actions {
		c := strings.TrimSpace(a.Command)
		if c != "" {
			return c
		}
	}
	return ""
}

func taskCommandLine(a taskAction) string {
	parts := []string{strings.TrimSpace(a.Command), strings.TrimSpace(a.Arguments)}
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

func taskSuspiciousExecute(exePath string) bool {
	l := strings.ToLower(filepath.Clean(exePath))
	if l == "" {
		return false
	}
	if strings.Contains(l, `\users\public\`) || strings.Contains(l, `\programdata\`) {
		return true
	}
	if strings.Contains(l, `\appdata\`) || strings.Contains(l, `\temp\`) || strings.Contains(l, `\tmp\`) {
		return true
	}
	if strings.Contains(l, `\downloads\`) || strings.Contains(l, `\desktop\`) {
		return true
	}
	return false
}

func applyScheduledTaskFields(detail map[string]any, taskFilePath string, p scheduledTaskParsed, taskBaseName string) {
	if detail == nil {
		return
	}
	detail["task_def_path"] = taskFilePath
	detail["task_name"] = taskBaseName
	if p.Author != "" {
		detail["task_author"] = p.Author
	}
	if p.Triggers != "" {
		detail["task_triggers"] = p.Triggers
	}
	if p.From != "" {
		detail["task_parse_source"] = p.From
	}
	if len(p.Actions) == 0 {
		detail["task_parse_pending"] = true
		return
	}
	detail["task_parse_pending"] = false
	var actions []map[string]any
	for _, a := range p.Actions {
		actions = append(actions, map[string]any{
			"command": a.Command, "arguments": a.Arguments, "working_directory": a.WorkingDirectory,
			"command_line": taskCommandLine(a),
		})
	}
	detail["task_actions"] = actions
	a0 := p.Actions[0]
	exe := strings.TrimSpace(a0.Command)
	detail["task_execute"] = exe
	detail["task_arguments"] = strings.TrimSpace(a0.Arguments)
	detail["task_workdir"] = strings.TrimSpace(a0.WorkingDirectory)
	cl := taskCommandLine(a0)
	detail["task_command_line"] = cl
	if exe != "" {
		detail["payload_path"] = exe
		detail["image"] = exe
		detail["matched"] = exe
		if cl != "" {
			detail["command_line"] = cl
		}
	}
}

func enrichScheduledTaskEvent(ev map[string]any, taskFilePath string, p scheduledTaskParsed) {
	if ev == nil {
		return
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		d = map[string]any{}
		ev["detail"] = d
	}
	base := filepath.Base(taskFilePath)
	applyScheduledTaskFields(d, taskFilePath, p, base)
	exe := firstTaskExecute(p)
	act := fimActionNames[strings.ToLower(asString(ev["etype"]))]
	if act == "" {
		act = "变更"
	}
	if exe != "" {
		exeName := filepath.Base(exe)
		ev["summary"] = "FIM" + act + ": " + exeName + " [计划任务] · 任务 " + base
		if wd := asString(d["task_workdir"]); wd != "" {
			d["summary_hint"] = exe + " @ " + wd
		}
		if taskSuspiciousExecute(exe) {
			if sev, _ := ev["severity"].(string); sev == "" || sev == "medium" {
				ev["severity"] = "high"
			}
		}
	} else if d["task_parse_pending"] == true {
		ev["severity"] = "info"
		ev["summary"] = "FIM" + act + ": " + base + " [计划任务] · 未解析载荷"
	}
}

func enrichWinTaskEvent(ev map[string]any, taskName, xmlContent string) {
	if ev == nil {
		return
	}
	key := taskKeyFromTaskName(taskName)
	if key == "" {
		key = strings.ToLower(strings.TrimSpace(taskName))
	}
	p := parseTaskXMLContent(xmlContent)
	if len(p.Actions) == 0 && xmlContent == "" {
		if c, ok := lookupTaskDefinition(key); ok {
			p = c
		}
	} else {
		p.From = "winlog"
		cacheTaskDefinition(key, p)
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		d = map[string]any{}
		ev["detail"] = d
	}
	defPath := scheduledTaskFilePath(taskName)
	applyScheduledTaskFields(d, defPath, p, filepath.Base(defPath))
	exe := firstTaskExecute(p)
	if exe != "" {
		ev["summary"] = "计划任务创建: " + filepath.Base(exe) + " · 任务 " + strings.TrimSpace(taskName)
		if taskSuspiciousExecute(exe) {
			ev["severity"] = "high"
		}
	}
}

func taskKeyFromTaskName(taskName string) string {
	t := strings.TrimSpace(taskName)
	t = strings.Trim(t, `\`)
	if t == "" {
		return ""
	}
	return strings.ToLower(filepath.Base(t))
}

func scheduledTaskFilePath(taskName string) string {
	sys := strings.TrimSpace(osGetenvSystemRoot())
	if sys == "" {
		sys = `C:\Windows`
	}
	name := strings.Trim(strings.TrimSpace(taskName), `\`)
	if name == "" {
		return ""
	}
	if strings.Contains(name, `\`) {
		return filepath.Join(sys, "System32", "Tasks", name)
	}
	return filepath.Join(sys, "System32", "Tasks", name)
}

func osGetenvSystemRoot() string {
	return os.Getenv("SystemRoot")
}
