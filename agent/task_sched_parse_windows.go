//go:build windows

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	reTaskExecBlock = regexp.MustCompile(`(?is)<Exec\b[^>]*>(.*?)</Exec>`)
	reTaskCommand   = regexp.MustCompile(`(?is)<Command>([^<]*)</Command>`)
	reTaskArguments = regexp.MustCompile(`(?is)<Arguments>([^<]*)</Arguments>`)
	reTaskWorkDir   = regexp.MustCompile(`(?is)<WorkingDirectory>([^<]*)</WorkingDirectory>`)
	reTaskAuthor    = regexp.MustCompile(`(?is)<Author>([^<]*)</Author>`)
)

func parseScheduledTaskFile(path string) scheduledTaskParsed {
	var last scheduledTaskParsed
	for i := 0; i < 3; i++ {
		b, err := os.ReadFile(path)
		if err != nil {
			time.Sleep(80 * time.Millisecond)
			continue
		}
		p := parseTaskXMLContent(string(b))
		p.From = "file"
		return p
	}
	if c, ok := lookupTaskDefinition(taskKeyFromDefPath(path)); ok {
		last = c
		last.From = "cache"
	}
	return last
}

func parseTaskXMLContent(xml string) scheduledTaskParsed {
	xml = strings.TrimSpace(xml)
	if xml == "" {
		return scheduledTaskParsed{}
	}
	var actions []taskAction
	for _, block := range reTaskExecBlock.FindAllStringSubmatch(xml, -1) {
		if len(block) < 2 {
			continue
		}
		a := parseTaskActionTags(block[1])
		if a.Command != "" || a.Arguments != "" || a.WorkingDirectory != "" {
			actions = append(actions, a)
		}
	}
	if len(actions) == 0 {
		a := parseTaskActionTags(xml)
		if a.Command != "" || a.Arguments != "" {
			actions = append(actions, a)
		}
	}
	author := ""
	if m := reTaskAuthor.FindStringSubmatch(xml); len(m) > 1 {
		author = strings.TrimSpace(decodeTaskXMLText(m[1]))
	}
	return scheduledTaskParsed{Actions: actions, Author: author, From: "xml"}
}

func parseTaskActionTags(fragment string) taskAction {
	a := taskAction{}
	if m := reTaskCommand.FindStringSubmatch(fragment); len(m) > 1 {
		a.Command = strings.TrimSpace(decodeTaskXMLText(m[1]))
	}
	if m := reTaskArguments.FindStringSubmatch(fragment); len(m) > 1 {
		a.Arguments = strings.TrimSpace(decodeTaskXMLText(m[1]))
	}
	if m := reTaskWorkDir.FindStringSubmatch(fragment); len(m) > 1 {
		a.WorkingDirectory = strings.TrimSpace(decodeTaskXMLText(m[1]))
	}
	return a
}

func decodeTaskXMLText(s string) string {
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&quot;", `"`)
	return s
}

func enrichFIMScheduledTaskEvent(ev map[string]any, taskFilePath string) {
	if !isScheduledTaskDefPath(taskFilePath) {
		return
	}
	p := parseScheduledTaskFile(taskFilePath)
	if len(p.Actions) > 0 {
		cacheTaskDefinition(taskKeyFromDefPath(taskFilePath), p)
	}
	enrichScheduledTaskEvent(ev, taskFilePath, p)
	// 进程展示：优先载荷 exe，避免进程名显示为任务文件名
	if d, ok := ev["detail"].(map[string]any); ok {
		if exe := asString(d["task_execute"]); exe != "" {
			d["process_name"] = filepath.Base(exe)
			d["name"] = filepath.Base(exe)
		}
	}
}
