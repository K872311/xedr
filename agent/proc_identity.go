package main

import (
	"fmt"
	"strings"
)

// processGUID 稳定进程身份：pid + 创建时间（防 PID 复用错链）。
func processGUID(pid int, createTime string) string {
	if pid <= 0 {
		return ""
	}
	ct := strings.TrimSpace(createTime)
	if ct == "" {
		return fmt.Sprintf("%d", pid)
	}
	return fmt.Sprintf("%d_%s", pid, ct)
}

func asProcessGUID(m map[string]any) string {
	if g := asString(m["process_guid"]); g != "" {
		return g
	}
	return processGUID(asInt(m["pid"]), asString(m["create_time"]))
}

// attachIdentityToDetail 给时间线/ETW detail 写入稳定身份字段。
func attachIdentityToDetail(detail map[string]any, createTime string) {
	if detail == nil {
		return
	}
	pid := asInt(detail["pid"])
	ct := asString(detail["create_time"])
	if ct == "" {
		ct = strings.TrimSpace(createTime)
		if ct != "" {
			detail["create_time"] = ct
		}
	}
	if asString(detail["process_guid"]) == "" && pid > 0 {
		detail["process_guid"] = processGUID(pid, ct)
	}
	ppid := asInt(detail["ppid"])
	if ppid > 0 && asString(detail["parent_guid"]) == "" {
		pct := asString(detail["parent_create_time"])
		detail["parent_guid"] = processGUID(ppid, pct)
	}
}
