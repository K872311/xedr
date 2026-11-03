//go:build windows

package main

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func startRootcheckLoop(ctx context.Context, box *outbox, aid func() string) {
	go func() {
		t := time.NewTicker(12 * time.Hour)
		defer t.Stop()
		runRootcheck(box, aid)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if integrationEnabled("rootcheck") {
					runRootcheck(box, aid)
				}
			}
		}
	}()
}

func runRootcheck(box *outbox, aid func() string) {
	var findings []map[string]any
	// 监听端口粗查
	if ports, err := listListeningPorts(); err == nil {
		for _, p := range ports {
			if p >= 4444 && p <= 4455 {
				findings = append(findings, map[string]any{
					"type": "suspicious_port", "port": p, "severity": "medium",
				})
			}
		}
	}
	// 可疑路径存在性
	for _, path := range []string{
		`C:\Windows\Temp\svchost.exe`,
		`C:\Users\Public\Documents\svchost.exe`,
	} {
		if fileExists(path) {
			findings = append(findings, map[string]any{
				"type": "suspicious_path", "path": path, "severity": "high",
			})
		}
	}
	if len(findings) == 0 {
		return
	}
	log.Printf("rootcheck: %d findings", len(findings))
	box.enqueue(outEvent, 60, map[string]any{
		"agent_id": aid(), "module": "rootcheck", "severity": "medium",
		"title": "Rootcheck 可疑项",
		"detail": map[string]any{"findings": findings, "count": len(findings)},
	})
}

func listListeningPorts() ([]int, error) {
	var ports []int
	seen := map[int]bool{}
	for _, proto := range []string{"tcp", "tcp4", "tcp6"} {
		_ = proto
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	_ = addrs
	// 轻量：用 net.Listen 探测常见 C2 端口占用由 listen 模块兜底；此处仅占位扩展
	for _, p := range []int{4444, 5555, 8080, 8443} {
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err == nil {
			_ = ln.Close()
		} else if strings.Contains(err.Error(), "bind") {
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	return ports, nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
