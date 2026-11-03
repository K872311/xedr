//go:build windows

package main

import (
	"os"
	"testing"
	"time"
)

func TestCollectProcessesNative(t *testing.T) {
	t0 := time.Now()
	items, err := collectProcessesNative()
	if err != nil || len(items) < 5 {
		t.Fatalf("native enum: n=%d err=%v", len(items), err)
	}
	self := os.Getpid()
	found := false
	for _, it := range items {
		m := it.(map[string]any)
		if m["pid"] == self {
			found = true
			if m["path"] == "" || m["create_time"] == "" || m["command_line"] == "" {
				t.Fatalf("自身进程字段缺失: %v", m)
			}
		}
	}
	if !found {
		t.Fatal("未枚举到自身进程")
	}
	t.Logf("native: %d 个进程，耗时 %s", len(items), time.Since(t0))
	if os.Getenv("FA_BENCH") == "1" {
		t1 := time.Now()
		full, _ := collectProcesses()
		t.Logf("collectProcesses(含签名/模块富化): %d 条，耗时 %s", len(full), time.Since(t1))
	}
}
