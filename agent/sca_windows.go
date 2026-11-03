//go:build windows

package main

import (
	"context"
	"log"
	"time"
)

func startSCALoop(ctx context.Context, box *outbox, aid func() string) {
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		runSCA(box, aid)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if integrationEnabled("sca") {
					runSCA(box, aid)
				}
			}
		}
	}()
}

func runSCA(box *outbox, aid func() string) {
	checks := []map[string]any{
		scaCheckFirewall(),
		scaCheckDefenderService(),
		scaCheckGuestAccount(),
	}
	var failed []map[string]any
	for _, c := range checks {
		if c["status"] == "fail" {
			failed = append(failed, c)
		}
	}
	failed = append(failed, runBundledSCA()...)
	if len(failed) == 0 {
		return
	}
	log.Printf("sca: %d failed checks", len(failed))
	box.enqueue(outEvent, 50, map[string]any{
		"agent_id": aid(), "module": "sca", "severity": "medium",
		"title": "SCA 合规检查未通过",
		"detail": map[string]any{"failed": failed, "count": len(failed)},
	})
}

func scaCheckFirewall() map[string]any {
	out, err := runCmd(8*time.Second, "netsh", "advfirewall", "show", "allprofiles", "state")
	ok := err == nil && (containsFold(out, "ON") || containsFold(out, "启用"))
	st := "pass"
	if !ok {
		st = "fail"
	}
	return map[string]any{"id": "sca.firewall", "title": "防火墙开启", "status": st}
}

func scaCheckDefenderService() map[string]any {
	out, err := runCmd(8*time.Second, "sc", "query", "WinDefend")
	ok := err == nil && containsFold(out, "RUNNING")
	st := "pass"
	if !ok {
		st = "fail"
	}
	return map[string]any{"id": "sca.defender", "title": "Defender 服务运行", "status": st}
}

func scaCheckGuestAccount() map[string]any {
	out, err := runCmd(8*time.Second, "net", "user", "guest")
	disabled := err == nil && (containsFold(out, "disabled") || containsFold(out, "已禁用"))
	st := "pass"
	if !disabled {
		st = "fail"
	}
	return map[string]any{"id": "sca.guest", "title": "Guest 账户禁用", "status": st}
}

func containsFold(s, sub string) bool {
	return len(sub) > 0 && (len(s) >= len(sub)) && (stringIndexFold(s, sub) >= 0)
}

func stringIndexFold(s, sub string) int {
	// 简化：小写子串
	ls, lsub := toLowerASCII(s), toLowerASCII(sub)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return i
		}
	}
	return -1
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
