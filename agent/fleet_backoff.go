package main

import (
	"math/rand"
	"sync"
	"time"
)

// 对齐 Fleet Gateway：心跳失败指数退避 + jitter。
var hbBackoff struct {
	mu   sync.Mutex
	fail int
}

func heartbeatBackoffDelay() time.Duration {
	hbBackoff.mu.Lock()
	defer hbBackoff.mu.Unlock()
	if hbBackoff.fail <= 0 {
		return 0
	}
	n := hbBackoff.fail
	if n > 6 {
		n = 6
	}
	base := time.Duration(1<<uint(n-1)) * time.Second
	if base > 60*time.Second {
		base = 60 * time.Second
	}
	j := time.Duration(rand.Intn(500)) * time.Millisecond
	return base + j
}

func heartbeatBackoffOK() {
	hbBackoff.mu.Lock()
	hbBackoff.fail = 0
	hbBackoff.mu.Unlock()
}

func heartbeatBackoffFail() {
	hbBackoff.mu.Lock()
	hbBackoff.fail++
	hbBackoff.mu.Unlock()
}
