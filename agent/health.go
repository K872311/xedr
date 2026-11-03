package main

import (
	"os"
	"runtime"
	"sync"
	"time"
)

// healthCollector 采集 Agent 自身资源/队列/传感器状态，随心跳上报，
// 让管理台能区分"Agent 活着但已经卡死/丢数据"与"一切正常"。
type healthCollector struct {
	mu        sync.Mutex
	started   time.Time
	lastCPU   uint64 // 100ns 单位的进程 CPU 时间
	lastWall  time.Time
	cpuPct    float64
	sensorsFn func() map[string]any
	authMode  func() string
	protoFn   func() int
}

func newHealthCollector() *healthCollector {
	h := &healthCollector{started: time.Now()}
	cpu, _, _ := processUsage()
	h.lastCPU, h.lastWall = cpu, time.Now()
	return h
}

func (h *healthCollector) snapshot(box *outbox) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()

	cpu, rss, handles := processUsage()
	now := time.Now()
	if dt := now.Sub(h.lastWall).Seconds(); dt >= 1 && cpu >= h.lastCPU {
		used := float64(cpu-h.lastCPU) / 1e7 // 秒
		h.cpuPct = round1(used / dt / float64(runtime.NumCPU()) * 100)
		h.lastCPU, h.lastWall = cpu, now
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	out := map[string]any{
		"cpu_pct":    h.cpuPct,
		"rss_mb":     round1(float64(rss) / (1 << 20)),
		"heap_mb":    round1(float64(ms.HeapAlloc) / (1 << 20)),
		"goroutines": runtime.NumGoroutine(),
		"handles":    handles,
		"uptime_sec": int(now.Sub(h.started).Seconds()),
		"pid":        os.Getpid(),
		"version":    agentVersion,
		"build_id":   buildID,
		"num_cpu":    runtime.NumCPU(),
	}
	if box != nil {
		out["outbox"] = box.stats()
	}
	if h.sensorsFn != nil {
		out["sensors"] = h.sensorsFn()
	}
	if h.authMode != nil {
		out["auth"] = h.authMode()
	}
	if h.protoFn != nil {
		out["protocol"] = h.protoFn()
	}
	return out
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
