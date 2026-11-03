package main

import (
	"strings"
	"sync"
	"time"
)

// dllGate 压制 DLL 加载遥测的重复量：
//   - 未签名 / 签名无效 / 投放区 DLL：每个进程实例各报一次（必出，不受总量上限压制）；
//   - 已签名的其他非系统 DLL：同一"进程名 + DLL 路径" 30 分钟内只报一次，且每个进程实例最多 dllPerEntityMax 条。
//
// 同一应用每次启动都会加载同一批已签名私有 DLL，不去重时一台开发机一分钟就能刷出上千条。
const (
	dllDedupTTL     = 30 * time.Minute
	dllPerEntityMax = 30
)

type dllGate struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	perEnt map[string]int
}

func newDLLGate() *dllGate {
	return &dllGate{seen: map[string]time.Time{}, perEnt: map[string]int{}}
}

func (g *dllGate) allow(proc, dll, entity string, dropZone, unsigned bool, now time.Time) bool {
	dll = strings.ToLower(dll)
	g.mu.Lock()
	defer g.mu.Unlock()
	// 未签名/投放区：只做「同实例同路径」去重，必须能报到管理台
	if dropZone || unsigned {
		k := "z|" + entity + "|" + dll
		if entity == "" {
			k = "z|" + strings.ToLower(proc) + "|" + dll
		}
		if t, ok := g.seen[k]; ok && now.Sub(t) < dllDedupTTL {
			return false
		}
		g.seen[k] = now
		return true
	}
	k := strings.ToLower(proc) + "|" + dll
	if t, ok := g.seen[k]; ok && now.Sub(t) < dllDedupTTL {
		return false
	}
	if entity != "" {
		if g.perEnt[entity] >= dllPerEntityMax {
			return false
		}
		g.perEnt[entity]++
	}
	g.seen[k] = now
	return true
}

func (g *dllGate) gc(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, t := range g.seen {
		if now.Sub(t) > dllDedupTTL {
			delete(g.seen, k)
		}
	}
	if len(g.perEnt) > 20000 {
		g.perEnt = map[string]int{}
	}
}
