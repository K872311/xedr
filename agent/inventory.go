package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 增量资产清单：每个模块维护 (key -> 内容哈希) 与代号 generation。
// 有变化时只发 upserts/removes（带 base_generation），服务端代号不匹配则拒绝，
// Agent 收到拒绝后下一轮改发全量；另外定期（条数/时长）强制全量兜底。
// 内存/句柄/运行时长等易变字段不参与哈希，否则每轮所有条目都会"变化"。

const (
	invFullEvery      = 60               // 连续增量次数上限
	invFullMaxAge     = time.Hour        // 全量最长间隔
	invTouchEvery     = 10 * time.Minute // 无变化时的保活间隔（刷新服务端采集时间）
	invDeltaMaxRatio2 = 2                // 变化条数 *2 > 总数 时直接发全量
)

var invVolatile = map[string]bool{
	"memory_mb": true, "handles": true, "uptime": true, "uptime_sec": true, "collected_at": true,
	"cpu": true, "cpu_pct": true, "working_set": true, "threads": true, "last_run": true, "next_run": true,
}

var invKeyFields = map[string][]string{
	"process":  {"process_guid"},
	"network":  {"proto", "local", "remote", "pid"},
	"listen":   {"proto", "local", "pid"},
	"service":  {"name"},
	"driver":   {"name"},
	"task":     {"task_name"},
	"startup":  {"location", "name", "command"},
	"file":     {"path"},
	"user":     {"name"},
	"software": {"name", "version", "arch"},
	"hotfix":   {"kb"},
	"sysinfo":  {"hostname"},
}

type invModule struct {
	gen         int64
	lastFullGen int64
	hashes      map[string]string
	order       []string
	sinceFull   int
	lastFull    time.Time
	lastSend    time.Time
	forceFull   bool
}

type inventory struct {
	mu   sync.Mutex
	st   *stateDB
	mods map[string]*invModule
	now  func() time.Time
}

func newInventory(st *stateDB) *inventory {
	return &inventory{st: st, mods: map[string]*invModule{}, now: time.Now}
}

func itemHash(m map[string]any) string {
	clean := make(map[string]any, len(m))
	for k, v := range m {
		if !invVolatile[k] {
			clean[k] = v
		}
	}
	b, _ := json.Marshal(clean) // map 键按字母序序列化，结果稳定
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:8])
}

func itemKey(module string, m map[string]any, h string) string {
	var parts []string
	for _, f := range invKeyFields[module] {
		if v := asString(m[f]); v != "" {
			parts = append(parts, strings.ToLower(v))
		}
	}
	if len(parts) == 0 {
		return "h:" + h
	}
	return strings.Join(parts, "|")
}

// planned 一次上报计划：kind 为 outSnapshot（全量）或 outSnapshotDelta；skip 表示无需上报。
type planned struct {
	kind    outboxKind
	payload map[string]any
	skip    bool
	stats   string
}

func (iv *inventory) loadGen(module string) int64 {
	if iv.st == nil {
		return 0
	}
	n, _ := strconv.ParseInt(iv.st.kvGet("inv_gen:"+module), 10, 64)
	return n
}

func (iv *inventory) saveGen(module string, gen int64) {
	if iv.st != nil {
		iv.st.kvSet("inv_gen:"+module, strconv.FormatInt(gen, 10))
	}
}

// plan 根据本轮采集结果决定发全量、发增量或跳过。deltaOK=false 时总是全量（v1/旧服务端）。
func (iv *inventory) plan(module, agentID string, items []any, deltaOK bool) planned {
	now := iv.now()
	keys := make([]string, 0, len(items))
	hashes := make(map[string]string, len(items))
	byKey := make(map[string]any, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		h := itemHash(m)
		k := itemKey(module, m, h)
		if _, dup := hashes[k]; dup {
			// 同键重复（例如 tasklist 兜底无 guid）：追加序号保持唯一
			for i := 2; ; i++ {
				k2 := k + "#" + strconv.Itoa(i)
				if _, d := hashes[k2]; !d {
					k = k2
					break
				}
			}
		}
		keys = append(keys, k)
		hashes[k] = h
		byKey[k] = m
	}
	digest := digestItems(items)
	at := now.Format("2006-01-02T15:04:05")

	iv.mu.Lock()
	defer iv.mu.Unlock()
	st := iv.mods[module]
	if st == nil {
		st = &invModule{gen: iv.loadGen(module), forceFull: true}
		iv.mods[module] = st
	}

	var upserts []map[string]any
	var removes []string
	full := !deltaOK || st.forceFull || st.sinceFull >= invFullEvery || now.Sub(st.lastFull) >= invFullMaxAge
	if !full {
		for _, k := range keys {
			if old, ok := st.hashes[k]; !ok || old != hashes[k] {
				upserts = append(upserts, map[string]any{"k": k, "item": byKey[k]})
			}
		}
		for _, k := range st.order {
			if _, ok := hashes[k]; !ok {
				removes = append(removes, k)
			}
		}
		changed := len(upserts) + len(removes)
		if changed == 0 && now.Sub(st.lastSend) < invTouchEvery {
			return planned{skip: true, stats: "unchanged"}
		}
		if changed*invDeltaMaxRatio2 > len(keys)+1 {
			full = true
		}
	}

	base := st.gen
	st.gen++
	gen := st.gen
	st.hashes, st.order, st.lastSend = hashes, keys, now
	iv.saveGen(module, gen)
	if full {
		st.forceFull, st.sinceFull, st.lastFull, st.lastFullGen = false, 0, now, gen
		return planned{kind: outSnapshot, stats: "full", payload: map[string]any{
			"agent_id": agentID, "module": module, "collected_at": at, "digest": digest,
			"items": items, "keys": keys, "generation": gen,
		}}
	}
	st.sinceFull++
	if upserts == nil {
		upserts = []map[string]any{}
	}
	if removes == nil {
		removes = []string{}
	}
	return planned{kind: outSnapshotDelta, stats: "delta", payload: map[string]any{
		"agent_id": agentID, "module": module, "collected_at": at, "digest": digest,
		"base_generation": base, "generation": gen, "item_count": len(keys),
		"upserts": upserts, "removes": removes,
	}}
}

// invalidate 服务端拒绝了某代号的增量（代号不匹配/服务端丢状态）：下一轮发全量。
// 早于最近一次全量的增量被拒属于过期重放，忽略。
func (iv *inventory) invalidate(module string, gen int64) {
	iv.mu.Lock()
	defer iv.mu.Unlock()
	st := iv.mods[module]
	if st == nil {
		return
	}
	if gen == 0 || gen > st.lastFullGen {
		st.forceFull = true
	}
}
