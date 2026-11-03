package main

import (
	"strings"
	"testing"
	"time"
)

func invItems(names ...string) []any {
	out := make([]any, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]any{"name": n, "status": "Running", "memory_mb": 1.0})
	}
	return out
}

func TestInventoryDeltaChain(t *testing.T) {
	st := memoryStateDB()
	iv := newInventory(st)
	now := time.Now()
	iv.now = func() time.Time { return now }

	p := iv.plan("service", "a1", invItems("a", "b", "c", "d"), true)
	if p.kind != outSnapshot || p.payload["generation"] != int64(1) {
		t.Fatalf("首轮必须全量: %+v", p)
	}
	// 只有易变字段变化：视为未变化（10 分钟内跳过）
	items := invItems("a", "b", "c", "d")
	items[0].(map[string]any)["memory_mb"] = 99.0
	if p := iv.plan("service", "a1", items, true); !p.skip {
		t.Fatal("易变字段变化不应触发上报")
	}
	// 新增 e、删除 d：增量
	p = iv.plan("service", "a1", invItems("a", "b", "c", "e"), true)
	if p.kind != outSnapshotDelta || p.payload["base_generation"] != int64(1) || p.payload["generation"] != int64(2) {
		t.Fatalf("应为增量 1->2: %+v", p.payload)
	}
	ups := p.payload["upserts"].([]map[string]any)
	rms := p.payload["removes"].([]string)
	if len(ups) != 1 || ups[0]["k"] != "e" || len(rms) != 1 || rms[0] != "d" {
		t.Fatalf("delta 内容: ups=%v rms=%v", ups, rms)
	}
	// 服务端拒绝 gen 2 → 下一轮全量
	iv.invalidate("service", 2)
	if p := iv.plan("service", "a1", invItems("a", "b", "c", "e"), true); p.kind != outSnapshot {
		t.Fatal("被拒后应回退全量")
	}
	// 过期的旧增量被拒（早于最近全量）不再触发全量
	iv.invalidate("service", 2)
	now = now.Add(time.Minute)
	if p := iv.plan("service", "a1", invItems("a", "b", "c", "e", "f"), true); p.kind != outSnapshotDelta {
		t.Fatal("过期增量被拒不应强制全量")
	}
	// 一大半变化：直接全量更省
	if p := iv.plan("service", "a1", invItems("x", "y", "z", "w", "v"), true); p.kind != outSnapshot {
		t.Fatal("大面积变化应发全量")
	}
	// 无变化超过保活间隔：发空增量刷新采集时间
	now = now.Add(invTouchEvery + time.Second)
	p = iv.plan("service", "a1", invItems("x", "y", "z", "w", "v"), true)
	if p.kind != outSnapshotDelta || len(p.payload["upserts"].([]map[string]any)) != 0 {
		t.Fatal("保活应为空增量")
	}
	// v1/不支持增量：总是全量
	if p := iv.plan("service", "a1", invItems("x"), false); p.kind != outSnapshot {
		t.Fatal("deltaOK=false 必须全量")
	}
	// 代号跨重启单调递增
	iv2 := newInventory(st)
	if p := iv2.plan("service", "a1", invItems("x"), true); p.kind != outSnapshot || p.payload["generation"].(int64) <= 5 {
		t.Fatalf("重启后首轮全量且代号继续递增: %+v", p.payload["generation"])
	}
}

func TestItemKeyDuplicates(t *testing.T) {
	iv := newInventory(nil)
	items := []any{map[string]any{"pid": 1, "name": "a"}, map[string]any{"pid": 2, "name": "a"}}
	p := iv.plan("process", "a1", items, true)
	keys := p.payload["keys"].([]string)
	if len(keys) != 2 || keys[0] == keys[1] {
		t.Fatalf("无 guid 时按内容哈希，且必须唯一: %v", keys)
	}
}

func TestPolicyValidate(t *testing.T) {
	good := map[string]any{"response_enabled": true, "heartbeat_sec": 5.0,
		"intervals_sec": map[string]any{"process": 5.0}, "fim_paths": []any{`D:\app|r`}}
	if errs := validatePolicy(good); len(errs) != 0 {
		t.Fatalf("合法策略被拒: %v", errs)
	}
	bad := map[string]any{"response_enabled": "yes", "heartbeat_sec": 1.0,
		"intervals_sec": map[string]any{"process": 0.0}, "fim_paths": []any{`C:\`, 3.0}}
	errs := validatePolicy(bad)
	if len(errs) < 4 {
		t.Fatalf("应报出全部错误: %v", errs)
	}
}

func TestPolicyLKGLifecycle(t *testing.T) {
	st := memoryStateDB()
	var applied []map[string]any
	now := time.Now()
	mk := func() *policyManager {
		pm := newPolicyManager(st, func(p map[string]any) { applied = append(applied, p) })
		pm.now = func() time.Time { return now }
		return pm
	}
	pm := mk()
	pm.boot()
	pm.offer(1, map[string]any{"response_enabled": false})
	if pm.state()["status"] != policyStatusProb {
		t.Fatal("新策略应进入试用期")
	}
	for i := 0; i < policyMinBeats; i++ {
		now = now.Add(policyProbation / 2)
		pm.heartbeatOK(1, 50)
	}
	if s := pm.state(); s["status"] != policyStatusOK || s["lkg_rev"] != 1 {
		t.Fatalf("试用通过应成为 LKG: %v", s)
	}
	// 非法策略整份拒绝，且不改变已生效策略
	n := len(applied)
	pm.offer(2, map[string]any{"heartbeat_sec": 999.0})
	if s := pm.state(); s["status"] != policyStatusReject || s["applied_rev"] != 1 || len(applied) != n {
		t.Fatalf("非法策略: %v", s)
	}
	pm.offer(2, map[string]any{"heartbeat_sec": 999.0})
	if len(applied) != n {
		t.Fatal("被拒 rev 不应重试")
	}
	// 资源超限回滚到 LKG
	pm.offer(3, map[string]any{"fim_enabled": true})
	for i := 0; i < policyOverStrikes; i++ {
		pm.heartbeatOK(80, 50)
	}
	s := pm.state()
	if s["status"] != policyStatusRB || s["applied_rev"] != 1 || !strings.Contains(asString(s["error"]), "资源超限") {
		t.Fatalf("应回滚到 LKG: %v", s)
	}
	if last := applied[len(applied)-1]; last["response_enabled"] != false {
		t.Fatalf("回滚应重新应用 LKG 内容: %v", last)
	}
	// 试用期内反复重启：第 2 次启动时回滚
	pm.offer(4, map[string]any{"self_protect": true})
	pmA := mk()
	pmA.boot() // 第 1 次重启：继续试用
	if pmA.state()["applied_rev"] != 4 {
		t.Fatalf("第一次重启应继续试用 rev 4: %v", pmA.state())
	}
	pmB := mk()
	pmB.boot() // 第 2 次重启：回滚
	if s := pmB.state(); s["status"] != policyStatusRB || s["applied_rev"] != 1 {
		t.Fatalf("连续重启应回滚: %v", s)
	}
	pmB.offer(4, map[string]any{"self_protect": true})
	if pmB.state()["applied_rev"] != 1 {
		t.Fatal("已判坏的 rev 不应再次生效")
	}
}
