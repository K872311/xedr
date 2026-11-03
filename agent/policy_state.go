package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// 策略原子生效 + LKG（Last Known Good）：
//  1. 先整体校验，任何一项非法则整份拒绝（不做部分生效），该 rev 不再重试；
//  2. 校验通过后先落盘为 pending 再生效，进入试用期；
//  3. 试用期内心跳持续成功且资源不超限 → 晋升为 LKG；
//  4. 试用期内资源超限，或 Agent 连续重启（pending 未晋升就重启 ≥2 次）→ 回滚到 LKG（无 LKG 用内置默认）。
// 启动时先应用本地 LKG，离线重启也保持上次有效策略。

const (
	policyProbation    = 20 * time.Second
	policyMinBeats     = 3
	policyMaxBoots     = 2
	policyCPULimitPct  = 30.0
	policyRSSLimitMB   = 400.0
	policyOverStrikes  = 3
	kvPolicyLKG        = "policy:lkg"
	kvPolicyPending    = "policy:pending"
	kvPolicyBad        = "policy:bad"
	policyStatusNone   = "none"
	policyStatusProb   = "probation"
	policyStatusOK     = "applied"
	policyStatusReject = "rejected"
	policyStatusRB     = "rolled_back"
)

type policyDoc struct {
	Rev    int            `json:"rev"`
	Policy map[string]any `json:"policy"`
	Boots  int            `json:"boots,omitempty"`
}

// globalPolicyManager 供诊断包读取策略状态（agent_loop 初始化时赋值）。
var globalPolicyManager *policyManager

type policyManager struct {
	st    *stateDB
	apply func(map[string]any)
	now   func() time.Time

	mu        sync.Mutex
	offered   int
	applied   int
	lkg       *policyDoc
	bad       int
	status    string
	errMsg    string
	since     time.Time
	okBeats   int
	overCount int
	changedAt time.Time
}

func newPolicyManager(st *stateDB, apply func(map[string]any)) *policyManager {
	return &policyManager{st: st, apply: apply, now: time.Now, status: policyStatusNone}
}

func (pm *policyManager) loadDoc(k string) *policyDoc {
	if pm.st == nil {
		return nil
	}
	raw := pm.st.kvGet(k)
	if raw == "" {
		return nil
	}
	var d policyDoc
	if json.Unmarshal([]byte(raw), &d) != nil || d.Rev == 0 {
		return nil
	}
	return &d
}

func (pm *policyManager) saveDoc(k string, d *policyDoc) {
	if pm.st == nil {
		return
	}
	if d == nil {
		_, _ = pm.st.db.Exec("DELETE FROM kv WHERE k=?", k)
		return
	}
	b, _ := json.Marshal(d)
	pm.st.kvSet(k, string(b))
}

// safeApply 生效函数若 panic 视为失败，交由调用方回滚。
func (pm *policyManager) safeApply(p map[string]any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("应用策略时崩溃: %v", r)
		}
	}()
	pm.apply(p)
	return nil
}

// boot 启动时：应用 LKG；检查上次是否在试用期内反复重启。
func (pm *policyManager) boot() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.lkg = pm.loadDoc(kvPolicyLKG)
	if b := pm.loadDoc(kvPolicyBad); b != nil {
		pm.bad = b.Rev
	}
	if pm.lkg != nil {
		if pm.safeApply(pm.lkg.Policy) == nil {
			pm.applied, pm.status = pm.lkg.Rev, policyStatusOK
		}
	}
	pend := pm.loadDoc(kvPolicyPending)
	if pend == nil {
		return
	}
	pend.Boots++
	if pend.Boots >= policyMaxBoots {
		pm.bad = pend.Rev
		pm.saveDoc(kvPolicyBad, &policyDoc{Rev: pend.Rev})
		pm.saveDoc(kvPolicyPending, nil)
		pm.status = policyStatusRB
		pm.errMsg = fmt.Sprintf("rev %d 试用期内 Agent 连续重启 %d 次，已回滚到 %s", pend.Rev, pend.Boots, pm.lkgLabel())
		pm.changedAt = pm.now()
		log.Printf("策略回滚: %s", pm.errMsg)
		return
	}
	pm.saveDoc(kvPolicyPending, pend)
	if err := pm.safeApply(pend.Policy); err != nil {
		pm.rollbackLocked(err.Error())
		return
	}
	pm.applied, pm.status, pm.since, pm.okBeats = pend.Rev, policyStatusProb, pm.now(), 0
}

func (pm *policyManager) lkgLabel() string {
	if pm.lkg == nil {
		return "内置默认策略"
	}
	return fmt.Sprintf("LKG rev %d", pm.lkg.Rev)
}

// offer 心跳带来的服务端策略。
func (pm *policyManager) offer(rev int, pol map[string]any) {
	if rev <= 0 || pol == nil {
		return
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.offered = rev
	if rev == pm.applied || rev == pm.bad {
		return
	}
	if errs := validatePolicy(pol); len(errs) > 0 {
		pm.bad = rev
		pm.saveDoc(kvPolicyBad, &policyDoc{Rev: rev})
		pm.status, pm.errMsg, pm.changedAt = policyStatusReject, strings.Join(errs, "；"), pm.now()
		log.Printf("策略 rev %d 校验失败，整份拒绝: %s", rev, pm.errMsg)
		return
	}
	pm.saveDoc(kvPolicyPending, &policyDoc{Rev: rev, Policy: pol})
	if err := pm.safeApply(pol); err != nil {
		pm.applied = rev
		pm.rollbackLocked(err.Error())
		return
	}
	pm.applied, pm.status, pm.errMsg = rev, policyStatusProb, ""
	pm.since, pm.okBeats, pm.overCount, pm.changedAt = pm.now(), 0, 0, pm.now()
	log.Printf("策略 rev %d 已生效，进入试用期 %s", rev, policyProbation)
}

// heartbeatOK 每次心跳成功后调用；附带本进程资源占用用于试用期判定。
func (pm *policyManager) heartbeatOK(cpuPct, rssMB float64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.status != policyStatusProb {
		return
	}
	pm.okBeats++
	if cpuPct > policyCPULimitPct || rssMB > policyRSSLimitMB {
		pm.overCount++
		if pm.overCount >= policyOverStrikes {
			pm.rollbackLocked(fmt.Sprintf("试用期资源超限（CPU %.1f%% / 内存 %.0fMB）", cpuPct, rssMB))
			return
		}
	} else {
		pm.overCount = 0
	}
	if pm.okBeats >= policyMinBeats && pm.now().Sub(pm.since) >= policyProbation {
		pend := pm.loadDoc(kvPolicyPending)
		if pend == nil || pend.Rev != pm.applied {
			return
		}
		pend.Boots = 0
		pm.lkg = pend
		pm.saveDoc(kvPolicyLKG, pend)
		pm.saveDoc(kvPolicyPending, nil)
		pm.status, pm.changedAt = policyStatusOK, pm.now()
		log.Printf("策略 rev %d 试用通过，记为 LKG", pend.Rev)
	}
}

func (pm *policyManager) rollbackLocked(reason string) {
	failed := pm.applied
	pm.bad = failed
	pm.saveDoc(kvPolicyBad, &policyDoc{Rev: failed})
	pm.saveDoc(kvPolicyPending, nil)
	target, rev := defaultAgentPolicy(), 0
	if pm.lkg != nil {
		target, rev = pm.lkg.Policy, pm.lkg.Rev
	}
	_ = pm.safeApply(target)
	pm.applied = rev
	pm.status = policyStatusRB
	pm.errMsg = fmt.Sprintf("rev %d %s，已回滚到 %s", failed, reason, pm.lkgLabel())
	pm.changedAt = pm.now()
	log.Printf("策略回滚: %s", pm.errMsg)
}

func (pm *policyManager) state() map[string]any {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	m := map[string]any{
		"offered_rev": pm.offered, "applied_rev": pm.applied, "status": pm.status,
	}
	if pm.lkg != nil {
		m["lkg_rev"] = pm.lkg.Rev
	}
	if pm.bad != 0 {
		m["bad_rev"] = pm.bad
	}
	if pm.errMsg != "" {
		m["error"] = pm.errMsg
	}
	if !pm.changedAt.IsZero() {
		m["changed_at"] = pm.changedAt.Format("2006-01-02T15:04:05")
	}
	return m
}

// defaultAgentPolicy 没有 LKG 时的回滚目标（与服务端默认值一致的 Agent 侧子集）。
func defaultAgentPolicy() map[string]any {
	iv := map[string]any{}
	for k, v := range defaultIntervals() {
		iv[k] = float64(v)
	}
	return map[string]any{
		"response_enabled": true, "timeline_process": true, "timeline_file": true, "timeline_network": true,
		"self_protect": false, "fim_enabled": true, "fim_paths": []any{}, "intervals_sec": iv,
	}
}

var policyBoolKeys = []string{
	"response_enabled", "timeline_process", "timeline_file", "timeline_network", "self_protect",
	"fim_enabled", "isolate_allow_server", "whitelist_skip_rules", "mysql_dual_write",
}

func numberOf(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// validatePolicy 返回全部错误（空表示可整体生效）。未知字段忽略，保持向前兼容。
func validatePolicy(p map[string]any) []string {
	var errs []string
	for _, k := range policyBoolKeys {
		if v, ok := p[k]; ok {
			if _, isBool := v.(bool); !isBool {
				errs = append(errs, k+" 必须是布尔值")
			}
		}
	}
	if v, ok := p["heartbeat_sec"]; ok {
		if n, isNum := numberOf(v); !isNum || n < 3 || n > 120 {
			errs = append(errs, "heartbeat_sec 必须在 3~120")
		}
	}
	if v, ok := p["intervals_sec"]; ok {
		m, isMap := v.(map[string]any)
		if !isMap {
			errs = append(errs, "intervals_sec 必须是对象")
		} else {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if n, isNum := numberOf(m[k]); !isNum || n < 3 || n > 86400 {
					errs = append(errs, fmt.Sprintf("intervals_sec.%s 必须在 3~86400 秒", k))
				}
			}
		}
	}
	if v, ok := p["fim_paths"]; ok && v != nil {
		arr, isArr := v.([]any)
		switch {
		case !isArr:
			errs = append(errs, "fim_paths 必须是数组")
		case len(arr) > 50:
			errs = append(errs, "fim_paths 最多 50 项")
		default:
			for _, x := range arr {
				s, isStr := x.(string)
				r, okSpec := parseFIMPathSpec(s)
				if !isStr || !okSpec {
					errs = append(errs, fmt.Sprintf("fim_paths 非法路径: %v", x))
					continue
				}
				if len(strings.TrimRight(r.Path, `\`)) <= 2 {
					errs = append(errs, fmt.Sprintf("fim_paths 不允许监控整个磁盘: %s", s))
				}
			}
		}
	}
	if v, ok := p["log_tail_paths"]; ok && v != nil {
		arr, isArr := v.([]any)
		switch {
		case !isArr:
			errs = append(errs, "log_tail_paths 必须是数组")
		case len(arr) > 20:
			errs = append(errs, "log_tail_paths 最多 20 项")
		default:
			for _, x := range arr {
				s, isStr := x.(string)
				if !isStr || !validLogTailPath(s) {
					errs = append(errs, fmt.Sprintf("log_tail_paths 非法文件路径: %v", x))
				}
			}
		}
	}
	return errs
}

func validLogTailPath(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) <= 4 || strings.HasSuffix(s, `\`) {
		return false
	}
	if len(s) < 4 || s[1] != ':' || (s[2] != '\\' && s[2] != '/') {
		return false
	}
	return strings.ContainsAny(s[3:], `\/`)
}
