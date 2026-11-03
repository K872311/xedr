package main

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 实时 DNS：每个（进程实例, 域名, 类型）在窗口内只上报首次，其余计数，定期出进程级汇总；
// 记录应答 IP→域名，供网络外联事件反查域名；同一进程短时间大量 NXDOMAIN 视为 DGA 迹象。

const (
	dnsWindow       = 10 * time.Minute
	dnsSummaryEvery = 5 * time.Minute
	dnsNXWindow     = 5 * time.Minute
	dnsNXBurst      = 60 // 浏览器/广告拦截/VPN 易到 25，抬高减少 DGA 误报
	dnsIPCacheMax   = 20000
	dnsKeysMax      = 50000
)

var dnsCache = newDNSAgg()

var dnsQTypeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
	28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}

var dnsStatusNames = map[uint32]string{
	0: "NOERROR", 9002: "SERVFAIL", 9003: "NXDOMAIN", 9005: "REFUSED",
	9501: "NODATA", 1460: "TIMEOUT", 11001: "NXDOMAIN", 1168: "NOTFOUND",
}

type dnsRecord struct {
	Query   string
	QType   uint16
	Status  uint32
	Answers []string // IP
	CNAMEs  []string
	PID     uint32
	Proc    string
	Entity  string
	At      time.Time
}

type dnsKeyState struct {
	lastEmit   time.Time
	suppressed int
}

type dnsOwnerSum struct {
	pid    uint32
	proc   string
	entity string
	total  int
	counts map[string]int
}

type ipDomain struct {
	domain string
	at     time.Time
}

type dnsAgg struct {
	mu        sync.Mutex
	keys      map[string]*dnsKeyState
	owners    map[string]*dnsOwnerSum
	nx        map[string]map[string]time.Time
	nxAlerted map[string]time.Time
	ips       map[string]ipDomain
	lastFlush time.Time
}

func newDNSAgg() *dnsAgg {
	return &dnsAgg{
		keys: map[string]*dnsKeyState{}, owners: map[string]*dnsOwnerSum{},
		nx: map[string]map[string]time.Time{}, nxAlerted: map[string]time.Time{},
		ips: map[string]ipDomain{}, lastFlush: time.Now(),
	}
}

// normalizeDomain 小写、去尾点与空白；返回空串表示不值得上报。
func normalizeDomain(q string) string {
	q = strings.ToLower(strings.TrimSpace(q))
	q = strings.TrimRight(q, ".")
	if q == "" || !strings.Contains(q, ".") || net.ParseIP(q) != nil {
		return ""
	}
	for _, suf := range []string{".arpa", ".local", ".localhost", ".localdomain", ".lan", ".home"} {
		if strings.HasSuffix(q, suf) {
			return ""
		}
	}
	return q
}

// parseDNSResults 解析 DNS-Client 3008 的 QueryResults，如 "type:  5 cdn.x.com;::ffff:1.2.3.4;1.2.3.5;"。
func parseDNSResults(s string) (ips []string, cnames []string) {
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(part), "type:") {
			f := strings.Fields(part[5:])
			if len(f) >= 2 && f[0] == "5" {
				if c := normalizeDomain(f[1]); c != "" && !seen["c:"+c] {
					seen["c:"+c] = true
					cnames = append(cnames, c)
				}
			}
			continue
		}
		p := strings.TrimPrefix(part, "::ffff:")
		if ip := net.ParseIP(p); ip != nil {
			v := ip.String()
			if !seen[v] {
				seen[v] = true
				ips = append(ips, v)
			}
		}
	}
	return ips, cnames
}

// dgaScore 0~1：对注册域主体标签看长度、熵、元音与数字比例。启发式，仅作提示。
func dgaScore(domain string) float64 {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return 0
	}
	l := labels[len(labels)-2]
	if len(labels) >= 3 && len(l) <= 3 && len(labels[len(labels)-1]) <= 3 {
		l = labels[len(labels)-3] // 例如 xxx.com.cn
	}
	if len(l) < 10 {
		return 0
	}
	freq := map[rune]int{}
	vowels, digits := 0, 0
	for _, r := range l {
		freq[r]++
		switch {
		case strings.ContainsRune("aeiou", r):
			vowels++
		case r >= '0' && r <= '9':
			digits++
		}
	}
	ent := 0.0
	n := float64(len(l))
	for _, c := range freq {
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	score := 0.0
	if ent >= 3.3 {
		score += 0.4
	}
	if ent >= 3.8 {
		score += 0.2
	}
	if float64(vowels)/n < 0.25 {
		score += 0.2
	}
	if float64(digits)/n > 0.25 {
		score += 0.2
	}
	if len(l) >= 16 {
		score += 0.1
	}
	if score > 1 {
		score = 1
	}
	return math.Round(score*100) / 100
}

func dnsOwner(r dnsRecord) string {
	if r.Entity != "" {
		return r.Entity
	}
	return "pid:" + strconv.FormatUint(uint64(r.PID), 10)
}

func qtypeName(t uint16) string {
	if s, ok := dnsQTypeNames[t]; ok {
		return s
	}
	return strconv.Itoa(int(t))
}

func dnsStatusName(s uint32) string {
	if n, ok := dnsStatusNames[s]; ok {
		return n
	}
	return strconv.FormatUint(uint64(s), 10)
}

func isNXStatus(s uint32) bool { return s == 9003 || s == 11001 }

func nameOr2(name string, pid uint32) string {
	if name != "" {
		return name
	}
	return fmt.Sprintf("pid-%d", pid)
}

// observe 处理一条查询完成记录，返回需立即上报的事件。
func (a *dnsAgg) observe(r dnsRecord) []map[string]any {
	r.Query = normalizeDomain(r.Query)
	if r.Query == "" {
		return nil
	}
	if r.At.IsZero() {
		r.At = time.Now()
	}
	owner := dnsOwner(r)
	key := owner + "|" + r.Query + "|" + strconv.Itoa(int(r.QType))
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, ip := range r.Answers {
		if len(a.ips) >= dnsIPCacheMax {
			a.gcIPsLocked(r.At)
		}
		a.ips[ip] = ipDomain{domain: r.Query, at: r.At}
	}
	sum := a.owners[owner]
	if sum == nil {
		sum = &dnsOwnerSum{pid: r.PID, proc: r.Proc, entity: r.Entity, counts: map[string]int{}}
		a.owners[owner] = sum
	}
	sum.total++
	sum.counts[r.Query]++

	var out []map[string]any
	if isNXStatus(r.Status) {
		set := a.nx[owner]
		if set == nil {
			set = map[string]time.Time{}
			a.nx[owner] = set
		}
		set[r.Query] = r.At
		for q, t := range set {
			if r.At.Sub(t) > dnsNXWindow {
				delete(set, q)
			}
		}
		if len(set) >= dnsNXBurst && r.At.Sub(a.nxAlerted[owner]) > dnsWindow {
			a.nxAlerted[owner] = r.At
			names := make([]string, 0, len(set))
			for q := range set {
				names = append(names, q)
			}
			sort.Strings(names)
			if len(names) > 30 {
				names = names[:30]
			}
			out = append(out, map[string]any{
				"etype": "dns_nx_burst", "severity": "high", "ts": r.At.Format("2006-01-02T15:04:05"),
				"summary": fmt.Sprintf("DNS 大量解析失败(疑似DGA): %s %d 个域名", nameOr2(r.Proc, r.PID), len(set)),
				"detail": map[string]any{
					"source": "etw_dns", "pid": r.PID, "process_name": r.Proc, "entity_id": r.Entity,
					"nx_count": len(set), "window_sec": int(dnsNXWindow.Seconds()), "samples": names,
				},
			})
		}
	}

	st := a.keys[key]
	if st != nil && r.At.Sub(st.lastEmit) < dnsWindow {
		st.suppressed++
		return out
	}
	repeat := 0
	if st != nil {
		repeat = st.suppressed
	}
	if len(a.keys) >= dnsKeysMax {
		a.gcKeysLocked(r.At)
	}
	a.keys[key] = &dnsKeyState{lastEmit: r.At}
	score := dgaScore(r.Query)
	sev := "info"
	if score >= 0.7 && isNXStatus(r.Status) {
		sev = "medium"
	}
	detail := map[string]any{
		"source": "etw_dns", "query": r.Query, "qtype": r.QType, "qtype_name": qtypeName(r.QType),
		"status": r.Status, "status_name": dnsStatusName(r.Status),
		"pid": r.PID, "process_name": r.Proc,
	}
	if r.Entity != "" {
		detail["entity_id"] = r.Entity
	}
	if len(r.Answers) > 0 {
		detail["answers"] = r.Answers
	}
	if len(r.CNAMEs) > 0 {
		detail["cnames"] = r.CNAMEs
	}
	if score > 0 {
		detail["dga_score"] = score
	}
	if repeat > 0 {
		detail["repeat_prev_window"] = repeat
	}
	sum2 := "DNS: " + r.Query
	if isNXStatus(r.Status) {
		sum2 = "DNS(NXDOMAIN): " + r.Query
	}
	out = append(out, map[string]any{
		"etype": "dns_query", "summary": sum2, "severity": sev,
		"ts": r.At.Format("2006-01-02T15:04:05"), "detail": detail,
	})
	return out
}

// flush 输出进程级汇总（仅包含窗口内被合并的重复查询），并清理过期状态。
func (a *dnsAgg) flush(now time.Time) []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastFlush = now
	var out []map[string]any
	for owner, s := range a.owners {
		if s.total <= len(s.counts) {
			continue // 没有重复查询，首条事件已足够
		}
		type kv struct {
			q string
			n int
		}
		top := make([]kv, 0, len(s.counts))
		for q, n := range s.counts {
			top = append(top, kv{q, n})
		}
		sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n || top[i].n == top[j].n && top[i].q < top[j].q })
		if len(top) > 20 {
			top = top[:20]
		}
		items := make([]map[string]any, 0, len(top))
		for _, t := range top {
			items = append(items, map[string]any{"query": t.q, "count": t.n})
		}
		d := map[string]any{
			"source": "etw_dns", "pid": s.pid, "process_name": s.proc,
			"total": s.total, "distinct": len(s.counts), "top": items,
			"window_sec": int(dnsSummaryEvery.Seconds()),
		}
		if s.entity != "" {
			d["entity_id"] = s.entity
		}
		out = append(out, map[string]any{
			"etype": "dns_summary", "severity": "info", "ts": now.Format("2006-01-02T15:04:05"),
			"summary": fmt.Sprintf("DNS 汇总: %s %d 次/%d 个域名", nameOr2(s.proc, s.pid), s.total, len(s.counts)),
			"detail":  d,
		})
		_ = owner
	}
	a.owners = map[string]*dnsOwnerSum{}
	a.gcKeysLocked(now)
	a.gcIPsLocked(now)
	for o, t := range a.nxAlerted {
		if now.Sub(t) > 2*dnsWindow {
			delete(a.nxAlerted, o)
		}
	}
	for o, set := range a.nx {
		for q, t := range set {
			if now.Sub(t) > dnsNXWindow {
				delete(set, q)
			}
		}
		if len(set) == 0 {
			delete(a.nx, o)
		}
	}
	return out
}

func (a *dnsAgg) due(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return now.Sub(a.lastFlush) >= dnsSummaryEvery
}

func (a *dnsAgg) gcKeysLocked(now time.Time) {
	for k, st := range a.keys {
		if now.Sub(st.lastEmit) > dnsWindow {
			delete(a.keys, k)
		}
	}
}

func (a *dnsAgg) gcIPsLocked(now time.Time) {
	for ip, d := range a.ips {
		if now.Sub(d.at) > 30*time.Minute {
			delete(a.ips, ip)
		}
	}
	if len(a.ips) >= dnsIPCacheMax {
		a.ips = map[string]ipDomain{}
	}
}

// domainForIP 外联事件反查最近解析到该 IP 的域名。
func (a *dnsAgg) domainForIP(ip string) string {
	ip = strings.Trim(ip, "[]")
	if p := net.ParseIP(ip); p != nil {
		ip = p.String()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if d, ok := a.ips[ip]; ok && time.Since(d.at) < 30*time.Minute {
		return d.domain
	}
	return ""
}
