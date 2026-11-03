package main

import (
	"testing"
	"time"
)

func TestEntityPIDReuseAndTombstone(t *testing.T) {
	tb := newEntityTable("b1", nil)
	base := filetimeOf(time.Date(2026, 1, 1, 10, 0, 0, 0, time.Local))
	parent, _ := tb.onStart(100, 0, base, "explorer.exe", `C:\Windows\explorer.exe`, false)
	child, isNew := tb.onStart(200, 100, base+5*ftPerSec, "cmd.exe", "", false)
	if !isNew || child.ParentID != parent.ID {
		t.Fatalf("child parent link: new=%v parent=%q want %q", isNew, child.ParentID, parent.ID)
	}
	if _, again := tb.onStart(200, 100, base+5*ftPerSec+ftPerSec/2, "cmd.exe", "", true); again {
		t.Fatal("同一实例的重复创建事件不应视为新进程")
	}
	exitAt := base + 60*ftPerSec
	if e := tb.onExit(200, exitAt, 1); e == nil || e.ID != child.ID {
		t.Fatal("exit 应命中 child")
	}
	// 迟到事件（退出后 3 秒内）仍归属旧实例
	if e := tb.resolve(200, exitAt+3*ftPerSec); e == nil || e.ID != child.ID {
		t.Fatal("墓碑期内迟到事件应归属已退出实例")
	}
	// PID 复用：新实例与旧实例 ID 不同，新时间点归属新实例
	reused, isNew := tb.onStart(200, 100, base+120*ftPerSec, "evil.exe", "", false)
	if !isNew || reused.ID == child.ID {
		t.Fatal("PID 复用必须生成新实体")
	}
	if e := tb.resolve(200, base+30*ftPerSec); e == nil || e.ID != child.ID {
		t.Fatal("旧时间点应解析到旧实例")
	}
	if e := tb.resolve(200, base+130*ftPerSec); e == nil || e.ID != reused.ID {
		t.Fatal("新时间点应解析到新实例")
	}
}

func TestEntityReuseWithoutExitEvent(t *testing.T) {
	tb := newEntityTable("b1", nil)
	base := filetimeOf(time.Now())
	old, _ := tb.onStart(300, 0, base, "a.exe", "", false)
	nw, _ := tb.onStart(300, 0, base+100*ftPerSec, "b.exe", "", false)
	if old.Exit == 0 {
		t.Fatal("丢了 ProcessStop 时，同 PID 新实例出现应把旧实例转为墓碑")
	}
	if tb.resolve(300, 0).ID != nw.ID {
		t.Fatal("当前存活应为新实例")
	}
}

func TestEntityGCAndAnnotate(t *testing.T) {
	now := time.Now()
	tb := newEntityTable("b1", func(pid uint32) (procInfo, bool) {
		if pid == 77 {
			return procInfo{Start: filetimeOf(now.Add(-time.Hour)), PPID: 1, Name: "svc.exe"}, true
		}
		return procInfo{}, false
	})
	d := map[string]any{"pid": 77}
	if e := tb.annotate(d, filetimeOf(now)); e == nil || d["entity_id"] == "" {
		t.Fatal("未登记的现存进程应通过 lookup 补登记")
	}
	tb.gc(map[uint32]bool{})
	e := tb.get(asString(d["entity_id"]))
	if e == nil || e.Exit == 0 {
		t.Fatal("gc 应把已不存在的 PID 标为退出")
	}
	tb.now = func() time.Time { return now.Add(entityTombstoneTTL + time.Minute) }
	tb.gc(nil)
	if tb.size() != 0 {
		t.Fatalf("过期墓碑应被清理, size=%d", tb.size())
	}
	// lookup 到的进程比事件晚创建：说明事件属于已退出的旧实例，不得错误归属
	late := newEntityTable("b1", func(uint32) (procInfo, bool) {
		return procInfo{Start: filetimeOf(now)}, true
	})
	if late.resolve(5, filetimeOf(now.Add(-time.Minute))) != nil {
		t.Fatal("不应把旧事件归给新创建的同 PID 进程")
	}
}

func TestDNSAggregation(t *testing.T) {
	a := newDNSAgg()
	at := time.Now()
	rec := dnsRecord{Query: "WWW.Example.COM.", QType: 1, PID: 10, Proc: "chrome.exe", Entity: "e1", At: at,
		Answers: []string{"93.184.216.34"}}
	evs := a.observe(rec)
	if len(evs) != 1 || evs[0]["etype"] != "dns_query" {
		t.Fatalf("首次查询应立即上报: %v", evs)
	}
	if q := evs[0]["detail"].(map[string]any)["query"]; q != "www.example.com" {
		t.Fatalf("域名应规范化: %v", q)
	}
	for i := 0; i < 5; i++ {
		rec.At = at.Add(time.Duration(i+1) * time.Second)
		if len(a.observe(rec)) != 0 {
			t.Fatal("窗口内重复查询应合并")
		}
	}
	if a.domainForIP("93.184.216.34") != "www.example.com" {
		t.Fatal("应答 IP 应能反查域名")
	}
	sum := a.flush(at.Add(dnsSummaryEvery))
	if len(sum) != 1 || sum[0]["detail"].(map[string]any)["total"] != 6 {
		t.Fatalf("汇总应包含重复计数: %v", sum)
	}
	// 窗口过后再次出现：重新上报并带上一窗口被合并的次数
	rec.At = at.Add(dnsWindow + time.Second)
	evs = a.observe(rec)
	if len(evs) != 1 {
		t.Fatal("窗口过期后应重新上报")
	}
	if normalizeDomain("printer.local") != "" || normalizeDomain("1.2.3.4") != "" || normalizeDomain("wpad") != "" {
		t.Fatal("本地/IP/单标签名不应上报")
	}
}

func TestDNSNXBurst(t *testing.T) {
	a := newDNSAgg()
	at := time.Now()
	var burst int
	for i := 0; i < dnsNXBurst+5; i++ {
		for _, ev := range a.observe(dnsRecord{Query: "x" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "qzv.com",
			Status: 9003, PID: 9, Entity: "e9", At: at.Add(time.Duration(i) * time.Second)}) {
			if ev["etype"] == "dns_nx_burst" {
				burst++
			}
		}
	}
	if burst != 1 {
		t.Fatalf("NXDOMAIN 爆发应且只应告警一次, got %d", burst)
	}
}

func TestParseDNSResultsAndDGA(t *testing.T) {
	ips, cn := parseDNSResults("type:  5 cdn.example.net;::ffff:1.2.3.4;2606:4700::1;1.2.3.4;")
	if len(ips) != 2 || ips[0] != "1.2.3.4" || len(cn) != 1 || cn[0] != "cdn.example.net" {
		t.Fatalf("parse: ips=%v cnames=%v", ips, cn)
	}
	if dgaScore("www.google.com") != 0 {
		t.Fatal("常见域名不应有 DGA 分")
	}
	if dgaScore("xkq7v9zt2mpl4rwb.com") < 0.6 {
		t.Fatalf("随机域名应有较高 DGA 分: %v", dgaScore("xkq7v9zt2mpl4rwb.com"))
	}
}

func TestDLLGate(t *testing.T) {
	g := newDLLGate()
	now := time.Now()
	if !g.allow("app.exe", `D:\App\a.dll`, "e1", false, false, now) || g.allow("app.exe", `D:\App\A.DLL`, "e2", false, false, now) {
		t.Fatal("已签名：同进程名同 DLL 30 分钟内只报一次（跨实例）")
	}
	if !g.allow("app.exe", `D:\App\a.dll`, "e3", false, false, now.Add(dllDedupTTL+time.Second)) {
		t.Fatal("过期后应重新上报")
	}
	// 投放区 / 未签名：每个进程实例各报一次，且不受 perEnt 上限压制
	if !g.allow("x.exe", `C:\Temp\evil.dll`, "e1", true, false, now) || !g.allow("x.exe", `C:\Temp\evil.dll`, "e2", true, false, now) {
		t.Fatal("投放区 DLL 应按实例上报")
	}
	if g.allow("x.exe", `C:\Temp\evil.dll`, "e2", true, false, now) {
		t.Fatal("同实例同投放区 DLL 只报一次")
	}
	n := 0
	for i := 0; i < dllPerEntityMax+10; i++ {
		dll := `D:\Big\u` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".dll"
		if g.allow("big.exe", dll, "eu", false, true, now) {
			n++
		}
	}
	if n != dllPerEntityMax+10 {
		t.Fatalf("未签名 DLL 不应受单实例上限压制, got %d", n)
	}
	n = 0
	for i := 0; i < dllPerEntityMax+10; i++ {
		if g.allow("big.exe", `D:\Big\m`+string(rune('a'+i%26))+string(rune('a'+i/26))+".dll", "eb", false, false, now) {
			n++
		}
	}
	if n != dllPerEntityMax {
		t.Fatalf("已签名单实例上限 %d, got %d", dllPerEntityMax, n)
	}
}

func TestFIMHelpers(t *testing.T) {
	r := fimRoot{Path: `C:\Windows\System32`, Exts: fimExecExts}
	if !r.contains(`C:\Windows\System32\evil.dll`) || r.contains(`C:\Windows\System32\drivers\x.sys`) {
		t.Fatal("非递归根只包含直接子文件")
	}
	if !r.wants(`a.DLL`) || r.wants(`a.txt`) {
		t.Fatal("扩展名过滤")
	}
	rr := fimRoot{Path: `C:\Users\Public`, Recursive: true}
	if !rr.contains(`C:\Users\Public\a\b\c.exe`) {
		t.Fatal("递归根应包含子目录")
	}
	if fimChanged(fimEntry{SHA: "aa", Size: 1, Mtime: 1}, fimEntry{SHA: "AA", Size: 1, Mtime: 9}) {
		t.Fatal("哈希相同视为未变化（仅时间戳变化）")
	}
	if !fimChanged(fimEntry{Size: 1, Mtime: 1}, fimEntry{Size: 2, Mtime: 1}) {
		t.Fatal("无哈希时大小变化视为变化")
	}
	if s, ok := parseFIMPathSpec(`D:\App\|r`); !ok || !s.Recursive || s.Path != `D:\App` {
		t.Fatalf("spec 解析: %+v %v", s, ok)
	}
	if _, ok := parseFIMPathSpec(`relative\dir`); ok {
		t.Fatal("相对路径应拒绝")
	}
	l := fimLimiter{limit: 2}
	now := time.Now()
	l.allow(now)
	l.allow(now)
	if l.allow(now) || l.takeDropped() != 1 {
		t.Fatal("限流计数")
	}
	ev := fimEvent("fim_modify", fimRoot{Path: `C:\X`, Label: "L", Severity: "high"},
		fimEntry{Path: `C:\X\a.exe`, Size: 2, SHA: "new"}, fimEntry{Path: `C:\X\a.exe`, Size: 1, SHA: "old"}, nil)
	d := ev["detail"].(map[string]any)
	if d["old_sha256"] != "old" || d["sha256"] != "new" || ev["severity"] != "high" {
		t.Fatalf("fim event: %v", ev)
	}
}
