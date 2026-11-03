package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// fakeServer 模拟 v2 批量接口：按 uuid 去重，可配置拒绝/部分确认/故障。
type fakeServer struct {
	mu       sync.Mutex
	seen     map[string]int // uuid -> 收到次数
	rejectFn func(uuid string) bool
	dropFn   func(uuid string) bool // 不确认（模拟部分失败）
	fail     int                    // 返回 500 的次数
	v2Status int                    // 非 0 则 v2 端点返回该状态
	legacy   int                    // v1 端点收到次数
}

func newFake() (*fakeServer, *httptest.Server) {
	f := &fakeServer{seen: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agent/v2/events/batch", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.v2Status != 0 {
			http.Error(w, "nope", f.v2Status)
			return
		}
		if f.fail > 0 {
			f.fail--
			http.Error(w, "boom", 500)
			return
		}
		var req struct {
			Events []struct {
				UUID string `json:"uuid"`
			} `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := map[string]any{"ok": true, "acked": []string{}, "rejected": []map[string]string{}}
		acked, rej := []string{}, []map[string]string{}
		for _, e := range req.Events {
			f.seen[e.UUID]++
			switch {
			case f.rejectFn != nil && f.rejectFn(e.UUID):
				rej = append(rej, map[string]string{"uuid": e.UUID, "error": "bad"})
			case f.dropFn != nil && f.dropFn(e.UUID):
			default:
				acked = append(acked, e.UUID)
			}
		}
		resp["acked"], resp["rejected"] = acked, rej
		_ = json.NewEncoder(w).Encode(resp)
	})
	legacy := func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.legacy++
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
	for _, p := range []string{"/api/agent/timeline", "/api/agent/snapshot", "/api/agent/event", "/api/agent/commands/ack"} {
		mux.HandleFunc(p, legacy)
	}
	return f, httptest.NewServer(mux)
}

func testBox(t *testing.T, dir string, srvURL string) (*outbox, *APIClient) {
	t.Helper()
	box := newOutbox(dir)
	t.Cleanup(func() { box.st.close() })
	api := newClient(Config{ServerURL: srvURL, Token: "tok"})
	api.setCredential("fa_secret", "aid")
	return box, api
}

func TestOutboxPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	box := newOutbox(dir)
	for i := 0; i < 3; i++ {
		box.enqueue(outEvent, 90, map[string]any{"title": "t", "i": i})
	}
	if box.pending() != 3 {
		t.Fatalf("pending=%d", box.pending())
	}
	box.st.close() // 模拟进程退出
	box2 := newOutbox(dir)
	defer box2.st.close()
	if box2.pending() != 3 {
		t.Fatalf("重启后丢数据: pending=%d", box2.pending())
	}
}

func TestOutboxV2AckAndPoisonDropped(t *testing.T) {
	f, srv := newFake()
	defer srv.Close()
	box, api := testBox(t, t.TempDir(), srv.URL)
	box.useV2.Store(true)
	box.enqueue(outEvent, 90, map[string]any{"title": "good"})
	box.enqueue(outEvent, 80, map[string]any{"title": "poison"})
	f.rejectFn = func(string) bool { return false }
	// 让第二条（优先级低）被永久拒绝
	var poison string
	f.mu.Lock()
	f.rejectFn = func(u string) bool { return u == poison }
	f.mu.Unlock()
	rows := box.fetchReady()
	poison = rows[1].uuid
	n := box.flush(api)
	if n != 2 || box.pending() != 0 {
		t.Fatalf("flush n=%d pending=%d", n, box.pending())
	}
	if box.rejected.Load() != 1 {
		t.Fatalf("rejected=%d", box.rejected.Load())
	}
}

func TestOutboxPartialAckKeepsUUIDStable(t *testing.T) {
	f, srv := newFake()
	defer srv.Close()
	box, api := testBox(t, t.TempDir(), srv.URL)
	box.useV2.Store(true)
	box.enqueue(outEvent, 90, map[string]any{"title": "a"})
	box.enqueue(outEvent, 90, map[string]any{"title": "b"})
	rows := box.fetchReady()
	stuck := rows[1].uuid
	f.dropFn = func(u string) bool { return u == stuck }
	if n := box.flush(api); n != 1 || box.pending() != 1 {
		t.Fatalf("n=%d pending=%d", n, box.pending())
	}
	// 重试条目有退避：立即取不到；放开退避后以同一 uuid 重发
	if len(box.fetchReady()) != 0 {
		t.Fatal("失败条目应进入退避")
	}
	_, _ = box.st.db.Exec("UPDATE outbox SET available_at=0")
	f.dropFn = nil
	if n := box.flush(api); n != 1 || box.pending() != 0 {
		t.Fatalf("retry n=%d pending=%d", n, box.pending())
	}
	if f.seen[stuck] != 2 {
		t.Fatalf("同一事件必须以同一 uuid 重发, seen=%d", f.seen[stuck])
	}
}

func TestOutboxNetworkFailureBacksOffAndRecovers(t *testing.T) {
	f, srv := newFake()
	defer srv.Close()
	box, api := testBox(t, t.TempDir(), srv.URL)
	box.useV2.Store(true)
	box.enqueue(outEvent, 90, map[string]any{"title": "x"})
	f.fail = 1
	if n := box.flush(api); n != 0 || box.pending() != 1 {
		t.Fatalf("n=%d pending=%d", n, box.pending())
	}
	if !box.netBackoff() {
		t.Fatal("网络失败后应整体退避")
	}
	if n := box.flush(api); n != 0 { // 退避期内不应再打服务端
		t.Fatalf("退避期内发送了 %d", n)
	}
	box.mu.Lock()
	box.netBackoffEnd = box.netBackoffEnd.Add(-1 << 40)
	box.mu.Unlock()
	if n := box.flush(api); n != 1 || box.pending() != 0 {
		t.Fatalf("recover n=%d pending=%d", n, box.pending())
	}
}

func TestSnapshotCoalescing(t *testing.T) {
	box := newOutbox(t.TempDir())
	defer box.st.close()
	box.enqueue(outSnapshot, 50, map[string]any{"module": "process", "items": []any{1}})
	box.enqueue(outSnapshot, 50, map[string]any{"module": "process", "items": []any{1, 2}})
	box.enqueue(outSnapshot, 50, map[string]any{"module": "service", "items": []any{}})
	if box.pending() != 2 {
		t.Fatalf("同模块快照应合并，pending=%d", box.pending())
	}
	var raw []byte
	_ = box.st.db.QueryRow("SELECT payload FROM outbox WHERE coalesce_key='snapshot:process'").Scan(&raw)
	var p map[string]any
	_ = json.Unmarshal(raw, &p)
	if len(p["items"].([]any)) != 2 {
		t.Fatal("应保留最新快照")
	}
}

func TestBudgetDropsLowestPriorityFirst(t *testing.T) {
	oldRows := outboxMaxRows
	outboxMaxRows = 20
	defer func() { outboxMaxRows = oldRows }()
	box := newOutbox(t.TempDir())
	defer box.st.close()
	for i := 0; i < 10; i++ {
		box.enqueue(outAck, 100, map[string]any{"i": i})
	}
	for i := 0; i < 30; i++ {
		box.enqueue(outTimeline, 80, map[string]any{"i": i})
	}
	if box.pending() > 20 {
		t.Fatalf("超预算未收敛 pending=%d", box.pending())
	}
	var acks int
	_ = box.st.db.QueryRow("SELECT COUNT(*) FROM outbox WHERE kind='ack'").Scan(&acks)
	if acks != 10 {
		t.Fatalf("高优先级事件不应被丢弃, ack=%d", acks)
	}
	if box.dropped.Load() == 0 {
		t.Fatal("应记录丢弃计数")
	}
}

func TestFallsBackToV1WhenServerLacksV2(t *testing.T) {
	f, srv := newFake()
	defer srv.Close()
	box, api := testBox(t, t.TempDir(), srv.URL)
	box.useV2.Store(true)
	f.v2Status = 404
	box.enqueue(outEvent, 90, map[string]any{"agent_id": "aid", "module": "m", "severity": "high", "title": "t", "detail": "d"})
	n := box.flush(api) // 探测到 404 后同一轮内回落 v1 并发完
	if box.useV2.Load() {
		t.Fatal("应回落 v1")
	}
	if n != 1 || f.legacy != 1 || box.pending() != 0 {
		t.Fatalf("legacy n=%d legacy=%d pending=%d", n, f.legacy, box.pending())
	}
}

func TestLegacyQueueImport(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "outbox"), 0700)
	old := `[{"id":"1","kind":"event","priority":90,"payload":{"title":"old"},"tries":0},
	         {"id":"2","kind":"ack","priority":100,"payload":{"id":"c1","ok":true}}]`
	_ = os.WriteFile(filepath.Join(dir, "outbox", "queue.json"), []byte(old), 0600)
	box := newOutbox(dir)
	defer box.st.close()
	if box.pending() != 2 {
		t.Fatalf("导入旧队列失败 pending=%d", box.pending())
	}
	if _, err := os.Stat(filepath.Join(dir, "outbox", "queue.json")); err == nil {
		t.Fatal("导入后应改名，避免重复导入")
	}
}

func TestCommandReceipts(t *testing.T) {
	box := newOutbox(t.TempDir())
	defer box.st.close()
	if box.cmdReceipt("c1") != nil {
		t.Fatal("未执行不应有回执")
	}
	box.cmdBegin("c1", "kill_process")
	if rc := box.cmdReceipt("c1"); rc == nil || rc.Status != "started" {
		t.Fatalf("started 回执缺失: %+v", rc)
	}
	box.cmdFinish("c1", true, map[string]any{"killed": true})
	rc := box.cmdReceipt("c1")
	if rc.Status != "done" || !rc.OK || rc.Result["killed"] != true {
		t.Fatalf("done 回执错误: %+v", rc)
	}
	if !nonIdempotentAction("upgrade") || nonIdempotentAction("kill_process") {
		t.Fatal("幂等性分类错误")
	}
	if !commandExpired("2000-01-01T00:00:00") || commandExpired("") || commandExpired("2999-01-01T00:00:00") {
		t.Fatal("deadline 判断错误")
	}
}

func TestSecretProtectRoundTrip(t *testing.T) {
	blob, err := protectSecret("fa_supersecret")
	if err != nil || blob == "" || blob == "fa_supersecret" {
		t.Fatalf("protect: %q %v", blob, err)
	}
	got, err := unprotectSecret(blob)
	if err != nil || got != "fa_supersecret" {
		t.Fatalf("unprotect: %q %v", got, err)
	}
	if _, err := unprotectSecret("dpapi:!!!"); err == nil {
		t.Fatal("损坏的密文应报错")
	}
}

func TestConfigSecretNeverStoredPlain(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.json")
	_ = os.WriteFile(p, []byte(`{"server_url":"http://x","token":"enroll-key-xxxxxxxx"}`), 0600)
	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := protectSecret("fa_plain_should_not_appear")
	cfg.SecretBlob, cfg.AgentID = blob, "aid1"
	if err := cfg.saveAgentID(p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) == "" || contains(string(b), "fa_plain_should_not_appear") {
		t.Fatal("明文凭据不应写入 agent.json")
	}
	cfg2, _ := loadConfigFile(p)
	if cfg2.Secret != "fa_plain_should_not_appear" {
		t.Fatalf("重载后应能解出凭据: %q", cfg2.Secret)
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestHealthSnapshotShape(t *testing.T) {
	box := newOutbox(t.TempDir())
	defer box.st.close()
	box.enqueue(outEvent, 90, map[string]any{"x": 1})
	h := newHealthCollector()
	snap := h.snapshot(box)
	for _, k := range []string{"cpu_pct", "rss_mb", "goroutines", "uptime_sec", "outbox", "build_id"} {
		if _, ok := snap[k]; !ok {
			t.Fatalf("健康快照缺少 %s", k)
		}
	}
	if snap["outbox"].(outboxStats).Depth != 1 {
		t.Fatal("outbox 深度应为 1")
	}
	// 必须可 JSON 序列化（随心跳上报）
	if _, err := json.Marshal(snap); err != nil {
		t.Fatal(err)
	}
}
