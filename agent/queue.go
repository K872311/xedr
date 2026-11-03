package main

import (
	"context"
	crand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 可靠 outbox：先落盘（SQLite WAL）再异步发送，ACK 后才删除。
//   - 每条事件有稳定 uuid（重试不变），服务端 v2 接口按 uuid 幂等；
//   - 按优先级/序号分批发送；失败按次数指数退避，网络不通整体退避；
//   - 预算：行数/字节数超限时先丢最低优先级最旧的并计数，绝不阻塞采集；
//   - snapshot 按 module 合并：同模块旧快照被新快照取代，避免离线期间堆积。
type outboxKind string

const (
	outTimeline outboxKind = "timeline"
	outEvent    outboxKind = "event"
	outSnapshot outboxKind = "snapshot"
	outAck      outboxKind = "ack"
	// 增量清单：不能合并（必须按代号链式应用），全量入队时清掉同模块未发出的增量
	outSnapshotDelta outboxKind = "snapshot_delta"
)

// 预算为变量仅为便于测试；生产值见默认。
var (
	outboxMaxRows  int64 = 100_000
	outboxMaxBytes int64 = 256 << 20
)

const (
	batchMaxEvents = 100
	batchMaxBytes  = 1 << 20
	outboxStream   = "main"
)

type outbox struct {
	st *stateDB

	flushMu sync.Mutex
	kickCh  chan struct{}

	mu            sync.Mutex // 保护下面的近似计数与退避状态
	rows          int64
	bytes         int64
	netFails      int
	netBackoffEnd time.Time
	lastErr       string
	lastOKAt      time.Time

	enq, sent, rejected, dropped atomic.Int64
	useV2                        atomic.Bool
	// onReject 服务端永久拒绝某条事件时回调（增量清单据此回退全量）
	onReject func(kind outboxKind, payload map[string]any, msg string)
}

func newOutbox(stateDir string) *outbox {
	_ = os.MkdirAll(stateDir, 0700)
	st, err := openStateDB(stateDir)
	if err != nil {
		// 不能让 Agent 因本地库打不开而停摆：退化为内存库（不持久，但仍可上报）
		log.Printf("state db 打开失败，降级为内存 outbox: %v", err)
		st = memoryStateDB()
	}
	o := &outbox{st: st, kickCh: make(chan struct{}, 1)}
	o.resync()
	o.importLegacy(filepath.Join(stateDir, "outbox", "queue.json"))
	return o
}

func memoryStateDB() *stateDB {
	db, _ := sqlOpenMemory()
	s := &stateDB{db: db, path: ":memory:"}
	_ = s.migrate()
	return s
}

func newUUID() string {
	var b [16]byte
	_, _ = crand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (o *outbox) resync() {
	var n, b int64
	_ = o.st.db.QueryRow("SELECT COUNT(*), COALESCE(SUM(bytes),0) FROM outbox").Scan(&n, &b)
	o.mu.Lock()
	o.rows, o.bytes = n, b
	o.mu.Unlock()
}

// importLegacy 一次性导入旧版 JSON 队列，导入后改名防止重复导入。
func (o *outbox) importLegacy(path string) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return
	}
	var items []struct {
		Kind     outboxKind     `json:"kind"`
		Priority int            `json:"priority"`
		Payload  map[string]any `json:"payload"`
	}
	if json.Unmarshal(b, &items) == nil {
		for _, it := range items {
			o.enqueue(it.Kind, it.Priority, it.Payload)
		}
		log.Printf("outbox: 已导入旧队列 %d 条", len(items))
	}
	_ = os.Rename(path, path+".migrated")
}

func coalesceKey(kind outboxKind, payload map[string]any) string {
	m, _ := payload["module"].(string)
	if m == "" {
		return ""
	}
	switch kind {
	case outSnapshot:
		return "snapshot:" + m
	case outSnapshotDelta:
		return "delta:" + m + ":" + asString(payload["generation"])
	}
	return ""
}

func (o *outbox) enqueue(kind outboxKind, priority int, payload map[string]any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	now := time.Now().UnixMilli()
	ck := coalesceKey(kind, payload)
	tx, err := o.st.db.Begin()
	if err != nil {
		log.Printf("outbox enqueue: %v", err)
		return
	}
	var delRows, delBytes int64
	if ck != "" {
		_ = tx.QueryRow("SELECT COUNT(*), COALESCE(SUM(bytes),0) FROM outbox WHERE coalesce_key=?", ck).Scan(&delRows, &delBytes)
		_, _ = tx.Exec("DELETE FROM outbox WHERE coalesce_key=?", ck)
	}
	if kind == outSnapshot && ck != "" {
		// 新全量取代同模块所有未发出的增量
		pat := "delta:" + strings.TrimPrefix(ck, "snapshot:") + ":%"
		var r2, b2 int64
		_ = tx.QueryRow("SELECT COUNT(*), COALESCE(SUM(bytes),0) FROM outbox WHERE coalesce_key LIKE ?", pat).Scan(&r2, &b2)
		_, _ = tx.Exec("DELETE FROM outbox WHERE coalesce_key LIKE ?", pat)
		delRows, delBytes = delRows+r2, delBytes+b2
	}
	if _, err := tx.Exec(
		`INSERT INTO outbox(uuid, stream, kind, priority, coalesce_key, payload, bytes, available_at, created_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		newUUID(), outboxStream, string(kind), priority, ck, raw, len(raw), now, now,
	); err != nil {
		_ = tx.Rollback()
		log.Printf("outbox enqueue: %v", err)
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("outbox enqueue commit: %v", err)
		return
	}
	o.enq.Add(1)
	o.mu.Lock()
	o.rows += 1 - delRows
	o.bytes += int64(len(raw)) - delBytes
	over := o.rows > outboxMaxRows || o.bytes > outboxMaxBytes
	o.mu.Unlock()
	if over {
		o.enforceBudget()
	}
	o.kick()
}

// enforceBudget 丢弃最低优先级、最旧的事件直到回到预算的 90%。
func (o *outbox) enforceBudget() {
	for i := 0; i < 200; i++ {
		o.mu.Lock()
		overRows := o.rows - outboxMaxRows*9/10
		overBytes := o.bytes > outboxMaxBytes*9/10
		o.mu.Unlock()
		if overRows <= 0 && !overBytes {
			return
		}
		// 行数超限按需精确丢弃；仅字节超限则小步丢弃后重新核算
		chunk := int64(25)
		if overRows > 0 {
			chunk = min(overRows, 500)
		}
		res, err := o.st.db.Exec(
			`DELETE FROM outbox WHERE seq IN (SELECT seq FROM outbox ORDER BY priority ASC, seq ASC LIMIT ?)`, chunk)
		if err != nil {
			return
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return
		}
		o.dropped.Add(n)
		o.resync()
	}
}

func (o *outbox) kick() {
	select {
	case o.kickCh <- struct{}{}:
	default:
	}
}

// run 后台发送循环：被 kick 或每 2 秒触发一次 flush。
func (o *outbox) run(ctx context.Context, api *APIClient) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-o.kickCh:
		case <-t.C:
		}
		if n := o.flush(api); n > 0 {
			log.Printf("outbox sent %d (pending=%d)", n, o.pending())
		}
	}
}

type readyRow struct {
	seq      int64
	uuid     string
	kind     outboxKind
	priority int
	payload  []byte
	attempt  int
	created  int64
}

func (o *outbox) fetchReady() []readyRow {
	now := time.Now().UnixMilli()
	rows, err := o.st.db.Query(
		`SELECT seq, uuid, kind, priority, payload, attempt, created_at FROM outbox
		 WHERE available_at<=? ORDER BY priority DESC, seq ASC LIMIT ?`, now, batchMaxEvents)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []readyRow
	var total int
	for rows.Next() {
		var r readyRow
		var k string
		if err := rows.Scan(&r.seq, &r.uuid, &k, &r.priority, &r.payload, &r.attempt, &r.created); err != nil {
			continue
		}
		r.kind = outboxKind(k)
		if len(out) > 0 && total+len(r.payload) > batchMaxBytes {
			break
		}
		total += len(r.payload)
		out = append(out, r)
	}
	return out
}

func (o *outbox) deleteSeqs(seqs []int64) {
	if len(seqs) == 0 {
		return
	}
	tx, err := o.st.db.Begin()
	if err != nil {
		return
	}
	for _, s := range seqs {
		_, _ = tx.Exec("DELETE FROM outbox WHERE seq=?", s)
	}
	_ = tx.Commit()
	o.resync()
}

func (o *outbox) bumpAttempt(seqs []int64, attempt map[int64]int) {
	tx, err := o.st.db.Begin()
	if err != nil {
		return
	}
	for _, s := range seqs {
		n := attempt[s] + 1
		_, _ = tx.Exec("UPDATE outbox SET attempt=?, available_at=? WHERE seq=?",
			n, time.Now().Add(retryDelay(n)).UnixMilli(), s)
	}
	_ = tx.Commit()
}

func retryDelay(attempt int) time.Duration {
	d := 2 * time.Second
	for i := 1; i < attempt && d < 5*time.Minute; i++ {
		d *= 2
	}
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	return d + time.Duration(rand.Int64N(int64(d/4)+1))
}

func (o *outbox) netBackoff() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return time.Now().Before(o.netBackoffEnd)
}

func (o *outbox) markNetFail(err error) {
	o.mu.Lock()
	o.netFails++
	d := time.Duration(1<<min(o.netFails, 6)) * time.Second // 2,4,...64s
	o.netBackoffEnd = time.Now().Add(d)
	o.lastErr = err.Error()
	o.mu.Unlock()
}

func (o *outbox) markOK() {
	o.mu.Lock()
	o.netFails = 0
	o.netBackoffEnd = time.Time{}
	o.lastErr = ""
	o.lastOKAt = time.Now()
	o.mu.Unlock()
}

// flush 单飞：把到期事件分批发出，返回本轮已确认条数。
func (o *outbox) flush(api *APIClient) int {
	o.flushMu.Lock()
	defer o.flushMu.Unlock()
	if o.netBackoff() {
		return 0
	}
	total := 0
	for round := 0; round < 30; round++ {
		rows := o.fetchReady()
		if len(rows) == 0 {
			break
		}
		var n int
		var err error
		if o.useV2.Load() {
			n, err = o.sendV2(api, rows)
		} else {
			n, err = o.sendLegacy(api, rows)
		}
		total += n
		if err != nil {
			o.markNetFail(err)
			break
		}
		o.markOK()
	}
	return total
}

func (o *outbox) sendV2(api *APIClient, rows []readyRow) (int, error) {
	events := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		var payload map[string]any
		if json.Unmarshal(r.payload, &payload) != nil {
			payload = map[string]any{}
		}
		events = append(events, map[string]any{
			"uuid": r.uuid, "seq": r.seq, "kind": string(r.kind),
			"ts": time.UnixMilli(r.created).Format("2006-01-02T15:04:05"), "payload": payload,
		})
	}
	resp, err := api.SendBatch(outboxStream, events)
	if err != nil {
		if isV2Unsupported(err) { // 老服务端：回落 v1，不当作网络故障
			log.Printf("服务端不支持 v2 批量上报，回落 v1: %v", err)
			o.useV2.Store(false)
			return 0, nil
		}
		return 0, err
	}
	ackSet := map[string]bool{}
	for _, u := range resp.Acked {
		ackSet[u] = true
	}
	rejSet := map[string]string{}
	for _, r := range resp.Rejected {
		rejSet[r.UUID] = r.Error
	}
	if o.onReject != nil && len(rejSet) > 0 {
		for i, r := range rows {
			if msg, ok := rejSet[r.uuid]; ok {
				o.onReject(r.kind, events[i]["payload"].(map[string]any), msg)
			}
		}
	}
	var done []int64
	var retry []int64
	attempts := map[int64]int{}
	for _, r := range rows {
		if ackSet[r.uuid] {
			done = append(done, r.seq)
		} else if msg, ok := rejSet[r.uuid]; ok {
			log.Printf("outbox 事件被服务端永久拒绝 kind=%s: %s", r.kind, msg)
			o.rejected.Add(1)
			done = append(done, r.seq) // 毒丸：丢弃，避免阻塞队列
		} else {
			retry = append(retry, r.seq)
			attempts[r.seq] = r.attempt
		}
	}
	o.deleteSeqs(done)
	o.bumpAttempt(retry, attempts)
	o.sent.Add(int64(len(done)))
	return len(done), nil
}

func (o *outbox) sendLegacy(api *APIClient, rows []readyRow) (int, error) {
	n := 0
	for _, r := range rows {
		var payload map[string]any
		_ = json.Unmarshal(r.payload, &payload)
		if r.kind == outSnapshotDelta {
			// v1 不支持增量：丢弃并让清单下一轮发全量
			if o.onReject != nil {
				o.onReject(r.kind, payload, "v1 不支持增量清单")
			}
			o.deleteSeqs([]int64{r.seq})
			continue
		}
		if err := sendLegacyOne(api, r.kind, payload); err != nil {
			o.bumpAttempt([]int64{r.seq}, map[int64]int{r.seq: r.attempt})
			return n, err
		}
		o.deleteSeqs([]int64{r.seq})
		o.sent.Add(1)
		n++
	}
	return n, nil
}

func sendLegacyOne(api *APIClient, kind outboxKind, p map[string]any) error {
	switch kind {
	case outTimeline:
		aid, _ := p["agent_id"].(string)
		hn, _ := p["hostname"].(string)
		raw, _ := p["events"].([]any)
		events := make([]map[string]any, 0, len(raw))
		for _, e := range raw {
			if m, ok := e.(map[string]any); ok {
				events = append(events, m)
			}
		}
		return api.Timeline(aid, hn, events)
	case outEvent:
		aid, _ := p["agent_id"].(string)
		mod, _ := p["module"].(string)
		sev, _ := p["severity"].(string)
		title, _ := p["title"].(string)
		detail, _ := p["detail"].(string)
		return api.Event(aid, mod, sev, title, detail)
	case outSnapshot:
		aid, _ := p["agent_id"].(string)
		mod, _ := p["module"].(string)
		at, _ := p["collected_at"].(string)
		dig, _ := p["digest"].(string)
		raw, _ := p["items"].([]any)
		return api.Snapshot(aid, mod, at, dig, raw)
	case outAck:
		id, _ := p["id"].(string)
		okv, _ := p["ok"].(bool)
		res, _ := p["result"].(map[string]any)
		return api.AckCommand(id, okv, res)
	}
	return nil
}

func (o *outbox) pending() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return int(o.rows)
}

// outboxStats 供心跳健康上报。
type outboxStats struct {
	Depth     int64   `json:"depth"`
	Bytes     int64   `json:"bytes"`
	OldestSec float64 `json:"oldest_age_sec"`
	Dropped   int64   `json:"dropped"`
	Rejected  int64   `json:"rejected"`
	Enqueued  int64   `json:"enqueued"`
	Sent      int64   `json:"sent"`
	LastError string  `json:"last_error,omitempty"`
	LastOKAge float64 `json:"last_ok_age_sec"`
	V2        bool    `json:"v2"`
	MaxRows   int64   `json:"max_rows"`
	MaxBytes  int64   `json:"max_bytes"`
	ByKind    map[string]int64 `json:"by_kind,omitempty"`
}

func (o *outbox) stats() outboxStats {
	var oldest sql.NullInt64
	_ = o.st.db.QueryRow("SELECT MIN(created_at) FROM outbox").Scan(&oldest)
	o.mu.Lock()
	defer o.mu.Unlock()
	s := outboxStats{
		Depth: o.rows, Bytes: o.bytes, Dropped: o.dropped.Load(), Rejected: o.rejected.Load(),
		Enqueued: o.enq.Load(), Sent: o.sent.Load(), LastError: o.lastErr, V2: o.useV2.Load(),
		MaxRows: outboxMaxRows, MaxBytes: outboxMaxBytes,
	}
	if oldest.Valid {
		s.OldestSec = float64(time.Now().UnixMilli()-oldest.Int64) / 1000
	}
	if !o.lastOKAt.IsZero() {
		s.LastOKAge = time.Since(o.lastOKAt).Seconds()
	}
	s.ByKind = o.statsByKind()
	return s
}

func (o *outbox) statsByKind() map[string]int64 {
	rows, err := o.st.db.Query("SELECT kind, COUNT(*) FROM outbox GROUP BY kind")
	if err != nil {
		return nil
	}
	defer rows.Close()
	m := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if rows.Scan(&k, &n) == nil {
			m[k] = n
		}
	}
	return m
}
