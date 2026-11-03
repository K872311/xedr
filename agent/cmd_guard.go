package main

import (
	"encoding/json"
	"time"
)

// 命令执行防重：服务端 lease 过期会重投同一个命令 ID（Agent 崩溃/ACK 丢失时）。
// Agent 在本地 SQLite 记录回执：已完成的只重放 ACK，不重复执行；
// 执行到一半崩溃的“非幂等动作”不自动重跑，改为回报失败，由管理员决定。
type cmdReceipt struct {
	Status string // started | done
	OK     bool
	Result map[string]any
}

const cmdReceiptTTL = 7 * 24 * time.Hour

func (o *outbox) cmdReceipt(id string) *cmdReceipt {
	var status string
	var ok int
	var raw []byte
	err := o.st.db.QueryRow("SELECT status, ok, result FROM cmd_receipts WHERE id=?", id).Scan(&status, &ok, &raw)
	if err != nil {
		return nil
	}
	r := &cmdReceipt{Status: status, OK: ok == 1}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &r.Result)
	}
	return r
}

func (o *outbox) cmdBegin(id, action string) {
	_, _ = o.st.db.Exec(
		`INSERT INTO cmd_receipts(id, action, status, started_at) VALUES(?,?, 'started', ?)
		 ON CONFLICT(id) DO NOTHING`, id, action, time.Now().UnixMilli())
}

func (o *outbox) cmdFinish(id string, ok bool, result map[string]any) {
	raw, _ := json.Marshal(result)
	okv := 0
	if ok {
		okv = 1
	}
	_, _ = o.st.db.Exec(
		`UPDATE cmd_receipts SET status='done', ok=?, result=?, done_at=? WHERE id=?`,
		okv, raw, time.Now().UnixMilli(), id)
}

func (o *outbox) cmdPurge() {
	_, _ = o.st.db.Exec("DELETE FROM cmd_receipts WHERE started_at<?", time.Now().Add(-cmdReceiptTTL).UnixMilli())
}

// nonIdempotentAction：中途崩溃后重跑可能造成副作用叠加的动作。
func nonIdempotentAction(action string) bool {
	switch action {
	case "upgrade", "rollback_upgrade", "uninstall_agent", "restore_file", "quarantine_file":
		return true
	}
	return false
}

func commandExpired(deadline string) bool {
	if deadline == "" {
		return false
	}
	t, err := time.ParseInLocation("2006-01-02T15:04:05", deadline, time.Local)
	if err != nil {
		return false
	}
	return time.Now().After(t)
}
