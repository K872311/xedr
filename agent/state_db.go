package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "modernc.org/sqlite" // 纯 Go SQLite，无需 CGO
)

// stateDB 是 Agent 本地持久状态：可靠 outbox、命令回执、KV。
// 使用 WAL + synchronous=NORMAL：进程崩溃不丢已提交数据，断电最多丢最后几毫秒。
type stateDB struct {
	db   *sql.DB
	path string
}

var (
	stateMu  sync.Mutex
	stateDBs = map[string]*stateDB{}
)

// stateMigrations 按版本递增追加，禁止改动已发布的迁移。
var stateMigrations = []string{
	// v1
	`CREATE TABLE outbox (
		seq INTEGER PRIMARY KEY AUTOINCREMENT,
		uuid TEXT NOT NULL UNIQUE,
		stream TEXT NOT NULL DEFAULT 'main',
		kind TEXT NOT NULL,
		priority INTEGER NOT NULL,
		coalesce_key TEXT NOT NULL DEFAULT '',
		payload BLOB NOT NULL,
		bytes INTEGER NOT NULL,
		attempt INTEGER NOT NULL DEFAULT 0,
		available_at INTEGER NOT NULL,
		created_at INTEGER NOT NULL
	);
	CREATE INDEX outbox_ready ON outbox(priority DESC, seq);
	CREATE INDEX outbox_coalesce ON outbox(coalesce_key) WHERE coalesce_key <> '';
	CREATE TABLE cmd_receipts (
		id TEXT PRIMARY KEY,
		action TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'started',
		ok INTEGER NOT NULL DEFAULT 0,
		result BLOB,
		started_at INTEGER NOT NULL,
		done_at INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);`,
	// v2：FIM 基线（k 为小写路径）
	`CREATE TABLE fim_baseline (
		k TEXT PRIMARY KEY,
		path TEXT NOT NULL,
		size INTEGER NOT NULL,
		mtime INTEGER NOT NULL,
		sha256 TEXT NOT NULL DEFAULT '',
		updated_at INTEGER NOT NULL
	);`,
}

func stateDBPath(stateDir string) string {
	return filepath.Join(stateDir, "state", "agent_state.db")
}

func openStateDB(stateDir string) (*stateDB, error) {
	path := stateDBPath(stateDir)
	stateMu.Lock()
	defer stateMu.Unlock()
	if s, ok := stateDBs[path]; ok {
		return s, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// 单连接：写入串行化，避免 SQLITE_BUSY；读写都很轻
	db.SetMaxOpenConns(1)
	s := &stateDB{db: db, path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		// 库损坏：改名保留证据后重建，保证 Agent 仍能工作
		if isCorrupt(err) {
			bad := path + ".corrupt"
			_ = os.Remove(bad)
			_ = os.Rename(path, bad)
			_ = os.Remove(path + "-wal")
			_ = os.Remove(path + "-shm")
			db2, err2 := sql.Open("sqlite", dsn)
			if err2 != nil {
				return nil, err2
			}
			db2.SetMaxOpenConns(1)
			s = &stateDB{db: db2, path: path}
			if err3 := s.migrate(); err3 != nil {
				return nil, err3
			}
			stateDBs[path] = s
			return s, nil
		}
		return nil, err
	}
	stateDBs[path] = s
	return s, nil
}

func sqlOpenMemory() (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file::memory:")
	if err == nil {
		db.SetMaxOpenConns(1)
	}
	return db, err
}

func isCorrupt(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "malformed") || strings.Contains(m, "not a database") || strings.Contains(m, "corrupt")
}

func (s *stateDB) migrate() error {
	var cur int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&cur); err != nil {
		return err
	}
	for i := cur; i < len(stateMigrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(stateMigrations[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("state migration v%d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version=%d", i+1)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *stateDB) close() {
	stateMu.Lock()
	defer stateMu.Unlock()
	delete(stateDBs, s.path)
	_ = s.db.Close()
}

func (s *stateDB) kvGet(k string) string {
	var v string
	_ = s.db.QueryRow("SELECT v FROM kv WHERE k=?", k).Scan(&v)
	return v
}

func (s *stateDB) kvSet(k, v string) {
	_, _ = s.db.Exec("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", k, v)
}
