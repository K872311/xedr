package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 进程实体：boot_id + pid + 创建时间（FILETIME，100ns）唯一确定一个进程实例。
// PID 会被系统复用；进程退出后保留一段时间"墓碑"，让迟到的网络/DNS/文件事件仍能归到正确实例。

const (
	ftPerSec           = int64(10_000_000)
	entityStartSlack   = 2 * ftPerSec // ETW 事件时间与真实创建时间的容差
	entityExitGrace    = 5 * ftPerSec // 退出后仍可能到达的迟到事件
	entityTombstoneTTL = 15 * time.Minute
	entityMaxPerPID    = 4
	entityMaxTotal     = 50000
)

var procEntities = newEntityTable(currentBootID(), lookupProcInfo)

type procInfo struct {
	Start int64
	PPID  uint32
	Name  string
	Image string
}

type procEntity struct {
	ID       string
	ParentID string
	PID      uint32
	PPID     uint32
	Start    int64
	Exit     int64
	ExitCode uint32
	Name     string
	Image    string
	Approx   bool // Start 由事件时间估算（进程已退出，拿不到真实创建时间）
	goneAt   time.Time
	SigLoaded  bool
	SigKnown   bool
	SigTrusted bool
	SigStatus  string
	SigSigner  string
	CommandLine string
	User        string
}

type entityTable struct {
	mu     sync.Mutex
	boot   string
	byPID  map[uint32][]*procEntity
	byID   map[string]*procEntity
	lookup func(pid uint32) (procInfo, bool)
	now    func() time.Time
	rev    atomic.Uint64
}

func newEntityTable(boot string, lookup func(uint32) (procInfo, bool)) *entityTable {
	if lookup == nil {
		lookup = func(uint32) (procInfo, bool) { return procInfo{}, false }
	}
	return &entityTable{
		boot: boot, byPID: map[uint32][]*procEntity{}, byID: map[string]*procEntity{},
		lookup: lookup, now: time.Now,
	}
}

func entityID(boot string, pid uint32, start int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", boot, pid, start)))
	return hex.EncodeToString(h[:8])
}

func filetimeOf(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()/100 + 116444736000000000
}

func timeOfFiletime(ft int64) time.Time {
	if ft <= 0 {
		return time.Time{}
	}
	return time.Unix(0, (ft-116444736000000000)*100)
}

func absI64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// onStart 登记新进程。start 为真实创建时间时 approx=false。
func (t *entityTable) onStart(pid, ppid uint32, start int64, name, image string, approx bool) (*procEntity, bool) {
	if pid == 0 {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.startLocked(pid, ppid, start, name, image, approx)
}

func (t *entityTable) startLocked(pid, ppid uint32, start int64, name, image string, approx bool) (*procEntity, bool) {
	list := t.byPID[pid]
	for _, e := range list {
		if absI64(e.Start-start) <= entityStartSlack {
			if e.Name == "" {
				e.Name = name
			}
			if e.Image == "" {
				e.Image = image
			}
			if e.PPID == 0 && ppid != 0 {
				e.PPID = ppid
				if p := t.resolveLocked(ppid, e.Start); p != nil {
					e.ParentID = p.ID
				}
			}
			return e, false
		}
	}
	// 同 PID 仍"存活"的旧实例必然已退出（PID 复用）
	for _, e := range list {
		if e.Exit == 0 && e.Start < start {
			e.Exit = start
			e.goneAt = t.now()
		}
	}
	e := &procEntity{
		ID: entityID(t.boot, pid, start), PID: pid, PPID: ppid, Start: start,
		Name: name, Image: image, Approx: approx,
	}
	if ppid != 0 {
		if p := t.resolveLocked(ppid, start); p != nil {
			e.ParentID = p.ID
		}
	}
	list = append(list, e)
	if len(list) > entityMaxPerPID {
		drop := list[0]
		delete(t.byID, drop.ID)
		list = list[1:]
	}
	t.byPID[pid] = list
	t.byID[e.ID] = e
	return e, true
}

// onExit 把 pid 对应的存活实例转为墓碑。
func (t *entityTable) onExit(pid uint32, at int64, code uint32) *procEntity {
	t.mu.Lock()
	defer t.mu.Unlock()
	list := t.byPID[pid]
	for i := len(list) - 1; i >= 0; i-- {
		e := list[i]
		if e.Exit == 0 && (at == 0 || e.Start <= at+entityStartSlack) {
			if at == 0 {
				at = filetimeOf(t.now())
			}
			e.Exit, e.ExitCode, e.goneAt = at, code, t.now()
			return e
		}
	}
	return nil
}

func (t *entityTable) resolveLocked(pid uint32, at int64) *procEntity {
	list := t.byPID[pid]
	for i := len(list) - 1; i >= 0; i-- {
		e := list[i]
		if at == 0 {
			if e.Exit == 0 {
				return e
			}
			continue
		}
		if e.Start <= at+entityStartSlack && (e.Exit == 0 || at <= e.Exit+entityExitGrace) {
			return e
		}
	}
	return nil
}

// resolve 找出 at 时刻持有该 PID 的进程实例；未知时尝试查询现存进程补登记。
func (t *entityTable) resolve(pid uint32, at int64) *procEntity {
	if pid == 0 {
		return nil
	}
	t.mu.Lock()
	if e := t.resolveLocked(pid, at); e != nil {
		t.mu.Unlock()
		return e
	}
	t.mu.Unlock()
	info, ok := t.lookup(pid)
	if !ok || info.Start == 0 {
		return nil
	}
	// 现存进程比事件还晚创建：说明事件属于已退出的旧实例，无法可靠归属
	if at != 0 && info.Start > at+entityStartSlack {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, _ := t.startLocked(pid, info.PPID, info.Start, info.Name, info.Image, false)
	return e
}

func (t *entityTable) get(id string) *procEntity {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.byID[id]
}

// annotate 给事件 detail 写入 entity_id / parent_entity_id。
func (t *entityTable) annotate(detail map[string]any, at int64) *procEntity {
	if t == nil || detail == nil {
		return nil
	}
	if s := asString(detail["entity_id"]); s != "" {
		return t.get(s)
	}
	pid := asInt(detail["pid"])
	if pid <= 0 {
		return nil
	}
	e := t.resolve(uint32(pid), at)
	if e == nil {
		return nil
	}
	detail["entity_id"] = e.ID
	if e.ParentID != "" && asString(detail["parent_entity_id"]) == "" {
		detail["parent_entity_id"] = e.ParentID
	}
	return e
}

// markExited 把指定实例标为退出（快照差分发现进程消失时使用，避免按 PID 误伤复用后的新进程）。
func (t *entityTable) markExited(id string, at int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.byID[id]
	if e == nil || e.Exit != 0 {
		return
	}
	if at == 0 {
		at = filetimeOf(t.now())
	}
	e.Exit, e.goneAt = at, t.now()
}

// fieldsOf 加锁读取实体字段（ParentID 等可能被并发补全）。
func (t *entityTable) fieldsOf(e *procEntity) map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	return entityFields(t.boot, e)
}

// gc 清理过期墓碑；alive 非空时把已不存在的 PID 标为退出（ETW 丢 ProcessStop 的兜底）。
func (t *entityTable) gc(alive map[uint32]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	total := 0
	for pid, list := range t.byPID {
		keep := list[:0]
		for _, e := range list {
			if e.Exit == 0 && alive != nil && !alive[pid] {
				e.Exit, e.goneAt = filetimeOf(now), now
			}
			if e.Exit != 0 && now.Sub(e.goneAt) > entityTombstoneTTL {
				delete(t.byID, e.ID)
				continue
			}
			keep = append(keep, e)
		}
		if len(keep) == 0 {
			delete(t.byPID, pid)
		} else {
			t.byPID[pid] = keep
			total += len(keep)
		}
	}
	if total > entityMaxTotal {
		for pid, list := range t.byPID {
			if list[len(list)-1].Exit != 0 {
				for _, e := range list {
					delete(t.byID, e.ID)
				}
				delete(t.byPID, pid)
				total -= len(list)
				if total <= entityMaxTotal*9/10 {
					break
				}
			}
		}
	}
}

func (t *entityTable) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byID)
}

func (t *entityTable) revision() uint64 {
	if t == nil {
		return 0
	}
	return t.rev.Load()
}

// applyCmdLine 命令行迟到回填时更新实体，供前端 entities_rev 与进程 DB 同步。
func (t *entityTable) applyCmdLine(pid uint32, at int64, cmd, user string) {
	cmd = strings.TrimSpace(cmd)
	user = strings.TrimSpace(user)
	if t == nil || pid == 0 || (cmd == "" && user == "") {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.resolveLocked(pid, at)
	if e == nil {
		return
	}
	changed := false
	if cmd != "" && e.CommandLine != cmd {
		e.CommandLine, changed = cmd, true
	}
	if user != "" && e.User != user {
		e.User, changed = user, true
	}
	if changed {
		t.rev.Add(1)
	}
}

// bestRecentUserProcess：RegNotify 等无 PID 回调时，用最近启动的非 System32 进程作启发式写入者（非 100% 准确）。
func (t *entityTable) bestRecentUserProcess(within time.Duration) *procEntity {
	if t == nil || within <= 0 {
		return nil
	}
	cutoff := t.now().Add(-within)
	t.mu.Lock()
	defer t.mu.Unlock()
	var best *procEntity
	for _, e := range t.byID {
		if e == nil || e.Exit != 0 || e.Approx {
			continue
		}
		st := timeOfFiletime(e.Start)
		if st.IsZero() || st.Before(cutoff) {
			continue
		}
		img := strings.ToLower(strings.TrimSpace(e.Image))
		if img != "" && (strings.Contains(img, `\windows\system32\`) || strings.Contains(img, `\windows\syswow64\`)) {
			continue
		}
		if best == nil || e.Start > best.Start {
			best = e
		}
	}
	return best
}

// entityFields 进程创建/退出事件统一携带的实体字段。
func entityFields(boot string, e *procEntity) map[string]any {
	if e == nil {
		return nil
	}
	m := map[string]any{
		"entity_id": e.ID, "boot_id": boot, "create_time_100ns": e.Start,
	}
	if e.ParentID != "" {
		m["parent_entity_id"] = e.ParentID
	}
	if e.Approx {
		m["create_time_approx"] = true
	}
	if e.CommandLine != "" {
		m["command_line"] = e.CommandLine
	}
	if e.User != "" {
		m["user"] = e.User
	}
	return m
}

func mergeInto(dst, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}

// parseLocalTS 把时间线 ts（本地时间，秒级）转为 FILETIME；失败返回 0（按"当前存活"归属）。
func parseLocalTS(ts string) int64 {
	if ts == "" {
		return 0
	}
	for _, layout := range []string{"2006-01-02T15:04:05", time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if tm, err := time.ParseInLocation(layout, ts, time.Local); err == nil {
			// 秒级时间戳：取该秒末尾，避免同秒内创建的进程被判为"晚于事件"
			if layout == "2006-01-02T15:04:05" || layout == "2006-01-02 15:04:05" {
				tm = tm.Add(999 * time.Millisecond)
			}
			return filetimeOf(tm)
		}
	}
	return 0
}
