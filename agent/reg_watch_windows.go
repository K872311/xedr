//go:build windows

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	regNotifyName           = 0x1
	regNotifyLastSet        = 0x4
	regNotifyThreadAgnostic = 0x10000000
	regDebounce             = 300 * time.Millisecond
	regMaxEntries           = 20000
	regBaselineKV           = "regwatch:v1"
)

var userSIDRe = regexp.MustCompile(`^S-1-5-21-[0-9-]+$`)

type regWatch struct {
	spec    regSpec
	key     registry.Key
	event   windows.Handle
	snap    map[string]regValue
	dirty   time.Time
	lastRun time.Time
}

type regWatcher struct {
	st *stateDB

	mu       sync.Mutex
	events   []map[string]any
	watches  []*regWatch
	missing  []regSpec
	users    map[string]bool
	baseline map[string]map[string]regValue // spec.ID -> 快照（持久化，用于离线对账）
	saveDue  bool
	active   bool
	stopEv   windows.Handle
	done     chan struct{}
}

func newRegWatcher(st *stateDB) *regWatcher {
	return &regWatcher{st: st, users: map[string]bool{}, baseline: map[string]map[string]regValue{}}
}

func (w *regWatcher) running() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.active
}

func (w *regWatcher) drain() []map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.events
	w.events = nil
	return out
}

func (w *regWatcher) push(ev map[string]any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, ev)
	if len(w.events) > 500 {
		w.events = w.events[len(w.events)-500:]
	}
}

func regRoot(spec regSpec) (registry.Key, string) {
	if spec.Hive == "HKU" {
		return registry.USERS, spec.SID + `\` + spec.Path
	}
	return registry.LOCAL_MACHINE, spec.Path
}

func readRegValue(k registry.Key, name string) (regValue, bool) {
	_, typ, err := k.GetValue(name, nil)
	if err != nil && err != registry.ErrShortBuffer {
		return regValue{}, false
	}
	switch typ {
	case registry.SZ, registry.EXPAND_SZ:
		s, _, e := k.GetStringValue(name)
		if e != nil {
			return regValue{}, false
		}
		return regValue{Type: map[uint32]string{registry.SZ: "REG_SZ", registry.EXPAND_SZ: "REG_EXPAND_SZ"}[typ], Data: truncate(s, 1024)}, true
	case registry.MULTI_SZ:
		ss, _, e := k.GetStringsValue(name)
		if e != nil {
			return regValue{}, false
		}
		return regValue{Type: "REG_MULTI_SZ", Data: truncate(strings.Join(ss, "|"), 1024)}, true
	case registry.DWORD, registry.QWORD:
		n, _, e := k.GetIntegerValue(name)
		if e != nil {
			return regValue{}, false
		}
		t := "REG_DWORD"
		if typ == registry.QWORD {
			t = "REG_QWORD"
		}
		return regValue{Type: t, Data: fmt.Sprintf("%d", n)}, true
	default:
		buf := make([]byte, 256)
		n, _, e := k.GetBinaryValue(name)
		if e == nil {
			buf = n
		}
		if len(buf) > 64 {
			buf = buf[:64]
		}
		return regValue{Type: fmt.Sprintf("REG_%d", typ), Data: hex.EncodeToString(buf)}, true
	}
}

// readTree 读取键及（Subtree 时）有限层子键里关注的值。
func readTree(k registry.Key, display string, spec regSpec, depth int, out map[string]regValue) {
	if len(out) >= regMaxEntries {
		return
	}
	if names, err := k.ReadValueNames(0); err == nil {
		for _, n := range names {
			if !spec.wantValue(n) {
				continue
			}
			if v, ok := readRegValue(k, n); ok {
				out[display+`\`+n] = v
			}
		}
	}
	if !spec.Subtree || depth <= 0 {
		return
	}
	subs, err := k.ReadSubKeyNames(0)
	if err != nil {
		return
	}
	for _, s := range subs {
		sk, err := registry.OpenKey(k, s, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		readTree(sk, display+`\`+s, spec, depth-1, out)
		sk.Close()
		if len(out) >= regMaxEntries {
			return
		}
	}
}

func (w *regWatcher) snapshot(rw *regWatch) map[string]regValue {
	out := map[string]regValue{}
	readTree(rw.key, rw.spec.displayRoot(), rw.spec, rw.spec.Depth, out)
	return out
}

func (w *regWatcher) open(spec regSpec) (*regWatch, error) {
	root, path := regRoot(spec)
	k, err := registry.OpenKey(root, path, registry.READ)
	if err != nil {
		return nil, err
	}
	ev, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		k.Close()
		return nil, err
	}
	rw := &regWatch{spec: spec, key: k, event: ev}
	if err := w.arm(rw); err != nil {
		k.Close()
		windows.CloseHandle(ev)
		return nil, err
	}
	return rw, nil
}

func (w *regWatcher) arm(rw *regWatch) error {
	return windows.RegNotifyChangeKeyValue(windows.Handle(rw.key), rw.spec.Subtree,
		regNotifyName|regNotifyLastSet|regNotifyThreadAgnostic, rw.event, true)
}

func (w *regWatcher) closeWatch(rw *regWatch) {
	rw.key.Close()
	windows.CloseHandle(rw.event)
}

func loadedUserSIDs() []string {
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(0)
	var out []string
	for _, n := range names {
		if userSIDRe.MatchString(n) {
			out = append(out, n)
		}
	}
	return out
}

func userHiveLoaded(sid string) bool {
	k, err := registry.OpenKey(registry.USERS, sid, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// start 建立全部订阅并做离线对账；返回 false 表示不可用（调用方保留轮询兜底）。
func (w *regWatcher) start(ctx context.Context) bool {
	stopEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return false
	}
	w.loadBaseline()
	specs := machineRegSpecs()
	for _, sid := range loadedUserSIDs() {
		w.users[sid] = true
		specs = append(specs, userRegSpecs(sid)...)
	}
	for _, s := range specs {
		w.addSpec(s, true)
	}
	w.mu.Lock()
	n := len(w.watches)
	if n == 0 {
		w.mu.Unlock()
		windows.CloseHandle(stopEv)
		return false
	}
	w.active, w.stopEv, w.done = true, stopEv, make(chan struct{})
	w.mu.Unlock()
	w.saveBaseline()
	go w.loop(ctx)
	log.Printf("regwatch: 实时订阅 %d 个注册表键（缺失待建 %d）", n, len(w.missing))
	return true
}

func (w *regWatcher) stop() {
	w.mu.Lock()
	on, ev, done := w.active, w.stopEv, w.done
	w.mu.Unlock()
	if !on {
		return
	}
	_ = windows.SetEvent(ev)
	<-done
}

// addSpec 打开并订阅；initial=true 时与持久化基线对账（离线期间的变更）。
func (w *regWatcher) addSpec(spec regSpec, initial bool) {
	rw, err := w.open(spec)
	if err != nil {
		w.mu.Lock()
		w.missing = append(w.missing, spec)
		prev := w.baseline[spec.ID]
		if len(prev) > 0 {
			w.baseline[spec.ID] = map[string]regValue{}
		}
		w.mu.Unlock()
		// 上次存在、这次整个键没了（离线期间被删）
		if initial && len(prev) > 0 {
			w.emitDiff(spec, prev, map[string]regValue{}, true)
		}
		return
	}
	rw.snap = w.snapshot(rw)
	w.mu.Lock()
	prev, had := w.baseline[spec.ID]
	w.baseline[spec.ID] = rw.snap
	w.watches = append(w.watches, rw)
	w.saveDue = true
	w.mu.Unlock()
	switch {
	case initial && had:
		w.emitDiff(spec, prev, rw.snap, true)
	case !initial:
		// 运行中新出现的键（如 UAC 绕过常用的 ms-settings 命令键）：全部视为新增
		w.emitDiff(spec, prev, rw.snap, false)
	}
}

func (w *regWatcher) emitDiff(spec regSpec, old, cur map[string]regValue, offline bool) {
	adds, mods, dels := regDiff(old, cur)
	n := 0
	for _, k := range adds {
		w.push(regEvent(spec, "add", k, cur[k], regValue{}, offline))
		n++
	}
	for _, k := range mods {
		w.push(regEvent(spec, "modify", k, cur[k], old[k], offline))
		n++
	}
	for _, k := range dels {
		w.push(regEvent(spec, "delete", k, regValue{}, old[k], offline))
		n++
	}
	if n > 0 {
		w.mu.Lock()
		w.saveDue = true
		w.mu.Unlock()
	}
}

func (w *regWatcher) loop(ctx context.Context) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(w.done)
	defer func() {
		w.mu.Lock()
		for _, rw := range w.watches {
			w.closeWatch(rw)
		}
		w.watches = nil
		w.active = false
		w.mu.Unlock()
		w.saveBaseline()
		windows.CloseHandle(w.stopEv)
	}()
	lastUsers := time.Now()
	lastSave := time.Now()
	for {
		if ctx.Err() != nil {
			return
		}
		w.mu.Lock()
		watches := append([]*regWatch(nil), w.watches...)
		w.mu.Unlock()
		// WaitForMultipleObjects 最多 64 个句柄：分组轮询，每组等待很短时间
		signaled := map[*regWatch]bool{}
		stopped := false
		groups := (len(watches) + 62) / 63
		if groups == 0 {
			groups = 1
		}
		wait := uint32(regDebounce / time.Millisecond / time.Duration(groups))
		for g := 0; g < groups; g++ {
			lo, hi := g*63, (g+1)*63
			if hi > len(watches) {
				hi = len(watches)
			}
			hs := []windows.Handle{w.stopEv}
			for _, rw := range watches[lo:hi] {
				hs = append(hs, rw.event)
			}
			r, err := windows.WaitForMultipleObjects(hs, false, wait)
			if err != nil || r == uint32(windows.WAIT_TIMEOUT) {
				continue
			}
			idx := int(r - windows.WAIT_OBJECT_0)
			if idx == 0 {
				stopped = true
				break
			}
			if idx > 0 && idx < len(hs) {
				signaled[watches[lo+idx-1]] = true
			}
		}
		if stopped {
			return
		}
		now := time.Now()
		for rw := range signaled {
			if rw.dirty.IsZero() {
				rw.dirty = now
			}
			_ = w.arm(rw)
		}
		for _, rw := range watches {
			if rw.dirty.IsZero() || now.Sub(rw.dirty) < regDebounce {
				continue
			}
			if rw.spec.MinInterval > 0 && now.Sub(rw.lastRun) < rw.spec.MinInterval {
				continue
			}
			rw.dirty, rw.lastRun = time.Time{}, now
			w.refresh(rw)
		}
		if now.Sub(lastUsers) > 30*time.Second {
			lastUsers = now
			w.refreshUsersAndMissing()
		}
		w.mu.Lock()
		due := w.saveDue
		w.mu.Unlock()
		if due && now.Sub(lastSave) > 10*time.Second {
			lastSave = now
			w.saveBaseline()
		}
	}
}

func (w *regWatcher) refresh(rw *regWatch) {
	// 键被删除或用户配置单元卸载：读不到时区分对待
	if _, err := rw.key.Stat(); err != nil {
		if rw.spec.Hive == "HKU" && !userHiveLoaded(rw.spec.SID) {
			w.dropUser(rw.spec.SID)
			return
		}
		w.emitDiff(rw.spec, rw.snap, map[string]regValue{}, false)
		w.mu.Lock()
		w.baseline[rw.spec.ID] = map[string]regValue{}
		w.removeWatchLocked(rw)
		w.missing = append(w.missing, rw.spec)
		w.mu.Unlock()
		w.closeWatch(rw)
		return
	}
	cur := w.snapshot(rw)
	old := rw.snap
	rw.snap = cur
	w.mu.Lock()
	w.baseline[rw.spec.ID] = cur
	w.mu.Unlock()
	w.emitDiff(rw.spec, old, cur, false)
}

func (w *regWatcher) removeWatchLocked(rw *regWatch) {
	for i, x := range w.watches {
		if x == rw {
			w.watches = append(w.watches[:i], w.watches[i+1:]...)
			return
		}
	}
}

// dropUser 用户注销：静默移除该用户的订阅，不当作删除事件。
func (w *regWatcher) dropUser(sid string) {
	w.mu.Lock()
	var closing []*regWatch
	keep := w.watches[:0]
	for _, rw := range w.watches {
		if rw.spec.SID == sid {
			closing = append(closing, rw)
		} else {
			keep = append(keep, rw)
		}
	}
	w.watches = keep
	miss := w.missing[:0]
	for _, s := range w.missing {
		if s.SID != sid {
			miss = append(miss, s)
		}
	}
	w.missing = miss
	delete(w.users, sid)
	w.mu.Unlock()
	for _, rw := range closing {
		w.closeWatch(rw)
	}
}

func (w *regWatcher) refreshUsersAndMissing() {
	for _, sid := range loadedUserSIDs() {
		w.mu.Lock()
		known := w.users[sid]
		w.users[sid] = true
		w.mu.Unlock()
		if !known {
			// 新登录用户：与该用户上次的基线对账（可能是离线期间写入的）
			for _, s := range userRegSpecs(sid) {
				w.addSpec(s, true)
			}
		}
	}
	w.mu.Lock()
	miss := w.missing
	w.missing = nil
	w.mu.Unlock()
	for _, s := range miss {
		if s.Hive == "HKU" && !userHiveLoaded(s.SID) {
			continue
		}
		w.addSpec(s, false)
	}
}

func (w *regWatcher) loadBaseline() {
	if w.st == nil {
		return
	}
	raw := w.st.kvGet(regBaselineKV)
	if raw == "" {
		return
	}
	m := map[string]map[string]regValue{}
	if json.Unmarshal([]byte(raw), &m) == nil {
		w.mu.Lock()
		w.baseline = m
		w.mu.Unlock()
	}
}

func (w *regWatcher) saveBaseline() {
	if w.st == nil {
		return
	}
	w.mu.Lock()
	b, err := json.Marshal(w.baseline)
	w.saveDue = false
	w.mu.Unlock()
	if err == nil {
		w.st.kvSet(regBaselineKV, string(b))
	}
}
