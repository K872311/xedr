//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	fimDebounce   = 1500 * time.Millisecond
	fimHashMax    = 32 << 20
	fimHashPerMin = 60
	fimEventsMin  = 120
)

type fimPending struct {
	path    string
	root    int
	oldPath string // 重命名的旧路径
	due     time.Time
}

type fimWatcher struct {
	st       *stateDB
	stateDir string

	mu       sync.Mutex
	base     map[string]fimEntry // 小写路径 -> 基线
	pending  map[string]*fimPending
	events   []map[string]any
	sigQueue []map[string]any
	roots    []fimRoot
	rescan   map[int]bool
	extra    []string
	active   bool

	limiter   fimLimiter
	hashLimit fimLimiter
	stopEv    windows.Handle
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func newFIMWatcher(st *stateDB, stateDir string) *fimWatcher {
	return &fimWatcher{
		st: st, stateDir: stateDir,
		base: map[string]fimEntry{}, pending: map[string]*fimPending{}, rescan: map[int]bool{},
		limiter: fimLimiter{limit: fimEventsMin}, hashLimit: fimLimiter{limit: fimHashPerMin},
	}
}

func defaultFIMRoots() []fimRoot {
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	// 不再监控 System32/SysWOW64 根：补丁与组件更新会持续刷 Valid 签名变更，且扫描拖慢安装后主机。
	// 驱动目录只保留 .sys；计划任务目录跳过 \Microsoft\（见 skipPath）。
	roots := []fimRoot{
		{Path: filepath.Join(sys, `System32\drivers\etc`), Label: "hosts/网络配置", Severity: "high", HashBase: true, MaxFiles: 200},
		{Path: filepath.Join(sys, `System32\Tasks`), Recursive: true, Label: "计划任务", Severity: "medium", HashBase: false, MaxFiles: 800},
		{Path: filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\Startup`), Label: "启动目录", Severity: "high", HashBase: true, MaxFiles: 500},
		{Path: filepath.Join(sys, `System32\GroupPolicy`), Recursive: true, Label: "组策略脚本", Severity: "medium", HashBase: true, MaxFiles: 2000},
		{Path: filepath.Join(sys, `System32\drivers`), Exts: extSet(".sys"), Label: "驱动目录", Severity: "high", MaxFiles: 3000},
	}
	if pub := os.Getenv("PUBLIC"); pub != "" {
		roots = append(roots, fimRoot{Path: pub, Recursive: true, Exts: hotFileExt, Label: "公共目录", Severity: "high", HashBase: true, MaxFiles: 5000})
	}
	users := filepath.Join(filepath.VolumeName(sys)+`\`, "Users")
	if ents, err := os.ReadDir(users); err == nil {
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			n := strings.ToLower(e.Name())
			if n == "public" || n == "default" || n == "default user" || n == "all users" {
				continue
			}
			p := filepath.Join(users, e.Name(), `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				roots = append(roots, fimRoot{Path: p, Label: "用户启动目录(" + e.Name() + ")", Severity: "high", HashBase: true, MaxFiles: 500})
			}
		}
	}
	return roots
}

func (w *fimWatcher) setExtra(paths []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.extra = paths
}

func (w *fimWatcher) drain() []map[string]any {
	w.mu.Lock()
	out := w.events
	w.events = nil
	w.mu.Unlock()
	if n := w.limiter.takeDropped(); n > 0 {
		out = append(out, map[string]any{
			"etype": "fim_overflow", "severity": "medium", "ts": time.Now().Format("2006-01-02T15:04:05"),
			"summary": fmt.Sprintf("FIM 变更过多，已合并 %d 条", n),
			"detail":  map[string]any{"source": "fim", "dropped": n},
		})
	}
	return out
}

func (w *fimWatcher) running() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.active
}

func (w *fimWatcher) push(ev map[string]any) {
	if !w.limiter.allow(time.Now()) {
		return
	}
	w.mu.Lock()
	w.events = append(w.events, ev)
	if len(w.events) > 500 {
		w.events = w.events[len(w.events)-500:]
	}
	w.mu.Unlock()
}

// start 载入基线、比对离线期间变更，然后对每个目录挂实时通知。
func (w *fimWatcher) start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		cancel()
		log.Printf("fim: CreateEvent: %v", err)
		return
	}
	w.mu.Lock()
	w.stopEv, w.cancel = ev, cancel
	roots := defaultFIMRoots()
	for _, s := range w.extra {
		if r, ok := parseFIMPathSpec(s); ok {
			roots = append(roots, r)
		}
	}
	kept := roots[:0]
	for _, r := range roots {
		if st, err := os.Stat(r.Path); err == nil && st.IsDir() {
			kept = append(kept, r)
		}
	}
	w.roots = kept
	w.active = true
	w.mu.Unlock()

	w.loadBaseline()
	for i := range kept {
		w.wg.Add(1)
		go w.watchRoot(ctx, i)
	}
	w.wg.Add(1)
	go w.processLoop(ctx)
	// 启动对账放后台：先挂通知再扫；大目录错开，避免安装后瞬时磁盘打满导致心跳掉线
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		for i := range kept {
			if ctx.Err() != nil {
				return
			}
			if i > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
			w.scanRoot(i, true)
		}
		log.Printf("fim: 监控 %d 个目录，基线 %d 个文件", len(kept), w.baseSize())
	}()
}

func (w *fimWatcher) stop() {
	w.mu.Lock()
	cancel, ev, on := w.cancel, w.stopEv, w.active
	w.active = false
	w.mu.Unlock()
	if !on {
		return
	}
	if cancel != nil {
		cancel()
	}
	_ = windows.SetEvent(ev)
	w.wg.Wait()
	_ = windows.CloseHandle(ev)
}

func (w *fimWatcher) baseSize() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.base)
}

func (w *fimWatcher) loadBaseline() {
	if w.st == nil {
		return
	}
	rows, err := w.st.db.Query("SELECT k, path, size, mtime, sha256 FROM fim_baseline")
	if err != nil {
		return
	}
	defer rows.Close()
	w.mu.Lock()
	defer w.mu.Unlock()
	for rows.Next() {
		var k string
		var e fimEntry
		if rows.Scan(&k, &e.Path, &e.Size, &e.Mtime, &e.SHA) == nil {
			w.base[k] = e
		}
	}
}

func (w *fimWatcher) saveEntry(e fimEntry) {
	if w.st == nil {
		return
	}
	_, _ = w.st.db.Exec(`INSERT INTO fim_baseline(k,path,size,mtime,sha256,updated_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(k) DO UPDATE SET path=excluded.path,size=excluded.size,mtime=excluded.mtime,sha256=excluded.sha256,updated_at=excluded.updated_at`,
		strings.ToLower(e.Path), e.Path, e.Size, e.Mtime, e.SHA, time.Now().Unix())
}

func (w *fimWatcher) deleteEntries(keys []string) {
	if w.st == nil || len(keys) == 0 {
		return
	}
	tx, err := w.st.db.Begin()
	if err != nil {
		return
	}
	for _, k := range keys {
		_, _ = tx.Exec("DELETE FROM fim_baseline WHERE k=?", k)
	}
	_ = tx.Commit()
}

func (w *fimWatcher) skipPath(p string) bool {
	l := strings.ToLower(p)
	if isAgentSelfNoisePath(l) {
		return true
	}
	// 回收站 / 系统卷信息不监控
	if strings.Contains(l, `\$recycle.bin\`) || strings.Contains(l, `\system volume information\`) {
		return true
	}
	if w.stateDir != "" && strings.HasPrefix(l, strings.ToLower(w.stateDir)) {
		return true
	}
	// 微软维护计划任务（更新编排 / Defender / Office 等）
	if strings.Contains(l, `\system32\tasks\microsoft\`) {
		return true
	}
	return false
}

// fimSignedStatusAlert：仅明确的未签名/签名损坏才告警；空串、UnknownError 等「未验出」不告警。
func fimSignedStatusAlert(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "notsigned", "hashmismatch", "nottrusted", "incompatible":
		return true
	default:
		return false
	}
}

func (w *fimWatcher) entryOf(root fimRoot, path string, fi os.FileInfo, old fimEntry, forceHash bool) fimEntry {
	e := fimEntry{Path: path, Size: fi.Size(), Mtime: fi.ModTime().Unix()}
	if old.SHA != "" && old.Size == e.Size && old.Mtime == e.Mtime && !forceHash {
		e.SHA = old.SHA
		return e
	}
	if (root.HashBase || forceHash) && e.Size <= fimHashMax && w.hashLimit.allow(time.Now()) {
		e.SHA = fileSHA256(path)
	}
	return e
}

// scanRoot 遍历目录与基线比对；initial=true 时为启动对账（首次建基线不出事件）。
func (w *fimWatcher) scanRoot(idx int, initial bool) {
	w.mu.Lock()
	if idx >= len(w.roots) {
		w.mu.Unlock()
		return
	}
	root := w.roots[idx]
	w.mu.Unlock()
	firstKey := "fim_root:" + strings.ToLower(root.Path)
	first := initial && w.st != nil && w.st.kvGet(firstKey) == ""

	seen := map[string]bool{}
	count := 0
	var batch []fimEntry
	walk := func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root.Path && !root.Recursive {
				return filepath.SkipDir
			}
			return nil
		}
		if !root.wants(p) || w.skipPath(p) {
			return nil
		}
		count++
		if root.MaxFiles > 0 && count > root.MaxFiles {
			return filepath.SkipAll
		}
		// 大目录扫描时让出 CPU，减轻安装后卡顿
		if count%400 == 0 {
			time.Sleep(20 * time.Millisecond)
		}
		fi, e := d.Info()
		if e != nil {
			return nil
		}
		k := strings.ToLower(p)
		seen[k] = true
		w.mu.Lock()
		old, had := w.base[k]
		w.mu.Unlock()
		if had && old.Size == fi.Size() && old.Mtime == fi.ModTime().Unix() {
			return nil
		}
		cur := w.entryOf(root, p, fi, old, false)
		w.mu.Lock()
		w.base[k] = cur
		w.mu.Unlock()
		batch = append(batch, cur)
		if first {
			return nil
		}
		extra := map[string]any{"offline": initial, "rescan": !initial}
		if !had {
			w.emitChange("fim_add", root, cur, fimEntry{}, extra)
		} else if fimChanged(old, cur) {
			w.emitChange("fim_modify", root, cur, old, extra)
		}
		return nil
	}
	_ = filepath.WalkDir(root.Path, walk)
	w.saveBatch(batch)

	// 基线里有、现在没有：删除
	var gone []string
	w.mu.Lock()
	for k, e := range w.base {
		if root.contains(e.Path) && root.wants(e.Path) && !seen[k] {
			gone = append(gone, k)
		}
	}
	var goneEntries []fimEntry
	for _, k := range gone {
		goneEntries = append(goneEntries, w.base[k])
		delete(w.base, k)
	}
	w.mu.Unlock()
	w.deleteEntries(gone)
	if !first && (root.MaxFiles == 0 || count <= root.MaxFiles) {
		for _, e := range goneEntries {
			w.emitChange("fim_delete", root, e, e, map[string]any{"offline": initial, "rescan": !initial})
		}
	}
	if first {
		w.st.kvSet(firstKey, time.Now().Format(time.RFC3339))
	}
}

func (w *fimWatcher) saveBatch(batch []fimEntry) {
	if w.st == nil || len(batch) == 0 {
		return
	}
	tx, err := w.st.db.Begin()
	if err != nil {
		return
	}
	now := time.Now().Unix()
	for _, e := range batch {
		_, _ = tx.Exec(`INSERT INTO fim_baseline(k,path,size,mtime,sha256,updated_at) VALUES(?,?,?,?,?,?)
			ON CONFLICT(k) DO UPDATE SET path=excluded.path,size=excluded.size,mtime=excluded.mtime,sha256=excluded.sha256,updated_at=excluded.updated_at`,
			strings.ToLower(e.Path), e.Path, e.Size, e.Mtime, e.SHA, now)
	}
	_ = tx.Commit()
}

type fileNotifyInfo struct {
	Next   uint32
	Action uint32
	Length uint32
	Name   uint16
}

func (w *fimWatcher) watchRoot(ctx context.Context, idx int) {
	defer w.wg.Done()
	w.mu.Lock()
	root := w.roots[idx]
	stopEv := w.stopEv
	w.mu.Unlock()
	p, _ := windows.UTF16PtrFromString(root.Path)
	h, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		log.Printf("fim: 打开 %s 失败: %v", root.Path, err)
		return
	}
	defer windows.CloseHandle(h)
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return
	}
	defer windows.CloseHandle(ev)
	buf := make([]byte, 64<<10)
	mask := uint32(windows.FILE_NOTIFY_CHANGE_FILE_NAME | windows.FILE_NOTIFY_CHANGE_DIR_NAME |
		windows.FILE_NOTIFY_CHANGE_SIZE | windows.FILE_NOTIFY_CHANGE_LAST_WRITE | windows.FILE_NOTIFY_CHANGE_CREATION)
	for ctx.Err() == nil {
		var ov windows.Overlapped
		ov.HEvent = ev
		_ = windows.ResetEvent(ev)
		if err := windows.ReadDirectoryChanges(h, &buf[0], uint32(len(buf)), root.Recursive, mask, nil, &ov, 0); err != nil {
			log.Printf("fim: ReadDirectoryChanges %s: %v", root.Path, err)
			return
		}
		r, _ := windows.WaitForMultipleObjects([]windows.Handle{ev, stopEv}, false, windows.INFINITE)
		if r != windows.WAIT_OBJECT_0 {
			_ = windows.CancelIoEx(h, &ov)
			var n uint32
			_ = windows.GetOverlappedResult(h, &ov, &n, true)
			return
		}
		var n uint32
		if err := windows.GetOverlappedResult(h, &ov, &n, false); err != nil || n == 0 {
			// 缓冲区溢出（变更太多）：整目录对账
			w.mu.Lock()
			w.rescan[idx] = true
			w.mu.Unlock()
			continue
		}
		w.parseNotify(idx, root, buf[:n])
	}
}

func (w *fimWatcher) parseNotify(idx int, root fimRoot, b []byte) {
	off := 0
	var renameOld string
	now := time.Now()
	for off+12 <= len(b) {
		fni := (*fileNotifyInfo)(unsafe.Pointer(&b[off]))
		n := int(fni.Length / 2)
		if off+12+int(fni.Length) > len(b) {
			break
		}
		name := windows.UTF16ToString(unsafe.Slice(&fni.Name, n))
		full := filepath.Join(root.Path, name)
		switch fni.Action {
		case windows.FILE_ACTION_RENAMED_OLD_NAME:
			renameOld = full
		case windows.FILE_ACTION_RENAMED_NEW_NAME:
			w.queue(idx, full, renameOld, now)
			renameOld = ""
		default:
			w.queue(idx, full, "", now)
		}
		if fni.Next == 0 {
			break
		}
		off += int(fni.Next)
	}
	if renameOld != "" {
		w.queue(idx, renameOld, "", now)
	}
}

func (w *fimWatcher) queue(idx int, path, oldPath string, now time.Time) {
	if w.skipPath(path) {
		return
	}
	k := strings.ToLower(path)
	w.mu.Lock()
	defer w.mu.Unlock()
	if p, ok := w.pending[k]; ok {
		p.due = now.Add(fimDebounce)
		if oldPath != "" {
			p.oldPath = oldPath
		}
		return
	}
	if len(w.pending) >= 5000 {
		w.rescan[idx] = true
		return
	}
	w.pending[k] = &fimPending{path: path, root: idx, oldPath: oldPath, due: now.Add(fimDebounce)}
}

func (w *fimWatcher) processLoop(ctx context.Context) {
	defer w.wg.Done()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			w.mu.Lock()
			var due []*fimPending
			for k, p := range w.pending {
				if now.After(p.due) {
					due = append(due, p)
					delete(w.pending, k)
				}
			}
			resc := w.rescan
			w.rescan = map[int]bool{}
			w.mu.Unlock()
			for idx := range resc {
				w.scanRoot(idx, false)
			}
			for _, p := range due {
				w.settle(p)
			}
			w.signPending()
		}
	}
}

// settle 防抖结束后核对文件真实状态并与基线比较。
func (w *fimWatcher) settle(p *fimPending) {
	w.mu.Lock()
	root := w.roots[p.root]
	w.mu.Unlock()
	k := strings.ToLower(p.path)
	fi, err := os.Stat(p.path)
	if err != nil {
		// 文件或目录已不存在
		var gone []fimEntry
		var keys []string
		w.mu.Lock()
		if e, ok := w.base[k]; ok {
			gone = append(gone, e)
			keys = append(keys, k)
			delete(w.base, k)
		}
		prefix := k + `\`
		for bk, e := range w.base {
			if strings.HasPrefix(bk, prefix) {
				gone = append(gone, e)
				keys = append(keys, bk)
				delete(w.base, bk)
			}
		}
		w.mu.Unlock()
		w.deleteEntries(keys)
		if len(gone) == 1 {
			w.emitChange("fim_delete", root, gone[0], gone[0], nil)
		} else if len(gone) > 1 {
			e := fimEntry{Path: p.path}
			w.emitChange("fim_delete", root, e, e, map[string]any{"is_dir": true, "files": len(gone)})
		}
		return
	}
	if fi.IsDir() {
		if root.Recursive {
			w.scanSubdir(p.root, root, p.path)
		}
		return
	}
	if !root.wants(p.path) {
		return
	}
	w.mu.Lock()
	old, had := w.base[k]
	var renamed fimEntry
	if p.oldPath != "" {
		ok2 := strings.ToLower(p.oldPath)
		if e, ok := w.base[ok2]; ok {
			renamed = e
			delete(w.base, ok2)
		}
	}
	w.mu.Unlock()
	if renamed.Path != "" {
		w.deleteEntries([]string{strings.ToLower(p.oldPath)})
	}
	cur := w.entryOf(root, p.path, fi, old, root.Exts != nil || root.HashBase)
	w.mu.Lock()
	w.base[k] = cur
	w.mu.Unlock()
	w.saveEntry(cur)
	switch {
	case renamed.Path != "":
		w.emitChange("fim_rename", root, cur, renamed, map[string]any{"old_path": renamed.Path})
	case !had:
		w.emitChange("fim_add", root, cur, fimEntry{}, nil)
	case fimChanged(old, cur):
		w.emitChange("fim_modify", root, cur, old, nil)
	}
}

func (w *fimWatcher) scanSubdir(idx int, root fimRoot, dir string) {
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		n++
		if n > 500 {
			return filepath.SkipAll
		}
		w.queue(idx, p, "", time.Now().Add(-fimDebounce))
		return nil
	})
}

func (w *fimWatcher) emitChange(etype string, root fimRoot, cur, old fimEntry, extra map[string]any) {
	if extra == nil {
		extra = map[string]any{}
	}
	if a, ok := fileActors.lookup(cur.Path); ok {
		extra["pid"] = a.pid
		extra["process_name"] = a.name
		if a.entity != "" {
			extra["entity_id"] = a.entity
		}
	}
	ev := fimEvent(etype, root, cur, old, extra)
	ext := strings.ToLower(filepath.Ext(cur.Path))
	if fimExecExts[ext] {
		// 可执行删除：无法验签，系统目录一律不报；其他目录降级 info 只留时间线
		if etype == "fim_delete" {
			lp := strings.ToLower(cur.Path)
			if strings.Contains(lp, `\windows\`) {
				return
			}
			ev["severity"] = "info"
			w.push(ev)
			return
		}
		w.mu.Lock()
		if len(w.sigQueue) < 2000 {
			w.sigQueue = append(w.sigQueue, ev)
			w.mu.Unlock()
			return
		}
		w.mu.Unlock()
		// 队列满：丢弃（不裸报），避免补丁风暴时刷屏
		return
	}
	if isScheduledTaskDefPath(cur.Path) {
		enrichFIMScheduledTaskEvent(ev, cur.Path)
	}
	if ext == ".lnk" || ext == ".url" {
		enrichFIMShortcutEvent(ev, cur.Path)
		if isStartupFolderPath(cur.Path) {
			if d, ok := ev["detail"].(map[string]any); ok {
				d["label"] = "启动项"
			}
		}
	}
	if isGroupPolicyScriptPath(cur.Path) {
		enrichFIMGroupPolicyScript(ev, cur.Path)
	}
	w.push(ev)
}

// signPending 可执行文件批量补签名（一次 PowerShell）：微软签名 info，其他有效签名 medium，未签名/无效 high。
func (w *fimWatcher) signPending() {
	w.mu.Lock()
	n := len(w.sigQueue)
	if n == 0 {
		w.mu.Unlock()
		return
	}
	if n > 40 {
		n = 40
	}
	batch := append([]map[string]any(nil), w.sigQueue[:n]...)
	w.sigQueue = w.sigQueue[n:]
	w.mu.Unlock()
	reqs := make([]peReq, 0, len(batch))
	for i, ev := range batch {
		reqs = append(reqs, peReq{idx: i, path: asString(ev["detail"].(map[string]any)["path"])})
	}
	meta := batchPEMeta(reqs)
	for _, ev := range batch {
		d := ev["detail"].(map[string]any)
		pm, ok := meta[strings.ToLower(asString(d["path"]))]
		if !ok {
			continue // 未验出：不告警
		}
		d["signed"], d["signer"], d["company"] = pm.Signed, pm.Signer, pm.Company
		// 仅明确未签名/损坏才上报；Valid（含微软/目录签名）及未知状态一律丢弃
		if !fimSignedStatusAlert(pm.Signed) {
			continue
		}
		// 规则监控目录保持 info：交给后台用户规则出告警，避免与 FIM 内置告警重复
		if asString(ev["severity"]) != "info" {
			ev["severity"] = "high"
		}
		w.push(ev)
	}
}
