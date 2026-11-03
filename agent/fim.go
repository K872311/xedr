package main

import (
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 文件完整性监控（FIM）：目录实时变更通知 + 本地基线（大小/修改时间/SHA256），
// 启动时与上次基线比对补出离线期间的变更；变更事件按 ETW 文件创建记录归属进程。

var fileActors = newFileActorCache()

type fileActor struct {
	pid    uint32
	name   string
	entity string
	at     time.Time
}

type fileActorCache struct {
	mu sync.Mutex
	m  map[string]fileActor
}

func newFileActorCache() *fileActorCache { return &fileActorCache{m: map[string]fileActor{}} }

func (c *fileActorCache) note(path string, pid uint32, name, entity string) {
	if path == "" || pid == 0 {
		return
	}
	k := strings.ToLower(path)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= 8192 {
		for p, a := range c.m {
			if time.Since(a.at) > 2*time.Minute {
				delete(c.m, p)
			}
		}
		if len(c.m) >= 8192 {
			c.m = map[string]fileActor{}
		}
	}
	c.m[k] = fileActor{pid: pid, name: name, entity: entity, at: time.Now()}
}

func (c *fileActorCache) lookup(path string) (fileActor, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.m[strings.ToLower(path)]
	if !ok || time.Since(a.at) > 2*time.Minute {
		return fileActor{}, false
	}
	return a, true
}

type fimEntry struct {
	Path  string
	Size  int64
	Mtime int64 // unix 秒
	SHA   string
}

// fimChanged 判断文件内容是否变化：两边都有哈希时以哈希为准，否则看大小与修改时间。
func fimChanged(old, cur fimEntry) bool {
	if old.SHA != "" && cur.SHA != "" {
		return !strings.EqualFold(old.SHA, cur.SHA)
	}
	return old.Size != cur.Size || old.Mtime != cur.Mtime
}

type fimRoot struct {
	Path      string
	Recursive bool
	Exts      map[string]bool // nil 表示全部
	Label     string
	Severity  string
	HashBase  bool // 建基线时就算哈希（小目录）
	MaxFiles  int
}

func (r fimRoot) wants(path string) bool {
	if r.Exts == nil {
		return true
	}
	return r.Exts[strings.ToLower(filepath.Ext(path))]
}

func (r fimRoot) contains(path string) bool {
	lp, lr := strings.ToLower(path), strings.ToLower(strings.TrimRight(r.Path, `\`))
	if !strings.HasPrefix(lp, lr+`\`) {
		return false
	}
	if r.Recursive {
		return true
	}
	return !strings.Contains(lp[len(lr)+1:], `\`)
}

func extSet(exts ...string) map[string]bool {
	m := map[string]bool{}
	for _, e := range exts {
		m[e] = true
	}
	return m
}

var fimExecExts = extSet(".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".com", ".efi")

// parseFIMPathSpec 策略里的自定义目录："D:\app" 或 "D:\app|r"（递归）。
// 规则下发格式："D:\Tools|r|exe,dll|rule"；盘符根 "D:\" 只监控一层。
func parseFIMPathSpec(spec string) (fimRoot, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return fimRoot{}, false
	}
	parts := strings.Split(spec, "|")
	path := strings.TrimSpace(parts[0])
	rec := false
	var exts map[string]bool
	fromRule := false
	for _, p := range parts[1:] {
		p = strings.ToLower(strings.TrimSpace(p))
		switch {
		case p == "r" || p == "recursive":
			rec = true
		case p == "rule":
			fromRule = true
		case p != "":
			exts = map[string]bool{}
			for _, e := range strings.Split(p, ",") {
				e = strings.TrimSpace(strings.TrimPrefix(e, "."))
				if e != "" {
					exts["."+e] = true
				}
			}
		}
	}
	clean := filepath.Clean(path)
	if len(clean) == 2 && clean[1] == ':' {
		clean += `\`
	}
	driveRoot := len(clean) == 3 && strings.HasSuffix(clean, `:\`)
	if !driveRoot {
		clean = strings.TrimRight(clean, `\`)
		if len(clean) < 3 || !strings.Contains(clean, `:\`) {
			return fimRoot{}, false
		}
	} else {
		rec = false // 整盘递归代价太高
	}
	r := fimRoot{Path: clean, Recursive: rec, Exts: exts, Label: "自定义", Severity: "medium", HashBase: true, MaxFiles: 5000}
	if fromRule {
		// 规则目录：只做未签名判定，不按 FIM 自身告警（由后台规则出告警）
		r.Label, r.Severity, r.HashBase = "规则监控", "info", false
		if r.Exts == nil {
			r.Exts = fimExecExts
		}
	}
	return r, true
}

// fimLimiter 每分钟事件预算，超出部分只计数，下一分钟出一条汇总。
type fimLimiter struct {
	mu      sync.Mutex
	window  time.Time
	used    int
	limit   int
	dropped int
}

func (l *fimLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.window) >= time.Minute {
		l.window, l.used = now, 0
	}
	if l.used >= l.limit {
		l.dropped++
		return false
	}
	l.used++
	return true
}

func (l *fimLimiter) takeDropped() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.dropped
	l.dropped = 0
	return n
}

var fimActionNames = map[string]string{
	"fim_add": "新增", "fim_modify": "修改", "fim_delete": "删除", "fim_rename": "重命名",
}

func fimEvent(etype string, root fimRoot, cur, old fimEntry, extra map[string]any) map[string]any {
	name := filepath.Base(cur.Path)
	detail := map[string]any{
		"source": "fim", "path": cur.Path, "name": name, "ext": strings.ToLower(filepath.Ext(cur.Path)),
		"root": root.Path, "label": root.Label,
	}
	if etype != "fim_delete" {
		detail["size"] = cur.Size
		if cur.Mtime > 0 {
			detail["mtime"] = time.Unix(cur.Mtime, 0).Format("2006-01-02T15:04:05")
		}
		if cur.SHA != "" {
			detail["sha256"] = cur.SHA
		}
	}
	if old.Path != "" && etype != "fim_add" {
		if old.SHA != "" {
			detail["old_sha256"] = old.SHA
		}
		detail["old_size"] = old.Size
	}
	for k, v := range extra {
		detail[k] = v
	}
	sev := root.Severity
	if sev == "" {
		sev = "medium"
	}
	if etype == "fim_delete" && sev == "high" {
		sev = "medium"
	}
	return map[string]any{
		"etype": etype, "severity": sev, "ts": time.Now().Format("2006-01-02T15:04:05"),
		"summary": "FIM" + fimActionNames[etype] + ": " + name + " [" + root.Label + "]",
		"detail":  detail,
	}
}
