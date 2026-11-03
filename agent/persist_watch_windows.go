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

	"golang.org/x/sys/windows/registry"
)

// persistWatcher：持久化点变更检测（Run/Services ImagePath/Startup），对标 OpenEDR+Wazuh 持久化清单。
type persistWatcher struct {
	mu      sync.Mutex
	prev    map[string]string // key -> value
	events  []map[string]any
	enabled bool
	// 注册表已由 RegNotifyChangeKeyValue 实时订阅时，轮询只保留启动目录与 hosts
	regRealtime bool
}

func newPersistWatcher() *persistWatcher {
	return &persistWatcher{
		prev:    map[string]string{},
		enabled: true,
	}
}

func (w *persistWatcher) drain() []map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.events
	w.events = nil
	return out
}

func (w *persistWatcher) tick() {
	w.mu.Lock()
	on := w.enabled
	w.mu.Unlock()
	if !on {
		return
	}
	cur := map[string]string{}
	w.mu.Lock()
	rt := w.regRealtime
	w.mu.Unlock()
	if !rt {
		w.scanRegistry(cur)
	}
	w.scanStartupFiles(cur)
	w.scanHosts(cur)
	w.diff(cur)
}

func (w *persistWatcher) setRegistryRealtime(on bool) {
	w.mu.Lock()
	w.regRealtime = on
	w.mu.Unlock()
}

func (w *persistWatcher) scanRegistry(cur map[string]string) {
	w.scanRun(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\\Run`, cur)
	w.scanRun(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\\RunOnce`, cur)
	w.scanRun(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\\Run`, cur)
	w.scanRun(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKCU\\RunOnce`, cur)
	w.scanRun(registry.LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, `HKLM\\Wow6432Node\\Run`, cur)
	w.scanAppInit(cur)
	w.scanServicesImagePath(cur)
}

func (w *persistWatcher) diff(cur map[string]string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.prev) == 0 {
		w.prev = cur
		return
	}
	ts := time.Now().Format("2006-01-02T15:04:05")
	for k, v := range cur {
		old, ok := w.prev[k]
		if !ok {
			ev := map[string]any{
				"etype": "persist_add", "summary": "持久化新增: " + k, "severity": "high", "ts": ts,
				"detail": map[string]any{"key": k, "value": v, "source": "persist_watch"},
			}
			enrichPersistStartupPayload(ev, k, v)
			w.events = append(w.events, ev)
		} else if old != v {
			ev := map[string]any{
				"etype": "persist_modify", "summary": "持久化修改: " + k, "severity": "high", "ts": ts,
				"detail": map[string]any{"key": k, "value": v, "old_value": old, "source": "persist_watch"},
			}
			enrichPersistStartupPayload(ev, k, v)
			w.events = append(w.events, ev)
		}
	}
	for k, old := range w.prev {
		if _, ok := cur[k]; !ok {
			w.events = append(w.events, map[string]any{
				"etype": "persist_delete", "summary": "持久化删除: " + k, "severity": "medium", "ts": ts,
				"detail": map[string]any{"key": k, "old_value": old, "source": "persist_watch"},
			})
		}
	}
	w.prev = cur
	if len(w.events) > 100 {
		w.events = w.events[len(w.events)-100:]
	}
}

func (w *persistWatcher) scanRun(root registry.Key, path, loc string, cur map[string]string) {
	k, err := registry.OpenKey(root, path, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	names, err := k.ReadValueNames(0)
	if err != nil {
		return
	}
	for _, n := range names {
		val, _, err := k.GetStringValue(n)
		if err != nil {
			continue
		}
		cur[loc+"\\"+n] = val
	}
}

func (w *persistWatcher) scanAppInit(cur map[string]string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	if v, _, err := k.GetStringValue("AppInit_DLLs"); err == nil && strings.TrimSpace(v) != "" {
		cur[`HKLM\\Windows\\AppInit_DLLs`] = v
	}
}

func (w *persistWatcher) scanServicesImagePath(cur map[string]string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(0)
	if err != nil {
		return
	}
	for _, n := range names {
		sk, err := registry.OpenKey(k, n, registry.READ)
		if err != nil {
			continue
		}
		img, _, err := sk.GetStringValue("ImagePath")
		sk.Close()
		if err != nil || strings.TrimSpace(img) == "" {
			continue
		}
		low := strings.ToLower(img)
		// 只盯可疑路径服务，避免把整个 SCM 当变更流
		if !pathLooksSuspicious(img) && !strings.Contains(low, `\temp\`) &&
			!strings.Contains(low, `\users\`) && !strings.Contains(low, `\appdata\`) &&
			!strings.Contains(low, `\programdata\`) {
			continue
		}
		cur[`HKLM\\Services\\`+n+`\\ImagePath`] = img
	}
}

func (w *persistWatcher) scanStartupFiles(cur map[string]string) {
	for _, dir := range startupFolders() {
		_ = filepath.WalkDir(dir.path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext != ".lnk" && ext != ".url" && ext != ".bat" && ext != ".cmd" && ext != ".exe" && ext != ".vbs" && ext != ".ps1" {
				return nil
			}
			fi, e := os.Stat(p)
			if e != nil {
				return nil
			}
			key := "Startup\\" + dir.label + "\\" + d.Name()
			val := fmt.Sprintf("%d|%d", fi.Size(), fi.ModTime().Unix())
			if sc, ok := parseShortcutFile(p); ok {
				payload := sc.payload()
				if payload != "" {
					val = payload + "|" + sc.commandLine() + "|" + fmt.Sprintf("%d|%d", fi.Size(), fi.ModTime().Unix())
				}
			}
			cur[key] = val
			return nil
		})
	}
}

func enrichPersistStartupPayload(ev map[string]any, key, val string) {
	if !strings.HasPrefix(key, "Startup\\") {
		return
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		return
	}
	// val: payload|cmdline|size|mtime 或旧格式 size|mtime
	parts := strings.Split(val, "|")
	if len(parts) >= 2 && (strings.Contains(parts[0], `\`) || strings.HasPrefix(strings.ToLower(parts[0]), "http")) {
		payload := parts[0]
		cmdline := parts[1]
		d["payload_path"] = payload
		d["shortcut_target"] = payload
		d["command_line"] = cmdline
		d["matched"] = payload
		name := filepath.Base(payload)
		if strings.HasPrefix(strings.ToLower(payload), "http") {
			name = truncateStr(payload, 48)
		}
		ev["summary"] = "启动项: " + name + " · " + key
		d["name"] = name
		d["process_name"] = name
		if taskSuspiciousExecute(payload) || strings.HasPrefix(strings.ToLower(payload), "http") {
			ev["severity"] = "high"
		}
	}
}

func (w *persistWatcher) scanHosts(cur map[string]string) {
	p := filepath.Join(os.Getenv("SystemRoot"), `System32\drivers\etc\hosts`)
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	// 只记非注释有效行的哈希摘要，避免整文件刷屏
	var lines []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		lines = append(lines, ln)
	}
	cur[`hosts`] = strings.Join(lines, "|")
}

func (w *persistWatcher) startLoop(ctx context.Context) {
	// 首次建基线
	w.tick()
	t := time.NewTicker(12 * time.Second)
	defer t.Stop()
	log.Printf("persist: 持久化监控已启动")
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick()
		}
	}
}
