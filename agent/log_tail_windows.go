//go:build windows

package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// logTailWatcher 策略 log_tail_paths：轻量「定向日志」采集（非 Filebeat filestream 任意路径）。
type logTailWatcher struct {
	mu      sync.Mutex
	paths   []string
	offsets map[string]int64
	events  []map[string]any
}

func newLogTailWatcher() *logTailWatcher {
	return &logTailWatcher{offsets: map[string]int64{}}
}

func (w *logTailWatcher) setPaths(paths []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.paths = append([]string(nil), paths...)
}

func (w *logTailWatcher) drain() []map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.events
	w.events = nil
	return out
}

func (w *logTailWatcher) start(ctx context.Context) {
	go func() {
		t := time.NewTicker(12 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				w.tick()
			}
		}
	}()
}

func (w *logTailWatcher) tick() {
	w.mu.Lock()
	paths := append([]string(nil), w.paths...)
	w.mu.Unlock()
	for _, p := range paths {
		w.readPath(p)
	}
}

func (w *logTailWatcher) readPath(p string) {
	p = strings.TrimSpace(p)
	if p == "" {
		return
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return
	}
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() {
		return
	}
	w.mu.Lock()
	off := w.offsets[abs]
	w.mu.Unlock()
	f, err := os.Open(abs)
	if err != nil {
		return
	}
	defer f.Close()
	if off > fi.Size() {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return
	}
	rd := bufio.NewReader(f)
	var lines []string
	for len(lines) < 20 {
		line, err := rd.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			if line != "" {
				lines = append(lines, line)
			}
		}
		if err != nil {
			break
		}
	}
	newOff, _ := f.Seek(0, io.SeekCurrent)
	w.mu.Lock()
	w.offsets[abs] = newOff
	ts := time.Now().Format("2006-01-02T15:04:05")
	for _, line := range lines {
		if len(line) > 4096 {
			line = line[:4096] + "…"
		}
		w.events = append(w.events, map[string]any{
			"etype": "log_tail_line", "summary": "日志: " + filepath.Base(abs), "severity": "info", "ts": ts,
			"detail": map[string]any{
				"source": "log_tail", "path": abs, "message": line,
				"note": "非 filestream；策略 log_tail_paths 白名单",
			},
		})
	}
	if len(w.events) > 200 {
		w.events = w.events[len(w.events)-200:]
	}
	w.mu.Unlock()
}

func applyLogTailPolicy(pol map[string]any) {
	if pol == nil {
		return
	}
	arr, ok := pol["log_tail_paths"].([]any)
	if !ok {
		return
	}
	var paths []string
	for _, x := range arr {
		if s := strings.TrimSpace(asString(x)); s != "" {
			paths = append(paths, s)
		}
	}
	if logTailGlobal != nil {
		logTailGlobal.setPaths(paths)
	}
	if len(paths) > 0 {
		log.Printf("log_tail: 监控 %d 条路径（FIM 之外定向 shipper）", len(paths))
	}
}

var logTailGlobal *logTailWatcher
