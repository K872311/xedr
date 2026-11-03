//go:build windows

package main

import (
	"context"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

type deviceWatcher struct {
	mu     sync.Mutex
	known  map[string]int // path -> GetDriveType
	events []map[string]any
}

func newDeviceWatcher() *deviceWatcher {
	return &deviceWatcher{known: map[string]int{}}
}

func driveTypeOf(root string) int {
	p16, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return 0
	}
	return int(windows.GetDriveType(p16))
}

func driveTypeLabel(t int) string {
	switch t {
	case windows.DRIVE_REMOVABLE:
		return "removable"
	case windows.DRIVE_FIXED:
		return "fixed"
	case windows.DRIVE_REMOTE:
		return "remote"
	case windows.DRIVE_CDROM:
		return "cdrom"
	case windows.DRIVE_RAMDISK:
		return "ramdisk"
	default:
		return "unknown"
	}
}

func listDriveRoots() []string {
	var out []string
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		p := string(c) + `:\`
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func (w *deviceWatcher) start(ctx context.Context) {
	w.mu.Lock()
	for _, p := range listDriveRoots() {
		w.known[p] = driveTypeOf(p)
	}
	w.mu.Unlock()
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

func (w *deviceWatcher) stop() {}

func (w *deviceWatcher) tick() {
	cur := listDriveRoots()
	curSet := map[string]int{}
	for _, p := range cur {
		curSet[p] = driveTypeOf(p)
	}
	now := time.Now().Format("2006-01-02T15:04:05")
	w.mu.Lock()
	defer w.mu.Unlock()
	for p, dt := range curSet {
		if _, ok := w.known[p]; ok {
			continue
		}
		sev := "info"
		if dt == windows.DRIVE_REMOVABLE || dt == windows.DRIVE_REMOTE {
			sev = "medium"
		}
		w.events = append(w.events, map[string]any{
			"etype": "device_mount", "summary": "卷挂载: " + p + " (" + driveTypeLabel(dt) + ")",
			"severity": sev, "ts": now,
			"detail": map[string]any{
				"path": p, "drive_type": driveTypeLabel(dt), "drive_type_id": dt,
				"source": "device_poll",
			},
		})
	}
	for p, dt := range w.known {
		if _, ok := curSet[p]; ok {
			continue
		}
		w.events = append(w.events, map[string]any{
			"etype": "device_unmount", "summary": "卷卸载: " + p,
			"severity": "info", "ts": now,
			"detail": map[string]any{
				"path": p, "drive_type": driveTypeLabel(dt), "source": "device_poll",
			},
		})
	}
	w.known = curSet
	if len(w.events) > 200 {
		w.events = w.events[len(w.events)-200:]
	}
}

func (w *deviceWatcher) drain() []map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.events) == 0 {
		return nil
	}
	out := append([]map[string]any(nil), w.events...)
	w.events = nil
	return out
}
