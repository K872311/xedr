//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseURLFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.url")
	_ = os.WriteFile(p, []byte("[InternetShortcut]\r\nURL=http://evil.example/a.exe\r\n"), 0644)
	s, ok := parseShortcutFile(p)
	if !ok || s.URL != "http://evil.example/a.exe" {
		t.Fatalf("got %+v ok=%v", s, ok)
	}
}

func TestEnrichFIMShortcutSummary(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.url")
	_ = os.WriteFile(p, []byte("[InternetShortcut]\nURL=https://cdn.evil/payload.exe\n"), 0644)
	ev := map[string]any{
		"etype": "fim_add", "severity": "medium", "summary": "FIM新增: bad.url",
		"detail": map[string]any{"path": p, "name": "bad.url"},
	}
	// 非 Startup 路径也会解析字段
	enrichFIMShortcutEvent(ev, p)
	d := ev["detail"].(map[string]any)
	if d["shortcut_url"] == nil && d["payload_path"] == nil {
		t.Fatalf("missing payload: %#v", d)
	}
}
