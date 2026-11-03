package main

import "testing"

func TestAgentSelfNoiseFaWatch(t *testing.T) {
	paths := []string{
		`C:\Users\x\AppData\Local\Temp\fa-watch-2296780178.ps1`,
		`C:\Windows\Temp\fa-ps-968272575.ps1`,
		`C:\Temp\fa-etw-1.ps1`,
		`C:\Temp\fa-wevt-2.ps1`,
	}
	for _, p := range paths {
		if !isAgentSelfNoisePath(p) {
			t.Fatalf("should noise: %s", p)
		}
		if pathLooksHot(p) {
			t.Fatalf("noise path must not be hot: %s", p)
		}
	}
	if isAgentSelfNoisePath(`C:\Temp\evil.ps1`) {
		t.Fatal("real dropper should not be noise")
	}
	ev := map[string]any{
		"summary": "ETW可疑目录文件创建: fa-watch-1.ps1",
		"detail":  map[string]any{"path": `C:\Temp\fa-watch-1.ps1`, "name": "fa-watch-1.ps1"},
	}
	if !isTimelineNoiseEvent(ev) {
		t.Fatal("timeline noise gate failed")
	}
}
