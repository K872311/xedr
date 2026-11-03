//go:build windows

package main

import "testing"

func TestRegDiffAndEvents(t *testing.T) {
	old := map[string]regValue{
		`HKLM\SOFTWARE\Run\a`: {Type: "REG_SZ", Data: "a.exe"},
		`HKLM\SOFTWARE\Run\b`: {Type: "REG_SZ", Data: "b.exe"},
	}
	cur := map[string]regValue{
		`HKLM\SOFTWARE\Run\a`: {Type: "REG_SZ", Data: `C:\Users\x\AppData\evil.exe`},
		`HKLM\SOFTWARE\Run\c`: {Type: "REG_SZ", Data: "c.exe"},
	}
	adds, mods, dels := regDiff(old, cur)
	if len(adds) != 1 || len(mods) != 1 || len(dels) != 1 {
		t.Fatalf("diff: %v %v %v", adds, mods, dels)
	}
	spec := regSpec{ID: "hklm_run", Hive: "HKLM", Path: `SOFTWARE\Run`, Category: "persistence", Label: `HKLM\Run`}
	ev := regEvent(spec, "modify", mods[0], cur[mods[0]], old[mods[0]], false)
	if ev["etype"] != "persist_modify" || ev["summary"] != `持久化修改: HKLM\Run\a` {
		t.Fatalf("persist event: %v", ev)
	}
	d := ev["detail"].(map[string]any)
	if d["old_value"] != "a.exe" || d["value_name"] != "a" {
		t.Fatalf("detail: %v", d)
	}
	sec := regSpec{ID: "defender_excl", Hive: "HKLM", Path: `SOFTWARE\Microsoft\Windows Defender\Exclusions`,
		Category: "defense_evasion", Label: "Defender排除项"}
	ev2 := regEvent(sec, "add", `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\tmp`,
		regValue{Type: "REG_DWORD", Data: "0"}, regValue{}, true)
	if ev2["etype"] != "registry_set" || ev2["severity"] != "high" {
		t.Fatalf("security event: %v", ev2)
	}
	if ev2["detail"].(map[string]any)["offline"] != true {
		t.Fatal("离线对账事件应标记 offline")
	}
	if !(regSpec{Values: []string{"debugger"}}).wantValue("Debugger") {
		t.Fatal("值名过滤应忽略大小写")
	}
	fimRun := regSpec{
		ID: "extra_run", Hive: "HKLM", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		Category: "defense_evasion", Label: "FIM扩展", Severity: "high",
	}
	ev3 := regEvent(fimRun, "modify", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth`,
		regValue{Type: "REG_SZ", Data: `C:\Windows\System32\SecurityHealthSystray.exe`},
		regValue{Type: "REG_SZ", Data: ""}, false)
	if ev3["severity"] != "info" {
		t.Fatalf("SecurityHealth Run 项应降为 info: %v", ev3)
	}
}
