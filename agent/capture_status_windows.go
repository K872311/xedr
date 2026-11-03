//go:build windows

package main

import (
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	captureProbeMu sync.Mutex
	captureProbeAt time.Time
	captureProbe   map[string]any
)

func probeCaptureEnvironment() map[string]any {
	captureProbeMu.Lock()
	defer captureProbeMu.Unlock()
	if captureProbe != nil && time.Since(captureProbeAt) < 60*time.Second {
		return captureProbe
	}
	out := map[string]any{
		"audit_4688_enabled": probeAudit4688(),
		"sysmon_present":     probeSysmonLog(),
		"etw_session_ok":     false,
	}
	if captureETWStatusFn != nil {
		mode, ok := captureETWStatusFn()
		out["etw_session_ok"] = ok
		out["etw_mode"] = mode
	}
	captureProbe, captureProbeAt = out, time.Now()
	return out
}

func probeAudit4688() bool {
	ps := `$p='Audit: Process Creation'; try { $g=Get-WinEvent -ListLog Security -ErrorAction Stop; $a=$g.IsEnabled } catch { $false }; if(-not $a){$false}else{ try { $c=auditpol /get /subcategory:$p 2>$null | Out-String; $c -match 'Success|成功' } catch { $false } }`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(b)), "success") || strings.Contains(string(b), "成功")
}

func probeSysmonLog() bool {
	ps := `try { $null=Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop; 'yes' } catch { 'no' }`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
	b, err := cmd.CombinedOutput()
	return err == nil && strings.TrimSpace(string(b)) == "yes"
}

func captureStatusSnapshot() map[string]any {
	m := probeCaptureEnvironment()
	m["entities_rev"] = procEntities.revision()
	return m
}

func componentHealthSnapshot() []map[string]any {
	var out []map[string]any
	add := func(name string, on bool, msg string) {
		st := "OFF"
		if on {
			st = "OK"
		}
		if on && msg != "" {
			st = "DEGRADED"
		}
		out = append(out, map[string]any{"name": name, "state": st, "message": msg})
	}
	etwOn, etwMsg := integrationEnabled("etw"), ""
	if captureETWStatusFn != nil {
		m, ok := captureETWStatusFn()
		if !ok {
			etwOn = false
		}
		if m == "starting" {
			etwMsg = "启动中"
		} else if !ok && m != "stopped" && m != "" {
			etwMsg = m
		}
	}
	add("etw", etwOn, etwMsg)
	add("winevent", integrationEnabled("winevent"), "")
	add("evm", integrationEnabled("evm"), "")
	add("ptm", integrationEnabled("ptm"), "")
	add("memory_scan", integrationEnabled("memory_scan"), "用户态 YARA（非 Defend 内核内存威胁）")
	add("wmi_process", integrationEnabled("wmi_process"), "")
	add("amsi", integrationEnabled("amsi"), "")
	add("api_etw", integrationEnabled("api_etw"), "")
	add("fim", integrationEnabled("fim"), "")
	add("registry", integrationEnabled("registry"), "")
	if blocked, msg := evaluatePreventions("memory_scan"); blocked {
		add("memory_scan", false, msg)
	}
	if blocked, msg := evaluatePreventions("wmi_process"); blocked {
		add("wmi_process", false, msg)
	}
	return out
}
