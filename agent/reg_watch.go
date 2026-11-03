//go:build windows

package main

import (
	"sort"
	"strings"
	"time"
)

// 实时注册表监控：RegNotifyChangeKeyValue 订阅关键键，触发后重读该键（含有限深度子键）
// 与上次快照逐值比较，输出新增/修改/删除。通知本身不含进程信息，因此事件不做进程归属。

type regSpec struct {
	ID          string
	Hive        string // HKLM / HKU
	SID         string // HKU 下的用户 SID
	Path        string
	Subtree     bool
	Depth       int      // 读取子键层数（Subtree 时有效）
	Values      []string // 仅关注这些值名（小写），空为全部
	Category    string   // persistence / defense_evasion / credential_access / privilege_escalation
	Label       string
	Severity    string
	MinInterval time.Duration // 高频变更键的最小重读间隔
}

type regValue struct {
	Type string `json:"t"`
	Data string `json:"d"`
}

func (s regSpec) displayRoot() string {
	if s.Hive == "HKU" {
		return `HKU\` + s.SID + `\` + s.Path
	}
	return s.Hive + `\` + s.Path
}

func (s regSpec) wantValue(name string) bool {
	if len(s.Values) == 0 {
		return true
	}
	n := strings.ToLower(name)
	for _, v := range s.Values {
		if v == n {
			return true
		}
	}
	return false
}

// regDiff 返回新增、修改、删除的完整值路径（已排序，便于测试与稳定输出）。
func regDiff(old, cur map[string]regValue) (adds, mods, dels []string) {
	for k, v := range cur {
		o, ok := old[k]
		switch {
		case !ok:
			adds = append(adds, k)
		case o != v:
			mods = append(mods, k)
		}
	}
	for k := range old {
		if _, ok := cur[k]; !ok {
			dels = append(dels, k)
		}
	}
	sort.Strings(adds)
	sort.Strings(mods)
	sort.Strings(dels)
	return
}

func splitValuePath(full string) (key, name string) {
	i := strings.LastIndex(full, `\`)
	if i < 0 {
		return "", full
	}
	return full[:i], full[i+1:]
}

// regFIMRunBenignSeverity：FIM 扩展监控 Run/RunOnce 时，常见合法启动项降为 info（仍进时间线，不晋升威胁告警）。
func regFIMRunBenignSeverity(spec regSpec, valueName string, cur regValue, sev string) string {
	if sev == "info" || spec.Label != "FIM扩展" {
		return sev
	}
	p := strings.ToLower(spec.Path)
	if !strings.Contains(p, `currentversion\run`) && !strings.Contains(p, `runonce`) {
		return sev
	}
	vn := strings.ToLower(strings.TrimSpace(valueName))
	if vn == "" || vn == "(默认)" {
		return sev
	}
	for _, b := range []string{
		"securityhealth", "sysdiag", "vmware user process", "vmware tray",
	} {
		if vn == b {
			return "info"
		}
	}
	data := strings.ToLower(strings.TrimSpace(cur.Data))
	if data != "" && strings.HasSuffix(data, ".exe") {
		if strings.Contains(data, `\windows\`) || strings.Contains(data, `\program files`) || strings.Contains(data, `\program files (x86)`) {
			return "info"
		}
	}
	return sev
}

// regEvent 持久化类沿用 persist_* 事件类型（兼容已有规则与看板），其余归为 registry_*。
func regEvent(spec regSpec, kind, full string, cur, old regValue, offline bool) map[string]any {
	key, name := splitValuePath(full)
	if name == "" {
		name = "(默认)"
	}
	short := spec.Label + `\` + strings.TrimPrefix(strings.TrimPrefix(key, spec.displayRoot()), `\`)
	short = strings.TrimRight(short, `\`) + `\` + name
	var etype, summary string
	sev := spec.Severity
	if sev == "" {
		sev = "high"
	}
	if spec.Category == "persistence" {
		switch kind {
		case "add":
			etype, summary = "persist_add", "持久化新增: "+short
		case "modify":
			etype, summary = "persist_modify", "持久化修改: "+short
		default:
			etype, summary = "persist_delete", "持久化删除: "+short
			sev = "medium"
		}
	} else {
		switch kind {
		case "add", "modify":
			etype, summary = "registry_set", "注册表安全项变更: "+short
		default:
			etype, summary = "registry_delete", "注册表安全项删除: "+short
			if sev == "high" {
				sev = "medium"
			}
		}
	}
	// 系统服务 / Active Setup：仅可疑路径才算威胁，其余降为 info（只进时间线）
	if spec.Category == "persistence" && (spec.ID == "services" || spec.ID == "active_setup") && kind != "delete" {
		if !pathLooksSuspicious(cur.Data) {
			sev = "info"
		}
	}
	// Defender 排除：只关心新增/修改排除路径；删除降为 info
	if spec.ID == "defender_excl" && kind == "delete" {
		sev = "info"
	}
	if kind != "delete" {
		sev = regFIMRunBenignSeverity(spec, name, cur, sev)
	}
	detail := map[string]any{
		"source": "reg_notify", "key": full, "reg_key": key, "value_name": name,
		"category": spec.Category, "label": spec.Label, "hive": spec.Hive, "watch": spec.ID,
		"change": kind,
	}
	if spec.SID != "" {
		detail["user_sid"] = spec.SID
	}
	if kind != "delete" {
		detail["value"] = cur.Data
		detail["value_type"] = cur.Type
	}
	if kind != "add" {
		detail["old_value"] = old.Data
	}
	if offline {
		detail["offline"] = true
		summary += "（Agent 离线期间）"
	}
	enrichRegActor(detail)
	return map[string]any{
		"etype": etype, "summary": summary, "severity": sev,
		"ts": time.Now().Format("2006-01-02T15:04:05"), "detail": detail,
	}
}

func enrichRegActor(detail map[string]any) {
	if detail == nil {
		return
	}
	e := procEntities.bestRecentUserProcess(4 * time.Second)
	if e == nil {
		detail["actor_confidence"] = "none"
		return
	}
	detail["actor_confidence"] = "heuristic"
	detail["pid"] = int(e.PID)
	if e.PPID != 0 {
		detail["ppid"] = int(e.PPID)
	}
	if e.Name != "" {
		detail["process_name"] = e.Name
	}
	if e.Image != "" {
		detail["image"] = e.Image
		detail["process_path"] = e.Image
	}
	mergeInto(detail, procEntities.fieldsOf(e))
}

func lowerAll(xs ...string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strings.ToLower(x)
	}
	return out
}

// machineRegSpecs HKLM 下的关键键（持久化 / 防御削弱 / 凭据）。
func machineRegSpecs() []regSpec {
	p := "persistence"
	de := "defense_evasion"
	ca := "credential_access"
	pe := "privilege_escalation"
	cv := `SOFTWARE\Microsoft\Windows\CurrentVersion`
	nt := `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	return []regSpec{
		{ID: "hklm_run", Hive: "HKLM", Path: cv + `\Run`, Category: p, Label: `HKLM\Run`},
		{ID: "hklm_runonce", Hive: "HKLM", Path: cv + `\RunOnce`, Category: p, Label: `HKLM\RunOnce`},
		{ID: "hklm_runonceex", Hive: "HKLM", Path: cv + `\RunOnceEx`, Subtree: true, Depth: 1, Category: p, Label: `HKLM\RunOnceEx`},
		{ID: "hklm_policy_run", Hive: "HKLM", Path: cv + `\Policies\Explorer\Run`, Category: p, Label: `HKLM\Policies\Run`},
		{ID: "hklm_wow_run", Hive: "HKLM", Path: `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, Category: p, Label: `HKLM\Wow64\Run`},
		{ID: "hklm_wow_runonce", Hive: "HKLM", Path: `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, Category: p, Label: `HKLM\Wow64\RunOnce`},
		{ID: "winlogon", Hive: "HKLM", Path: nt + `\Winlogon`, Values: lowerAll("Shell", "Userinit", "Taskman", "AppSetup", "GinaDLL"), Category: p, Label: "Winlogon"},
		{ID: "appinit", Hive: "HKLM", Path: nt + `\Windows`, Values: lowerAll("AppInit_DLLs", "LoadAppInit_DLLs", "Load", "Run"), Category: p, Label: "AppInit"},
		{ID: "appinit_wow", Hive: "HKLM", Path: `SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows`, Values: lowerAll("AppInit_DLLs", "LoadAppInit_DLLs"), Category: p, Label: "AppInit(Wow64)"},
		{ID: "ifeo", Hive: "HKLM", Path: nt + `\Image File Execution Options`, Subtree: true, Depth: 1, Values: lowerAll("Debugger", "GlobalFlag", "VerifierDlls"), Category: p, Label: "IFEO"},
		{ID: "silent_exit", Hive: "HKLM", Path: nt + `\SilentProcessExit`, Subtree: true, Depth: 1, Values: lowerAll("MonitorProcess", "ReportingMode"), Category: p, Label: "SilentProcessExit"},
		{ID: "session_mgr", Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Control\Session Manager`, Values: lowerAll("BootExecute", "SetupExecute", "Execute", "S0InitialCommand"), Category: p, Label: "SessionManager"},
		{ID: "knowndlls", Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`, Category: p, Label: "KnownDLLs"},
		{ID: "active_setup", Hive: "HKLM", Path: `SOFTWARE\Microsoft\Active Setup\Installed Components`, Subtree: true, Depth: 1, Values: lowerAll("StubPath"), Category: p, Label: "ActiveSetup", MinInterval: 2 * time.Second},
		{ID: "netsh", Hive: "HKLM", Path: `SOFTWARE\Microsoft\Netsh`, Category: p, Label: "Netsh"},
		{ID: "print_monitors", Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Control\Print\Monitors`, Subtree: true, Depth: 1, Values: lowerAll("Driver"), Category: p, Label: "PrintMonitors"},
		{ID: "time_providers", Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders`, Subtree: true, Depth: 1, Values: lowerAll("DllName"), Category: p, Label: "TimeProviders"},
		{ID: "services", Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Services`, Subtree: true, Depth: 2, Values: lowerAll("ImagePath", "ServiceDll"), Category: p, Label: "Services", MinInterval: 60 * time.Second},
		{ID: "lsa", Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Control\Lsa`, Values: lowerAll("Security Packages", "Authentication Packages", "Notification Packages", "RunAsPPL", "DisableRestrictedAdmin", "LmCompatibilityLevel", "NoLMHash", "LimitBlankPasswordUse", "DisableDomainCreds"), Category: ca, Label: "LSA"},
		{ID: "wdigest", Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, Values: lowerAll("UseLogonCredential"), Category: ca, Label: "WDigest"},
		{ID: "defender_excl", Hive: "HKLM", Path: `SOFTWARE\Microsoft\Windows Defender\Exclusions`, Subtree: true, Depth: 1, Category: de, Label: "Defender排除项"},
		{ID: "defender_policy", Hive: "HKLM", Path: `SOFTWARE\Policies\Microsoft\Windows Defender`, Subtree: true, Depth: 2, Category: de, Label: "Defender策略"},
		{ID: "uac", Hive: "HKLM", Path: cv + `\Policies\System`, Values: lowerAll("EnableLUA", "ConsentPromptBehaviorAdmin", "LocalAccountTokenFilterPolicy", "FilterAdministratorToken", "PromptOnSecureDesktop"), Category: de, Label: "UAC策略"},
		{ID: "firewall", Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`, Subtree: true, Depth: 1, Values: lowerAll("EnableFirewall", "DisableNotifications"), Category: de, Label: "防火墙", Severity: "medium", MinInterval: 2 * time.Second},
		{ID: "rdp", Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Control\Terminal Server`, Values: lowerAll("fDenyTSConnections", "fSingleSessionPerUser"), Category: de, Label: "远程桌面", Severity: "medium"},
		// COM：只盯常见 UAC/持久化劫持 CLSID（避免扫全量 Classes\CLSID）
		{ID: "com_fodhelper", Hive: "HKLM", Path: `SOFTWARE\Classes\ms-settings\Shell\Open\command`, Category: pe, Label: "COM(ms-settings)"},
		{ID: "com_eventvwr", Hive: "HKLM", Path: `SOFTWARE\Classes\mscfile\shell\open\command`, Category: pe, Label: "COM(mscfile)"},
		{ID: "com_sdclt", Hive: "HKLM", Path: `SOFTWARE\Classes\Folder\shell\open\command`, Category: pe, Label: "COM(Folder)"},
		// 常见 COM 持久化：TreatAs / InprocServer32 / LocalServer32（精选 CLSID，非全树）
		{ID: "com_treatas_mmdevice", Hive: "HKLM", Path: `SOFTWARE\Classes\CLSID\{BCDE0395-E52F-467C-8E3D-C4579291692E}\TreatAs`, Category: p, Label: "COM TreatAs(MMDevice)", Severity: "medium"},
		{ID: "com_inproc_schedule", Hive: "HKLM", Path: `SOFTWARE\Classes\CLSID\{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}\InprocServer32`, Category: p, Label: "COM Inproc(TaskScheduler)", Severity: "medium"},
		{ID: "com_inproc_wmi", Hive: "HKLM", Path: `SOFTWARE\Classes\CLSID\{76A64158-CB41-11D1-8B02-00600806D9B6}\InprocServer32`, Category: p, Label: "COM Inproc(WbemLocator)", Severity: "medium"},
		{ID: "com_local_iexplore", Hive: "HKLM", Path: `SOFTWARE\Classes\CLSID\{0002DF01-0000-0000-C000-000000000046}\LocalServer32`, Category: p, Label: "COM LocalServer(IE)", Severity: "medium"},
		{ID: "com_inproc_scriptlet", Hive: "HKLM", Path: `SOFTWARE\Classes\CLSID\{64AB4BB7-111E-11D1-8F79-00C04FC2FBE1}\InprocServer32`, Category: p, Label: "COM Inproc(Scriptlet)", Severity: "high"},
		{ID: "office_outlook_addins", Hive: "HKLM", Path: `SOFTWARE\Microsoft\Office\Outlook\Addins`, Subtree: true, Depth: 1, Category: p, Label: "Outlook加载项(HKLM)", Severity: "medium"},
		{ID: "office_excel_addins", Hive: "HKLM", Path: `SOFTWARE\Microsoft\Office\Excel\Addins`, Subtree: true, Depth: 1, Category: p, Label: "Excel加载项(HKLM)", Severity: "medium"},
		{ID: "office_word_addins", Hive: "HKLM", Path: `SOFTWARE\Microsoft\Office\Word\Addins`, Subtree: true, Depth: 1, Category: p, Label: "Word加载项(HKLM)", Severity: "medium"},
		{ID: "office_powerpnt_addins", Hive: "HKLM", Path: `SOFTWARE\Microsoft\Office\PowerPoint\Addins`, Subtree: true, Depth: 1, Category: p, Label: "PPT加载项(HKLM)", Severity: "medium"},
		{ID: "office_vsto_addins", Hive: "HKLM", Path: `SOFTWARE\Microsoft\VSTO\Security\Inclusion`, Subtree: true, Depth: 1, Category: p, Label: "VSTO信任加载项", Severity: "medium"},
		{ID: "office_excel_xlstart", Hive: "HKLM", Path: `SOFTWARE\Microsoft\Office\16.0\Excel\Options`, Values: lowerAll("OPEN", "OPEN1", "OPEN2"), Category: p, Label: "Excel自动打开", Severity: "medium"},
		{ID: "office_word_startup", Hive: "HKLM", Path: `SOFTWARE\Microsoft\Office\16.0\Word\Options`, Values: lowerAll("STARTUP-PATH"), Category: p, Label: "Word Startup路径", Severity: "medium"},
	}
}

// userRegSpecs 已加载用户配置单元（HKU\<SID>）下的关键键。
func userRegSpecs(sid string) []regSpec {
	p := "persistence"
	pe := "privilege_escalation"
	cv := `Software\Microsoft\Windows\CurrentVersion`
	mk := func(id, path, label, cat string, values []string, subtree bool, depth int) regSpec {
		return regSpec{ID: id + ":" + sid, Hive: "HKU", SID: sid, Path: path, Category: cat, Label: label,
			Values: values, Subtree: subtree, Depth: depth}
	}
	return []regSpec{
		mk("hkcu_run", cv+`\Run`, `HKCU\Run`, p, nil, false, 0),
		mk("hkcu_runonce", cv+`\RunOnce`, `HKCU\RunOnce`, p, nil, false, 0),
		mk("hkcu_policy_run", cv+`\Policies\Explorer\Run`, `HKCU\Policies\Run`, p, nil, false, 0),
		mk("hkcu_windows", `Software\Microsoft\Windows NT\CurrentVersion\Windows`, `HKCU\Windows`, p, lowerAll("Load", "Run"), false, 0),
		mk("hkcu_winlogon", `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, `HKCU\Winlogon`, p, lowerAll("Shell"), false, 0),
		mk("hkcu_env", `Environment`, `HKCU\Environment`, p, lowerAll("UserInitMprLogonScript", "COR_PROFILER", "COR_ENABLE_PROFILING"), false, 0),
		mk("hkcu_ms_settings", `Software\Classes\ms-settings\Shell\Open\command`, `UAC绕过(ms-settings)`, pe, nil, false, 0),
		mk("hkcu_mscfile", `Software\Classes\mscfile\shell\open\command`, `UAC绕过(mscfile)`, pe, nil, false, 0),
		mk("hkcu_exefile", `Software\Classes\exefile\shell\open\command`, `exe关联劫持`, pe, nil, false, 0),
		mk("hkcu_outlook_addins", `Software\Microsoft\Office\Outlook\Addins`, `Outlook加载项(HKCU)`, p, nil, true, 1),
		mk("hkcu_excel_addins", `Software\Microsoft\Office\Excel\Addins`, `Excel加载项(HKCU)`, p, nil, true, 1),
		mk("hkcu_word_addins", `Software\Microsoft\Office\Word\Addins`, `Word加载项(HKCU)`, p, nil, true, 1),
		mk("hkcu_ppt_addins", `Software\Microsoft\Office\PowerPoint\Addins`, `PPT加载项(HKCU)`, p, nil, true, 1),
		mk("hkcu_com_scriptlet", `Software\Classes\CLSID\{64AB4BB7-111E-11D1-8F79-00C04FC2FBE1}\InprocServer32`, `COM Inproc(Scriptlet HKCU)`, p, nil, false, 0),
		mk("hkcu_excel_options", `Software\Microsoft\Office\16.0\Excel\Options`, `Excel自动打开(HKCU)`, p, lowerAll("OPEN", "OPEN1"), false, 0),
	}
}
