//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func collectSysinfo() ([]any, error) {
	item := map[string]any{
		"hostname":     hostname(),
		"os_family":    "windows",
		"goos":         runtime.GOOS,
		"goarch":       runtime.GOARCH,
		"ip":           primaryIP(),
		"agent_ver":    agentVersion,
		"collected_at": time.Now().Format("2006-01-02T15:04:05"),
		"num_cpu":      runtime.NumCPU(),
	}
	ps := `
Get-CimInstance Win32_OperatingSystem | ForEach-Object {
  $os = $_
  $cs = Get-CimInstance Win32_ComputerSystem
  [PSCustomObject]@{
    caption = [string]$os.Caption
    version = [string]$os.Version
    build = [string]$os.BuildNumber
    install_date = if($os.InstallDate){$os.InstallDate.ToString('s')}else{''}
    last_boot = if($os.LastBootUpTime){$os.LastBootUpTime.ToString('s')}else{''}
    manufacturer = [string]$cs.Manufacturer
    model = [string]$cs.Model
    domain = [string]$cs.Domain
    total_ram_mb = [int]($cs.TotalPhysicalMemory/1MB)
    user = [string]$env:USERNAME
    logged_user = [string]$cs.UserName
    mac = [string]((Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | Where-Object { $_.DefaultIPGateway } | Select-Object -First 1).MACAddress)
  }
}
`
	if rows := decodeJSONRows(runPS(ps)); len(rows) > 0 {
		for k, v := range rows[0] {
			item[k] = v
		}
	}
	return []any{item}, nil
}

func collectServices() ([]any, error) {
	// 优先 CIM（经 UTF-8 落盘），失败再用 SCM API（UTF-16，无乱码）
	ps := `
Get-CimInstance Win32_Service | ForEach-Object {
  [PSCustomObject]@{
    name = [string]$_.Name
    display_name = [string]$_.DisplayName
    status = [string]$_.State
    start_type = [string]$_.StartMode
    path = [string]$_.PathName
    pid = [int]$_.ProcessId
    account = [string]$_.StartName
    description = [string]$_.Description
    exit_code = [int]$_.ExitCode
  }
}
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		name := asString(r["name"])
		if name == "" {
			continue
		}
		out = append(out, map[string]any{
			"name":         name,
			"display_name": asString(r["display_name"]),
			"status":       asString(r["status"]),
			"start_type":   asString(r["start_type"]),
			"path":         asString(r["path"]),
			"pid":          asInt(r["pid"]),
			"account":      asString(r["account"]),
			"description":  asString(r["description"]),
			"exit_code":    asInt(r["exit_code"]),
		})
	}
	if len(out) > 0 {
		enrichPEMeta(out, "path", 40)
		return applyRiskAndSort(out, "service"), nil
	}
	out, err := collectServicesSCM()
	if err != nil {
		return out, err
	}
	enrichPEMeta(out, "path", 40)
	return applyRiskAndSort(out, "service"), nil
}

func collectServicesSCM() ([]any, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(names))
	for _, name := range names {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		cfg, err := s.Config()
		st, _ := s.Query()
		s.Close()
		status := "Unknown"
		switch st.State {
		case svc.Stopped:
			status = "Stopped"
		case svc.StartPending:
			status = "StartPending"
		case svc.StopPending:
			status = "StopPending"
		case svc.Running:
			status = "Running"
		case svc.ContinuePending:
			status = "ContinuePending"
		case svc.PausePending:
			status = "PausePending"
		case svc.Paused:
			status = "Paused"
		}
		startType := ""
		if err == nil {
			switch cfg.StartType {
			case mgr.StartAutomatic:
				startType = "Automatic"
			case mgr.StartManual:
				startType = "Manual"
			case mgr.StartDisabled:
				startType = "Disabled"
			default:
				startType = strconv.FormatUint(uint64(cfg.StartType), 10)
			}
			out = append(out, map[string]any{
				"name":         name,
				"display_name": cfg.DisplayName,
				"status":       status,
				"start_type":   startType,
				"path":         cfg.BinaryPathName,
				"pid":          0,
			})
		} else {
			out = append(out, map[string]any{
				"name": name, "status": status,
			})
		}
	}
	return out, nil
}

func collectTasks() ([]any, error) {
	ps := `
Get-ScheduledTask | ForEach-Object {
  $t = $_
  $info = $null
  try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath } catch {}
  $a = $t.Actions | Select-Object -First 1
  $cmd = ''
  $wd = ''
  $exe = ''
  $args = ''
  if($a){
    $wd = [string]$a.WorkingDirectory
    $exe = [string]$a.Execute
    $args = [string]$a.Arguments
    $cmd = (($exe + ' ' + $args).Trim())
  }
  $trigs = @()
  foreach($tr in @($t.Triggers)){
    if($tr){ $trigs += [string]$tr.CimClass.CimClassName.Replace('MSFT_Task','').Replace('Trigger','') }
  }
  [PSCustomObject]@{
    task_name = ($t.TaskPath.TrimEnd('\') + '\' + $t.TaskName).Replace('\\','\')
    status = [string]$t.State
    author = [string]$t.Author
    description = [string]$t.Description
    command = $cmd
    execute = $exe
    arguments = $args
    working_directory = $wd
    last_run = if($info -and $info.LastRunTime){$info.LastRunTime.ToString('s')}else{''}
    next_run = if($info -and $info.NextRunTime){$info.NextRunTime.ToString('s')}else{''}
    last_result = if($info){[string]$info.LastTaskResult}else{''}
    triggers = ($trigs -join ',')
  }
}
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		name := asString(r["task_name"])
		if name == "" {
			continue
		}
		out = append(out, map[string]any{
			"task_name":         name,
			"status":            asString(r["status"]),
			"author":            asString(r["author"]),
			"description":       asString(r["description"]),
			"command":           asString(r["command"]),
			"execute":           asString(r["execute"]),
			"arguments":         asString(r["arguments"]),
			"working_directory": asString(r["working_directory"]),
			"last_run":          asString(r["last_run"]),
			"next_run":          asString(r["next_run"]),
			"last_result":       asString(r["last_result"]),
			"triggers":          asString(r["triggers"]),
			"path":              asString(r["execute"]),
		})
	}
	return applyRiskAndSort(out, "task"), nil
}

func collectStartup() ([]any, error) {
	var out []any
	addReg := func(root registry.Key, path, location string) {
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
			out = append(out, map[string]any{
				"location": location,
				"name":     n,
				"command":  val,
				"path":     extractExe(val),
			})
		}
	}
	addReg(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Run`)
	addReg(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\RunOnce`)
	addReg(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\Run`)
	addReg(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKCU\RunOnce`)
	addReg(registry.LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Wow6432Node\Run`)

	for _, dir := range startupFolders() {
		_ = filepath.WalkDir(dir.path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext != ".lnk" && ext != ".url" && ext != ".bat" && ext != ".cmd" && ext != ".exe" && ext != ".vbs" && ext != ".ps1" {
				return nil
			}
			item := map[string]any{
				"location":      dir.label,
				"name":          d.Name(),
				"command":       p,
				"shortcut_path": p,
				"path":          p,
				"user":          dir.user,
			}
			if sc, ok := parseShortcutFile(p); ok {
				item["shortcut_kind"] = sc.Kind
				if sc.TargetPath != "" {
					item["shortcut_target"] = sc.TargetPath
					item["path"] = sc.TargetPath
					item["command"] = sc.commandLine()
					item["execute"] = sc.TargetPath
				}
				if sc.Arguments != "" {
					item["arguments"] = sc.Arguments
				}
				if sc.WorkingDir != "" {
					item["working_directory"] = sc.WorkingDir
				}
				if sc.URL != "" {
					item["url"] = sc.URL
					item["path"] = sc.URL
					item["command"] = sc.URL
				}
			}
			out = append(out, item)
			return nil
		})
	}
	// 启动项用进程同款可疑路径打分，便于「仅可疑」筛选
	for _, it := range out {
		if m, ok := it.(map[string]any); ok {
			scoreProcess(m)
			if pathLooksSuspicious(asString(m["command"])) || pathLooksSuspicious(asString(m["path"])) {
				m["noise"] = false
				if asInt(m["risk_score"]) < 20 {
					m["risk_score"] = 25
					m["risk_tags"] = "启动项"
				}
			}
		}
	}
	sortByRisk(out)
	return truncateItems(out), nil
}

type startupDir struct {
	path  string
	label string
	user  string
}

func startupFolders() []startupDir {
	var dirs []startupDir
	if p := os.Getenv("ProgramData"); p != "" {
		dirs = append(dirs, startupDir{
			path:  filepath.Join(p, `Microsoft\Windows\Start Menu\Programs\Startup`),
			label: "CommonStartup",
			user:  "AllUsers",
		})
	}
	if app := os.Getenv("APPDATA"); app != "" {
		dirs = append(dirs, startupDir{
			path:  filepath.Join(app, `Microsoft\Windows\Start Menu\Programs\Startup`),
			label: "UserStartup",
			user:  os.Getenv("USERNAME"),
		})
	}
	return dirs
}

func extractExe(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if strings.HasPrefix(cmd, `"`) {
		if i := strings.Index(cmd[1:], `"`); i >= 0 {
			return cmd[1 : i+1]
		}
	}
	parts := strings.Fields(cmd)
	if len(parts) > 0 {
		return parts[0]
	}
	return cmd
}

func collectNetwork() ([]any, error) {
	raw, _ := runCmd(30*time.Second, "netstat", "-ano")
	var out []any
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		proto := strings.ToUpper(fields[0])
		if proto != "TCP" && proto != "UDP" && proto != "TCPv6" && proto != "UDPv6" {
			continue
		}
		local := fields[1]
		remote := fields[2]
		state := ""
		pidStr := ""
		if strings.HasPrefix(proto, "TCP") {
			if len(fields) < 5 {
				continue
			}
			state = fields[3]
			pidStr = fields[4]
		} else {
			pidStr = fields[len(fields)-1]
		}
		if !isAllDigits(pidStr) {
			continue
		}
		out = append(out, map[string]any{
			"proto":  proto,
			"local":  local,
			"remote": remote,
			"state":  state,
			"pid":    pidStr,
		})
	}
	out = truncateItems(out)
	attachProcessNamesToNetwork(out, quickPIDNames())
	return out, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// collectProcessesLite：仅枚举进程基础字段，供时间线差分；不做 PE/模块 PowerShell 富化。
func collectProcessesLite() ([]any, error) {
	out, err := collectProcessesNative()
	if err != nil || len(out) == 0 {
		return nil, err
	}
	out = truncateItems(out)
	attachParentAndUptime(out)
	return out, nil
}

var processEnrichTick uint64

func collectProcesses() ([]any, error) {
	if out, err := collectProcessesNative(); err == nil && len(out) > 0 {
		out = truncateItems(out)
		attachParentAndUptime(out)
		enrichProcessIdentity(out)
		// 验签/哈希较重：每轮最多补少量；模块枚举再降到约每 6 轮一次
		enrichPEMeta(out, "path", 12)
		out = applyRiskAndSort(out, "process")
		if atomic.AddUint64(&processEnrichTick, 1)%6 == 1 {
			enrichProcessModules(out, 8)
		}
		return out, nil
	}
	ps := `
Get-CimInstance Win32_Process | ForEach-Object {
  $p = $_
  $owner = ''
  try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner; if($o){ $owner = ($o.Domain + '\' + $o.User).Trim('\') } } catch {}
  [PSCustomObject]@{
    pid = [int]$p.ProcessId
    ppid = [int]$p.ParentProcessId
    name = [string]$p.Name
    path = [string]$p.ExecutablePath
    command_line = [string]$p.CommandLine
    user = $owner
    session_id = [int]$p.SessionId
    create_time = if($p.CreationDate){$p.CreationDate.ToString('s')}else{''}
    memory_mb = if($p.WorkingSetSize){[math]::Round($p.WorkingSetSize/1MB,1)}else{0}
    handles = [int]$p.HandleCount
    company = ''
  }
}
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		name := asString(r["name"])
		if name == "" {
			continue
		}
		pid := asInt(r["pid"])
		ct := asString(r["create_time"])
		item := map[string]any{
			"pid":          pid,
			"ppid":         asInt(r["ppid"]),
			"name":         name,
			"path":         asString(r["path"]),
			"command_line": asString(r["command_line"]),
			"user":         asString(r["user"]),
			"session_id":   asInt(r["session_id"]),
			"create_time":  ct,
			"memory_mb":    r["memory_mb"],
			"handles":      asInt(r["handles"]),
			// 稳定进程 ID：防 PID 复用（OpenEDR pid+creationTime）
			"process_guid": fmt.Sprintf("%d_%s", pid, ct),
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		raw, _ := runCmd(45*time.Second, "tasklist", "/FO", "CSV", "/NH")
		csvRows := parseCSV(raw)
		for _, cols := range csvRows {
			if len(cols) < 2 {
				continue
			}
			name := strings.TrimSpace(cols[0])
			pid, _ := strconv.Atoi(strings.TrimSpace(cols[1]))
			if name == "" {
				continue
			}
			out = append(out, map[string]any{"pid": pid, "name": name})
		}
	}
	out = truncateItems(out)
	attachParentAndUptime(out)
	enrichProcessIdentity(out)
	enrichPEMeta(out, "path", 12)
	out = applyRiskAndSort(out, "process")
	if atomic.AddUint64(&processEnrichTick, 1)%6 == 1 {
		enrichProcessModules(out, 8)
	}
	return out, nil
}

// collectFilesLite：时间线差分用，不做 PE 哈希/验签。
func collectFilesLite() ([]any, error) {
	items, err := collectFilesRaw()
	if err != nil {
		return nil, err
	}
	return truncateItems(items), nil
}

func collectFiles() ([]any, error) {
	out, err := collectFilesRaw()
	if err != nil {
		return nil, err
	}
	out = truncateItems(out)
	enrichPEMeta(out, "path", 20)
	sortByRisk(out)
	return out, nil
}

func collectFilesRaw() ([]any, error) {
	// 高危目录 + 盘符根目录一层：近期可执行/脚本（供文件规则 / 根目录投放检测）
	ps := `
$ext = @('*.exe','*.dll','*.sys','*.ps1','*.bat','*.cmd','*.vbs','*.js','*.jse','*.wsf','*.hta','*.scr')
$roots = @(
  $env:TEMP,
  $env:TMP,
  (Join-Path $env:LOCALAPPDATA 'Temp'),
  $env:PUBLIC,
  (Join-Path $env:PUBLIC 'Downloads'),
  (Join-Path $env:USERPROFILE 'Downloads'),
  (Join-Path $env:USERPROFILE 'Desktop'),
  'C:\Windows\Temp',
  'C:\ProgramData'
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
$cutoff = (Get-Date).AddDays(-14)
$__rows = @()
# 盘符根目录只扫一层（C:\evil.exe），不递归
foreach($drive in @('C:\','D:\','E:\')) {
  if(-not (Test-Path -LiteralPath $drive)){ continue }
  foreach($pat in $ext){
    try {
      Get-ChildItem -LiteralPath $drive -Filter $pat -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $cutoff } |
        Select-Object -First 40 | ForEach-Object {
          $__rows += [PSCustomObject]@{
            name = [string]$_.Name
            path = [string]$_.FullName
            ext = [string]$_.Extension.ToLower()
            size = [int64]$_.Length
            size_kb = [math]::Round($_.Length/1KB,1)
            modified = $_.LastWriteTime.ToString('s')
            created = $_.CreationTime.ToString('s')
            directory = [string]$_.DirectoryName
            location = [string]$drive
            root_drop = $true
          }
        }
    } catch {}
  }
}
foreach($root in $roots){
  foreach($pat in $ext){
    try {
      Get-ChildItem -LiteralPath $root -Filter $pat -File -Recurse -Depth 3 -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $cutoff } |
        Select-Object -First 80 | ForEach-Object {
          $__rows += [PSCustomObject]@{
            name = [string]$_.Name
            path = [string]$_.FullName
            ext = [string]$_.Extension.ToLower()
            size = [int64]$_.Length
            size_kb = [math]::Round($_.Length/1KB,1)
            modified = $_.LastWriteTime.ToString('s')
            created = $_.CreationTime.ToString('s')
            directory = [string]$_.DirectoryName
            location = [string]$root
            root_drop = $false
          }
        }
    } catch {}
    if($__rows.Count -ge 400){ break }
  }
  if($__rows.Count -ge 400){ break }
}
$__rows | Select-Object -First 400
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		p := asString(r["path"])
		if p == "" || isAgentSelfNoisePath(p) {
			continue
		}
		item := map[string]any{
			"name":      asString(r["name"]),
			"path":      p,
			"ext":       asString(r["ext"]),
			"size":      asInt(r["size"]),
			"size_kb":   r["size_kb"],
			"modified":  asString(r["modified"]),
			"created":   asString(r["created"]),
			"directory": asString(r["directory"]),
			"location":  asString(r["location"]),
		}
		switch v := r["root_drop"].(type) {
		case bool:
			if v {
				item["root_drop"] = true
				item["risk_tags"] = "根目录投放"
				item["risk_score"] = 50
			}
		case string:
			if strings.EqualFold(v, "true") || v == "1" {
				item["root_drop"] = true
				item["risk_tags"] = "根目录投放"
				item["risk_score"] = 50
			}
		}
		out = append(out, item)
	}
	return out, nil
}

func collectUsers() ([]any, error) {
	ps := `
$__rows = @()
try {
  Get-LocalUser | ForEach-Object {
    $__rows += [PSCustomObject]@{
      name = [string]$_.Name
      enabled = [bool]$_.Enabled
      description = [string]$_.Description
      last_logon = if($_.LastLogon){$_.LastLogon.ToString('s')}else{''}
      password_required = [bool]$_.PasswordRequired
      principal = [string]$_.SID
      source = 'local_user'
    }
  }
} catch {}
try {
  quser 2>$null | Select-Object -Skip 1 | ForEach-Object {
    $line = ($_ -replace '\s{2,}','|').Trim()
    $p = $line -split '\|'
    if($p.Count -ge 3){
      $__rows += [PSCustomObject]@{
        name = [string]$p[0].Trim()
        session = [string]$p[1].Trim()
        state = [string]$p[2].Trim()
        source = 'session'
      }
    }
  }
} catch {}
$__rows
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		name := asString(r["name"])
		if name == "" {
			continue
		}
		item := map[string]any{
			"name":   name,
			"source": asString(r["source"]),
		}
		for _, k := range []string{"enabled", "description", "last_logon", "password_required", "principal", "session", "state"} {
			if v, ok := r[k]; ok && v != nil && asString(v) != "" {
				item[k] = v
			}
		}
		out = append(out, item)
	}
	return truncateItems(out), nil
}
