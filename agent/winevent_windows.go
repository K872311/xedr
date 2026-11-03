//go:build windows

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// winEventWatcher：Wazuh 风格 Event Log 订阅（登录/账号/服务/任务），默认 XPath 压噪。
type winEventWatcher struct {
	mu          sync.Mutex
	events      []map[string]any
	cancel      context.CancelFunc
	running     bool
	bookmarkDir string
}

func newWinEventWatcher() *winEventWatcher { return &winEventWatcher{} }

func (w *winEventWatcher) start(ctx context.Context) {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	cctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.running = true
	w.mu.Unlock()
	go w.loop(cctx)
}

func (w *winEventWatcher) stop() {
	w.mu.Lock()
	if w.cancel != nil {
		w.cancel()
	}
	w.running = false
	w.mu.Unlock()
}

func (w *winEventWatcher) drain() []map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.events
	w.events = nil
	if len(out) > 200 {
		// 一次最多转发 200 条，剩余留到下一轮，避免突发时整批丢弃
		w.events = append([]map[string]any(nil), out[200:]...)
		return out[:200]
	}
	return out
}

func (w *winEventWatcher) push(ev map[string]any) {
	if isTimelineNoiseEvent(ev) {
		return
	}
	teleIncSource(ev)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, ev)
	if len(w.events) > 400 {
		w.events = w.events[len(w.events)-400:]
	}
}

func (w *winEventWatcher) loop(ctx context.Context) {
	dir := w.bookmarkDir
	if dir == "" && globalCfg.StateDir != "" {
		dir = filepath.Join(globalCfg.StateDir, "bookmarks")
	}
	if dir != "" {
		err := winevtTryNative(ctx, dir, w.push)
		if err == nil || ctx.Err() != nil {
			return
		}
		log.Printf("winevent: wevtapi 不可用 (%v)，回退 PowerShell", err)
	}
	w.loopPowerShell(ctx)
}

func (w *winEventWatcher) loopPowerShell(ctx context.Context) {
	ps := winEventSubscribeScript()
	tmp, err := os.CreateTemp("", "fa-wevt-*.ps1")
	if err != nil {
		log.Printf("winevent: temp %v", err)
		return
	}
	path := tmp.Name()
	_, _ = tmp.Write([]byte{0xEF, 0xBB, 0xBF})
	_, _ = tmp.WriteString(ps)
	_ = tmp.Close()
	defer os.Remove(path)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
		hideWindow(cmd)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		if err := cmd.Start(); err != nil {
			log.Printf("winevent start: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("winevent: subscriber started (%s)", filepath.Base(path))
		rd := bufio.NewReader(stdout)
		for {
			select {
			case <-ctx.Done():
				_ = cmd.Process.Kill()
				return
			default:
			}
			line, err := rd.ReadBytes('\n')
			if len(line) > 0 {
				var raw map[string]any
				if json.Unmarshal(line, &raw) == nil && raw["etype"] != nil {
					w.push(raw)
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("winevent read: %v", err)
				}
				break
			}
		}
		_ = cmd.Wait()
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func winEventSubscribeScript() string {
	// 压噪：不订 5156/4663/4656 等高量审计；只订登录/账号/服务/任务/进程访问(Sysmon10)
	return `
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$queue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
function Enq($obj){ [void]$queue.Enqueue(($obj | ConvertTo-Json -Compress -Depth 6)) }

$queries = @()
try {
  $null = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
  $xpath = @'
*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4697 or EventID=4698 or EventID=4702 or EventID=1102)]]
'@
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Security',[System.Diagnostics.Eventing.Reader.PathType]::LogName,$xpath.Trim())
  $queries += @{ Name='security'; Query=$q }
} catch {}
try {
  $null = Get-WinEvent -ListLog 'System' -ErrorAction Stop
  $xpath = '*[System[(EventID=7045 or EventID=7036 or EventID=7040)]]'
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('System',[System.Diagnostics.Eventing.Reader.PathType]::LogName,$xpath)
  $queries += @{ Name='system'; Query=$q }
} catch {}
try {
  $null = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
  $xpath = '*[System[(EventID=8 or EventID=10 or EventID=13 or EventID=22)]]'
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Microsoft-Windows-Sysmon/Operational',[System.Diagnostics.Eventing.Reader.PathType]::LogName,$xpath)
  $queries += @{ Name='sysmon_extra'; Query=$q }
} catch {}
# 可选：需本机开启 PowerShell 模块/脚本块日志（见安装包 README）
try {
  $null = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction Stop
  $xpath = '*[System[(EventID=4103 or EventID=4104)]]'
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Microsoft-Windows-PowerShell/Operational',[System.Diagnostics.Eventing.Reader.PathType]::LogName,$xpath)
  $queries += @{ Name='powershell'; Query=$q }
} catch {}

if($queries.Count -eq 0){
  Enq @{ etype='winevent_status'; summary='Windows 事件通道不可用'; severity='info'; ts=(Get-Date).ToString('s') }
  while($true){ Start-Sleep -Seconds 30 }
}

foreach($item in $queries){
  try {
    $watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($item.Query)
    $watcher.Enabled = $true
    $null = Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -MessageData $queue -Action {
      try {
        $rec = $Event.SourceEventArgs.EventRecord
        if(-not $rec){ return }
        $q = $Event.MessageData
        $xml = [xml]$rec.ToXml()
        $data = @{}
        foreach($n in $xml.Event.EventData.Data){ if($n.Name){ $data[$n.Name]=[string]$n.'#text' } }
        $eid=[int]$rec.Id
        $ts=$rec.TimeCreated.ToString('s')
        $chan=[string]$rec.LogName
        $obj=$null
        switch($eid){
          4624 {
            $logonType=[string]$data['LogonType']
            if($logonType -in @('0','5','11')){ return } # 系统/服务/缓存噪声
            $user=[string]$data['TargetUserName']
            if($user -in @('ANONYMOUS LOGON','SYSTEM','LOCAL SERVICE','NETWORK SERVICE')){ return }
            if($user -match '(?i)^(DWM-|UMFD-)' -or $user.EndsWith('$')){ return }
            $ip=[string]$data['IpAddress']
            if($logonType -eq '3' -and ($ip -in @('127.0.0.1','::1','-',''))){ return }
            $obj=@{ etype='win_logon'; summary=('登录成功: '+$user+' type='+$logonType); severity='info'; ts=$ts; detail=@{
              source='security'; event_id=$eid; user=$user; domain=[string]$data['TargetDomainName']
              logon_type=$logonType; ip=$ip; process=[string]$data['ProcessName']
            } }
          }
          4625 {
            $u=[string]$data['TargetUserName']
            if($u.EndsWith('$') -or $u -in @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','-','')){ return }
            # 单次失败只进时间线；暴破由后端/规则按频次判断
            $obj=@{ etype='win_logon_fail'; summary=('登录失败: '+$u); severity='info'; ts=$ts; detail=@{
              source='security'; event_id=$eid; user=$u; ip=[string]$data['IpAddress']
              status=[string]$data['Status']; substatus=[string]$data['SubStatus']
            } }
          }
          4648 {
            $proc=[string]$data['ProcessName']
            if($proc -match '(?i)\\(svchost|taskhostw|trustedinstaller|lsass|services|winlogon|consent)\.exe$'){ return }
            $obj=@{ etype='win_explicit_logon'; summary=('显式凭据登录: '+[string]$data['TargetUserName']); severity='info'; ts=$ts; detail=@{
              source='security'; event_id=$eid; user=[string]$data['TargetUserName']; process=$proc
              target=[string]$data['TargetServerName']
            } }
          }
          4720 { $obj=@{ etype='win_account_create'; summary=('账号创建: '+[string]$data['TargetUserName']); severity='high'; ts=$ts; detail=@{ source='security'; event_id=$eid; user=[string]$data['TargetUserName']; by=[string]$data['SubjectUserName'] } } }
          4722 { $obj=@{ etype='win_account_enable'; summary=('账号启用: '+[string]$data['TargetUserName']); severity='medium'; ts=$ts; detail=@{ source='security'; event_id=$eid; user=[string]$data['TargetUserName'] } } }
          4724 { $obj=@{ etype='win_password_reset'; summary=('密码重置: '+[string]$data['TargetUserName']); severity='medium'; ts=$ts; detail=@{ source='security'; event_id=$eid; user=[string]$data['TargetUserName'] } } }
          4728 { $obj=@{ etype='win_group_add'; summary=('加入组: '+[string]$data['MemberName']+' → '+[string]$data['TargetUserName']); severity='high'; ts=$ts; detail=@{ source='security'; event_id=$eid; member=[string]$data['MemberName']; group=[string]$data['TargetUserName'] } } }
          4732 { $obj=@{ etype='win_group_add'; summary=('加入本地组: '+[string]$data['MemberName']+' → '+[string]$data['TargetUserName']); severity='high'; ts=$ts; detail=@{ source='security'; event_id=$eid; member=[string]$data['MemberName']; group=[string]$data['TargetUserName'] } } }
          4756 { $obj=@{ etype='win_group_add'; summary=('加入通用组: '+[string]$data['MemberName']+' → '+[string]$data['TargetUserName']); severity='high'; ts=$ts; detail=@{ source='security'; event_id=$eid; member=[string]$data['MemberName']; group=[string]$data['TargetUserName'] } } }
          4697 {
            $sp=[string]$data['ServiceFileName']
            if($sp -match '(?i)\\windows\\(system32|syswow64|winsxs)\\'){ return }
            $obj=@{ etype='win_service_install'; summary=('服务安装: '+[string]$data['ServiceName']); severity='high'; ts=$ts; detail=@{ source='security'; event_id=$eid; name=[string]$data['ServiceName']; path=$sp; account=[string]$data['ServiceAccount'] } }
          }
          4698 {
            $tn=[string]$data['TaskName']
            if($tn -match '(?i)^\\Microsoft\\'){ return }
            $obj=@{ etype='win_task_create'; summary=('计划任务创建: '+$tn); severity='high'; ts=$ts; detail=@{ source='security'; event_id=$eid; task=$tn; content=[string]$data['TaskContent'] } }
          }
          4702 {
            $tn=[string]$data['TaskName']
            if($tn -match '(?i)^\\Microsoft\\'){ return }
            $obj=@{ etype='win_task_update'; summary=('计划任务更新: '+$tn); severity='info'; ts=$ts; detail=@{ source='security'; event_id=$eid; task=$tn } }
          }
          1102 { $obj=@{ etype='win_audit_clear'; summary='安全日志被清空'; severity='critical'; ts=$ts; detail=@{ source='security'; event_id=$eid } } }
          4672 {
            $su=[string]$data['SubjectUserName']
            if($su -in @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE') -or $su.EndsWith('$') -or $su -match '(?i)^(DWM-|UMFD-)'){ return }
            $priv=[string]$data['PrivilegeList']
            if(-not $priv -or $priv -notmatch '(?i)SeDebugPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege'){ return }
            # 管理员交互登录常带 Impersonate；仅 Debug/Tcb/LoadDriver 进时间线，且不作中危告警
            $obj=@{ etype='win_special_priv'; summary=('特殊权限分配: '+$su); severity='info'; ts=$ts; detail=@{
              source='security'; event_id=$eid; user=$su; domain=[string]$data['SubjectDomainName']; privileges=$priv
            } }
          }
          7045 {
            $ip=[string]$data['ImagePath']
            if($ip -match '(?i)\\windows\\(system32|syswow64|winsxs)\\'){ return }
            $obj=@{ etype='win_service_install'; summary=('服务安装: '+[string]$data['ServiceName']); severity='high'; ts=$ts; detail=@{
              source='system'; event_id=$eid; name=[string]$data['ServiceName']; path=$ip
              account=[string]$data['AccountName']; start_type=[string]$data['StartType']
            } }
          }
          7036 {
            $obj=@{ etype='win_service_state'; summary=('服务状态: '+[string]$data['param1']+' → '+[string]$data['param2']); severity='info'; ts=$ts; detail=@{
              source='system'; event_id=$eid; name=[string]$data['param1']; state=[string]$data['param2']
            } }
          }
          7040 {
            $disp=[string]$data['param1']
            # param4 为服务短名（中英文系统一致）；无则退回显示名
            $short=[string]$data['param4']
            if(-not $short){ $short=$disp }
            $noise='(?i)^(BITS|wuauserv|UsoSvc|DoSvc|TrustedInstaller|WaaSMedicSvc|wlidsvc|DiagTrack|WpnService|SystemEventsBroker|WinDefend|WdNisSvc|Sense|edgeupdate|edgeupdatem|gupdate|gupdatem|gpsvc|Schedule|WSearch|SysMain|ClickToRunSvc|MapsBroker|lfsvc|InstallService|AppXSvc|ClipSVC|StorSvc|TokenBroker|CDPSvc|CDPUserSvc.*|OneSyncSvc.*|PimIndexMaintenanceSvc.*|UnistoreSvc.*|UserDataSvc.*|WpnUserService.*)$'
            if($short -match $noise){ return }
            # 只关心改成「禁用」或非系统映像的启动类型变更
            $to=[string]$data['param3']
            if($to -notmatch '(?i)(disabled|禁用)'){ return }
            $obj=@{ etype='win_service_config'; summary=('服务被禁用: '+$disp); severity='medium'; ts=$ts; detail=@{
              source='system'; event_id=$eid; name=$disp; service=$short; from=[string]$data['param2']; to=$to
            } }
          }
          4103 {
            $payload=[string]$data['Payload']
            if(-not $payload){ $payload=[string]$data['MessageNumber'] }
            $snip = if($payload.Length -gt 180){ $payload.Substring(0,180)+'…' } else { $payload }
            $obj=@{ etype='win_ps_module'; summary=('PowerShell 模块日志: '+$snip); severity='info'; ts=$ts; detail=@{
              source='powershell'; event_id=$eid; payload=$payload; context=[string]$data['ContextInfo']
            } }
          }
          4104 {
            $script=[string]$data['ScriptBlockText']
            if(-not $script){ return }
            $sev='info'; $sum='PowerShell 脚本块'
            if($script -match '(?i)(-enc|frombase64string|iex\s|invoke-expression|downloadstring|system\.reflection\.assembly)'){
              $sev='high'; $sum='可疑 PowerShell 脚本块'
            }
            $snip = if($script.Length -gt 160){ $script.Substring(0,160)+'…' } else { $script }
            $obj=@{ etype='win_ps_scriptblock'; summary=($sum+': '+$snip); severity=$sev; ts=$ts; detail=@{
              source='powershell'; event_id=$eid; script_block=$script
              script_block_id=[string]$data['ScriptBlockId']; path=[string]$data['Path']
            } }
          }
          8 {
            $src=[string]$data['SourceImage']
            if($src -match '(?i)\\(MsMpEng|NisSrv|csrss|wininit|services|lsass|svchost|smss|dwm|audiodg|MpDefenderCoreService|SecurityHealthService)\.exe$'){ return }
            if($src -match '(?i)\\(chrome|msedge|firefox|opera|brave)\.exe$' -and [string]$data['TargetImage'] -match '(?i)\\(chrome|msedge|firefox|opera|brave)\.exe$'){ return }
            $obj=@{ etype='remote_thread'; summary=('远程线程(Sysmon): '+[IO.Path]::GetFileName($src)+' → '+[IO.Path]::GetFileName([string]$data['TargetImage'])); severity='high'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$src; target_path=[string]$data['TargetImage']
              pid=[int]($data['SourceProcessId']); target_pid=[int]($data['TargetProcessId']); start_address=[string]$data['StartAddress']
            } }
          }
          10 {
            $am=[string]$data['GrantedAccess']
            if(-not $am){ return }
            # 按位判断：仅 VM_WRITE(0x20) / CREATE_THREAD(0x2) / VM_OPERATION(0x8) / 全权限
            $mask=0
            try { $mask=[Convert]::ToInt64(($am -replace '^0x',''),16) } catch { return }
            $want=0x20 -bor 0x2 -bor 0x8
            if((($mask -band $want) -eq 0) -and ($mask -ne 0x1FFFFF) -and ($mask -ne 0x1F0FFF)){ return }
            $src=[string]$data['SourceImage']
            if($src -match '(?i)\\(MsMpEng|NisSrv|csrss|wininit|services|lsass|svchost|taskmgr|procexp|procexp64|vmtoolsd)\.exe$'){ return }
            $obj=@{ etype='process_access'; summary=('进程打开(Sysmon): '+[IO.Path]::GetFileName($src)+' → '+[IO.Path]::GetFileName([string]$data['TargetImage'])); severity='medium'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$src; target_path=[string]$data['TargetImage']
              pid=[int]($data['SourceProcessId']); target_pid=[int]($data['TargetProcessId']); access=$am
              call_trace=[string]$data['CallTrace']
            } }
          }
          13 {
            $to=[string]$data['TargetObject']
            # 只保留 ASEP / 安全相关键
            if($to -notmatch '(?i)\\(CurrentVersion\\Run|RunOnce|Winlogon|Image File Execution Options|AppInit_DLLs|Services\\[^\\]+\\(ImagePath|ServiceDll)|Windows Defender\\Exclusions|Policies\\Microsoft\\Windows Defender|Lsa\\|WDigest)'){ return }
            $obj=@{ etype='registry_write'; summary=('注册表写入(Sysmon): '+$to); severity='medium'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; path=$to; value=[string]$data['Details']
              pid=[int]($data['ProcessId']); process_name=[IO.Path]::GetFileName([string]$data['Image'])
            } }
          }
          22 {
            $qname=[string]$data['QueryName']
            if(-not $qname -or $qname -match '(?i)\.(arpa|local)$'){ return }
            $obj=@{ etype='dns_query'; summary=('DNS(Sysmon): '+$qname); severity='info'; ts=$ts; detail=@{
              source='sysmon'; event_id=$eid; query=$qname; type=[string]$data['QueryType']
              pid=[int]($data['ProcessId']); process_name=[IO.Path]::GetFileName([string]$data['Image'])
            } }
          }
        }
        if($obj){
          if($obj.detail -is [hashtable]){ $obj.detail['channel'] = $chan }
          [void]$q.Enqueue(($obj | ConvertTo-Json -Compress -Depth 6))
        }
      } catch {}
    }
  } catch {}
}

Enq @{ etype='winevent_status'; summary=('事件通道: '+(($queries|ForEach-Object Name) -join ',')); severity='info'; ts=(Get-Date).ToString('s'); detail=@{ sources=@($queries|ForEach-Object Name) } }
while($true){
  $line=$null
  while($queue.TryDequeue([ref]$line)){ Write-Output $line }
  Start-Sleep -Milliseconds 250
}
`
}
