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

// etwWatcher：优先原生实时 ETW 会话（etw_native_windows.go），
// 失败时回退 Sysmon / Security 4688 事件日志订阅。
type etwWatcher struct {
	mu      sync.Mutex
	events  []map[string]any
	cancel  context.CancelFunc
	running bool
	mode    string
}

func newETWWatcher() *etwWatcher {
	return &etwWatcher{}
}

func (w *etwWatcher) start(ctx context.Context) {
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

func (w *etwWatcher) stop() {
	w.mu.Lock()
	if w.cancel != nil {
		w.cancel()
	}
	w.running = false
	w.mu.Unlock()
}

func (w *etwWatcher) drain() []map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.events
	w.events = nil
	if len(out) > 300 {
		// 一次最多转发 300 条，剩余留到下一轮，避免突发时整批丢弃
		w.events = append([]map[string]any(nil), out[300:]...)
		return out[:300]
	}
	return out
}

func (w *etwWatcher) push(ev map[string]any) {
	if isTimelineNoiseEvent(ev) {
		return
	}
	teleIncSource(ev)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, ev)
	if et, _ := ev["etype"].(string); et == "process_create_etw" || et == "process_create_live" || et == "process_create" {
		if pe := privEscFromProcessEvent(ev); pe != nil && !isTimelineNoiseEvent(pe) {
			w.events = append(w.events, pe)
		}
	}
	if len(w.events) > 600 {
		w.events = w.events[len(w.events)-600:]
	}
}

func (w *etwWatcher) status() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.running {
		return "stopped"
	}
	if w.mode == "" {
		return "starting"
	}
	return w.mode
}

// waitMode 等到原生/回退模式就绪或超时，供主循环决定是否再启 WMI 进程监控。
func (w *etwWatcher) waitMode(d time.Duration) string {
	deadline := time.Now().Add(d)
	for {
		m := w.status()
		if m == "etw_native" || m == "etw_evt" || m == "stopped" {
			return m
		}
		if time.Now().After(deadline) {
			return m
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (w *etwWatcher) loop(ctx context.Context) {
	const nativeRetry = 90 * time.Second
	fallbackCtx, cancelFallback := context.WithCancel(ctx)
	defer cancelFallback()
	fallbackStarted := false

	for {
		if ctx.Err() != nil {
			return
		}
		err := w.runNative(ctx)
		if err == nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if !fallbackStarted {
			log.Printf("etw: 原生会话不可用（%v），启用 PowerShell Winlog 回退并与 winevent 并行（混合遥测）", err)
			setSensorPipeline("etw_evt", "winevent", "etw_evtlog_ps")
			go w.loopEvtLog(fallbackCtx)
			fallbackStarted = true
		} else {
			log.Printf("etw: 原生会话断开（%v），Winlog 回退继续；将重试原生", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(nativeRetry):
			log.Printf("etw: 重试原生 ETW 会话…")
		}
	}
}

// loopEvtLog：无管理员权限等情况下，订阅 Sysmon / Security 4688 事件日志。
func (w *etwWatcher) loopEvtLog(ctx context.Context) {
	ps := etwSubscribeScript()
	tmp, err := os.CreateTemp("", "fa-etw-*.ps1")
	if err != nil {
		log.Printf("etw: temp %v", err)
		return
	}
	path := tmp.Name()
	// Windows PowerShell 5 仅在有 BOM 时按 UTF-8 解析，否则中文字面量会破坏语法
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
			log.Printf("etw start: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		w.mu.Lock()
		w.mode = "etw_evt"
		w.mu.Unlock()
		log.Printf("etw: subscriber started (%s)", filepath.Base(path))

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
					log.Printf("etw read: %v", err)
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

func etwSubscribeScript() string {
	return `
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$queue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
function Enq($obj){ [void]$queue.Enqueue(($obj | ConvertTo-Json -Compress -Depth 6)) }

$queries = @()
try {
  $null = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
    'Microsoft-Windows-Sysmon/Operational',
    [System.Diagnostics.Eventing.Reader.PathType]::LogName,
    '*[System[(EventID=1 or EventID=3 or EventID=11)]]'
  )
  $queries += @{ Name='sysmon'; Query=$q }
} catch {}
try {
  $null = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
    'Security',
    [System.Diagnostics.Eventing.Reader.PathType]::LogName,
    '*[System[(EventID=4688)]]'
  )
  $queries += @{ Name='sec4688'; Query=$q }
} catch {}
if($queries.Count -eq 0){
  Enq @{ etype='etw_status'; summary='ETW通道不可用'; severity='info'; ts=(Get-Date).ToString('s'); detail=@{ mode='unavailable' } }
  while($true){
    $line=$null
    while($queue.TryDequeue([ref]$line)){ Write-Output $line }
    Start-Sleep -Seconds 20
  }
}

$watchers = @()
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
        $obj=$null
        if($eid -eq 1 -and $data.ContainsKey('Image')){
          $img=[string]$data['Image']; $name=[IO.Path]::GetFileName($img)
          $sev='info'; $sum='ETW进程创建(Sysmon): '+$name
          if($img -match '(?i)\\(temp|tmp|appdata|users\\public|downloads)\\'){ $sev='medium'; $sum='可疑路径进程(ETW): '+$name }
          $spid=[int]($data['ProcessId']); $sppid=[int]($data['ParentProcessId'])
          $utc=if([string]$data['UtcTime']){[string]$data['UtcTime']}else{$ts}
          $obj=@{ etype='process_create_etw'; summary=$sum; severity=$sev; ts=$ts; detail=@{
            source='sysmon'; pid=$spid; ppid=$sppid
            name=$name; path=$img; command_line=[string]$data['CommandLine']
            parent_name=[IO.Path]::GetFileName([string]$data['ParentImage']); user=[string]$data['User']
            create_time=$utc; process_guid=($spid.ToString()+'_'+$utc); parent_guid=($sppid.ToString()+'_')
          } }
        } elseif($eid -eq 3 -and $data.ContainsKey('DestinationIp')){
          $obj=@{ etype='network_connect_etw'; summary=('ETW外联(Sysmon): '+$data['DestinationIp']+':'+$data['DestinationPort']); severity='medium'; ts=$ts; detail=@{
            source='sysmon'; remote=($data['DestinationIp']+':'+$data['DestinationPort'])
            local=($data['SourceIp']+':'+$data['SourcePort']); pid=[int]($data['ProcessId'])
            process_name=[IO.Path]::GetFileName([string]$data['Image']); path=[string]$data['Image']
          } }
        } elseif($eid -eq 11 -and $data.ContainsKey('TargetFilename')){
          $fp=[string]$data['TargetFilename']
          $fn=[IO.Path]::GetFileName($fp)
          if($fn -match '(?i)psscriptpolicytest|fa-ps-|fa-etw-|fa-wevt-|fa-watch-|fa-upg-'){ return }
          $obj=@{ etype='file_write_etw'; summary=('ETW文件落地(Sysmon): '+$fn); severity='medium'; ts=$ts; detail=@{
            source='sysmon'; path=$fp; name=$fn; pid=[int]($data['ProcessId'])
          } }
        } elseif($eid -eq 4688){
          $img=[string]$data['NewProcessName']; $name=[IO.Path]::GetFileName($img)
          $cmd=[string]$data['CommandLine']; if(-not $cmd){ $cmd=$img }
          $npid=0; $ppid=0
          try { $npid=[Convert]::ToInt32(($data['NewProcessId'] -replace '^0x',''),16) } catch { try { $npid=[int]$data['NewProcessId'] } catch {} }
          try { $ppid=[Convert]::ToInt32(($data['ProcessId'] -replace '^0x',''),16) } catch { try { $ppid=[int]$data['ProcessId'] } catch {} }
          $obj=@{ etype='process_create_etw'; summary=('ETW进程创建(4688): '+$name); severity='info'; ts=$ts; detail=@{
            source='security_4688'; pid=$npid; ppid=$ppid; name=$name; path=$img; command_line=$cmd
            create_time=$ts; process_guid=($npid.ToString()+'_'+$ts); parent_guid=($ppid.ToString()+'_')
          } }
        } elseif($eid -eq 1){
          $pid2=0; $ppid2=0; $img2=''
          try { $pid2=[int64]$data['ProcessID'] } catch {}
          try { $ppid2=[int64]$data['ParentProcessID'] } catch {}
          try { $img2=[string]$data['ImageName'] } catch {}
          if(-not $img2){ try { $img2=[string]$data['Image'] } catch {} }
          $name2 = if($img2){ [IO.Path]::GetFileName($img2) } else { 'pid-'+$pid2 }
          $obj=@{ etype='process_create_etw'; summary=('ETW进程创建(Kernel): '+$name2); severity='info'; ts=$ts; detail=@{
            source='kernel_process'; pid=[int]$pid2; ppid=[int]$ppid2; name=$name2; path=$img2
            create_time=$ts; process_guid=(([int]$pid2).ToString()+'_'+$ts); parent_guid=(([int]$ppid2).ToString()+'_')
          } }
        }
        if($obj){ [void]$q.Enqueue(($obj | ConvertTo-Json -Compress -Depth 6)) }
      } catch {}
    }
    $watchers += $watcher
  } catch {}
}

Enq @{ etype='etw_status'; summary=('ETW订阅: '+(($queries|ForEach-Object Name) -join ',')); severity='info'; ts=(Get-Date).ToString('s'); detail=@{ sources=@($queries|ForEach-Object Name) } }

while($true){
  $line=$null
  while($queue.TryDequeue([ref]$line)){ Write-Output $line }
  Start-Sleep -Milliseconds 250
}
`
}
