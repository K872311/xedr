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
	"strings"
	"sync"
	"time"
)

// 实时进程创建：WMI Win32_ProcessStartTrace（用户态，近似 ETW 进程事件）。
type processWatcher struct {
	mu      sync.Mutex
	events  []map[string]any
	cancel  context.CancelFunc
	running bool
}

func newProcessWatcher() *processWatcher {
	return &processWatcher{}
}

func (w *processWatcher) start(ctx context.Context) {
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

func (w *processWatcher) stop() {
	w.mu.Lock()
	if w.cancel != nil {
		w.cancel()
	}
	w.running = false
	w.mu.Unlock()
}

func (w *processWatcher) drain() []map[string]any {
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

func (w *processWatcher) push(ev map[string]any) {
	if isTimelineNoiseEvent(ev) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, ev)
	if len(w.events) > 400 {
		w.events = w.events[len(w.events)-400:]
	}
}

func (w *processWatcher) loop(ctx context.Context) {
	ps := `
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier FaProcStart | Out-Null
while($true){
  $e = Wait-Event -SourceIdentifier FaProcStart -Timeout 2
  if(-not $e){ continue }
  $n = $e.SourceEventArgs.NewEvent
  Remove-Event -EventIdentifier $e.EventIdentifier -ErrorAction SilentlyContinue
  $procId = [int]$n.ProcessID
  $name = [string]$n.ProcessName
  $ppid = [int]$n.ParentProcessID
  # 热路径禁止 Get-FileHash / Authenticode：安装后进程风暴时会拖死整机导致心跳掉线
  $path = ''; $cmd = ''; $parent = ''; $parentPath = ''; $user = ''; $company = ''
  $createTime = (Get-Date).ToString('s'); $parentCreate = ''
  try {
    $p = Get-CimInstance Win32_Process -Filter ("ProcessId=$procId") -ErrorAction SilentlyContinue
    if($p){
      $path = [string]$p.ExecutablePath
      $cmd = [string]$p.CommandLine
      if($p.CreationDate){ $createTime = $p.CreationDate.ToString('s') }
      try {
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
        if($o -and $o.ReturnValue -eq 0){
          if($o.Domain){ $user = ($o.Domain + '\' + $o.User) } else { $user = [string]$o.User }
        }
      } catch {}
    }
    $pp = Get-CimInstance Win32_Process -Filter ("ProcessId=$ppid") -ErrorAction SilentlyContinue
    if($pp){
      $parent = [string]$pp.Name
      $parentPath = [string]$pp.ExecutablePath
      if($pp.CreationDate){ $parentCreate = $pp.CreationDate.ToString('s') }
    }
    if($path -and (Test-Path -LiteralPath $path)){
      try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
        if($vi){ $company = [string]$vi.CompanyName }
      } catch {}
    }
  } catch {}
  $sev = 'info'
  $sum = '进程创建: ' + $name
  if($path -match '(?i)\\(temp|tmp|appdata|users\\public|downloads)\\'){ $sev='medium'; $sum='可疑路径进程: '+$name }
  $obj = [PSCustomObject]@{
    etype = 'process_create_live'
    summary = $sum
    severity = $sev
    ts = (Get-Date).ToString('s')
    detail = @{
      pid = $procId
      ppid = $ppid
      name = $name
      path = $path
      command_line = $cmd
      parent_name = $parent
      parent_path = $parentPath
      user = $user
      company = $company
      create_time = $createTime
      process_guid = ($procId.ToString() + '_' + $createTime)
      parent_guid = if($ppid -gt 0){ $ppid.ToString() + '_' + $parentCreate } else { '' }
      source = 'WMI'
    }
  }
  Write-Output ($obj | ConvertTo-Json -Compress -Depth 5)
}
`
	tmp, err := os.CreateTemp("", "fa-watch-*.ps1")
	if err != nil {
		log.Printf("watch: temp %v", err)
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
			log.Printf("watch start: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("process watcher started (WMI)")
		w.readLines(ctx, stdout)
		_ = cmd.Wait()
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (w *processWatcher) readLines(ctx context.Context, r io.Reader) {
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var ev map[string]any
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		// 提升可疑路径严重级别（名称启发）
		name, _ := ev["summary"].(string)
		sev := "info"
		low := strings.ToLower(name)
		for _, k := range []string{"powershell", "wscript", "cscript", "mshta", "cmd.exe"} {
			if strings.Contains(low, k) {
				sev = "medium"
				break
			}
		}
		ev["severity"] = sev
		if d, ok := ev["detail"].(map[string]any); ok {
			ev["detail"] = d
		}
		w.push(ev)
	}
}
