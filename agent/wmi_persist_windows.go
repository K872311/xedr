//go:build windows

package main

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"
)

// wmiPersistWatcher：轮询 root\subscription 永久事件订阅（Filter/Consumer/Binding）。
type wmiPersistWatcher struct {
	mu     sync.Mutex
	prev   map[string]string // binding key -> consumer payload fingerprint
	events []map[string]any
}

func newWMIPersistWatcher() *wmiPersistWatcher {
	return &wmiPersistWatcher{prev: map[string]string{}}
}

func (w *wmiPersistWatcher) drain() []map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.events
	w.events = nil
	return out
}

func (w *wmiPersistWatcher) start(ctx context.Context) {
	go func() {
		// 延后首扫，避免与 FIM/ETW 抢启动
		select {
		case <-ctx.Done():
			return
		case <-time.After(45 * time.Second):
		}
		w.tick(true)
		t := time.NewTicker(90 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				w.tick(false)
			}
		}
	}()
}

type wmiSubRow struct {
	FilterName   string `json:"filter"`
	ConsumerName string `json:"consumer"`
	ConsumerType string `json:"ctype"`
	CommandLine  string `json:"cmdline"`
	ScriptText   string `json:"script"`
	Executable   string `json:"exe"`
	Query        string `json:"query"`
}

func (w *wmiPersistWatcher) tick(baseline bool) {
	rows, err := collectWMIPermanentSubs()
	if err != nil {
		if !baseline {
			log.Printf("wmi_persist: %v", err)
		}
		return
	}
	cur := map[string]string{}
	meta := map[string]wmiSubRow{}
	for _, r := range rows {
		key := strings.ToLower(r.FilterName + "|" + r.ConsumerName + "|" + r.ConsumerType)
		fp := r.CommandLine + "|" + r.ScriptText + "|" + r.Executable + "|" + r.Query
		cur[key] = fp
		meta[key] = r
	}
	ts := time.Now().Format("2006-01-02T15:04:05")
	w.mu.Lock()
	defer w.mu.Unlock()
	if baseline || len(w.prev) == 0 {
		w.prev = cur
		return
	}
	for k, fp := range cur {
		old, had := w.prev[k]
		r := meta[k]
		payload := firstNonEmpty(r.CommandLine, r.Executable, r.ScriptText)
		detail := map[string]any{
			"source": "wmi_persist", "filter": r.FilterName, "consumer": r.ConsumerName,
			"consumer_type": r.ConsumerType, "wmi_query": r.Query,
			"task_execute": payload, "payload_path": payload, "command_line": firstNonEmpty(r.CommandLine, r.Executable),
			"script_text": truncateStr(r.ScriptText, 600),
		}
		if !had {
			sev := "high"
			sum := "WMI 永久订阅新增: " + filepathBaseSafe(payload, r.ConsumerName)
			w.events = append(w.events, map[string]any{
				"etype": "wmi_persist_add", "summary": sum, "severity": sev, "ts": ts, "detail": detail,
			})
		} else if old != fp {
			w.events = append(w.events, map[string]any{
				"etype": "wmi_persist_modify", "summary": "WMI 永久订阅修改: " + filepathBaseSafe(payload, r.ConsumerName),
				"severity": "high", "ts": ts, "detail": detail,
			})
		}
	}
	for k := range w.prev {
		if _, ok := cur[k]; !ok {
			w.events = append(w.events, map[string]any{
				"etype": "wmi_persist_delete", "summary": "WMI 永久订阅删除", "severity": "medium", "ts": ts,
				"detail": map[string]any{"source": "wmi_persist", "key": k},
			})
		}
	}
	w.prev = cur
	if len(w.events) > 80 {
		w.events = w.events[len(w.events)-80:]
	}
}

func filepathBaseSafe(payload, fallback string) string {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return fallback
	}
	if strings.Contains(payload, `\`) || strings.Contains(payload, `/`) {
		return truncateStr(baseNamePath(payload), 80)
	}
	return truncateStr(payload, 80)
}

func baseNamePath(p string) string {
	p = strings.ReplaceAll(p, `/`, `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func collectWMIPermanentSubs() ([]wmiSubRow, error) {
	ps := `
$ErrorActionPreference='SilentlyContinue'
$out=@()
$ns='root\subscription'
$filters=@{}; Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object { $filters[$_.Name]=$_ }
$consumers=@()
foreach($cls in @('CommandLineEventConsumer','ActiveScriptEventConsumer')){
  Get-CimInstance -Namespace $ns -ClassName $cls -ErrorAction SilentlyContinue | ForEach-Object {
    $consumers += [PSCustomObject]@{ Name=$_.Name; Type=$cls; Cmd=[string]$_.CommandLineTemplate; Script=[string]$_.ScriptText; Exe=[string]$_.ExecutablePath }
  }
}
Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object {
  $fRef = [string]$_.Filter
  $cRef = [string]$_.Consumer
  $fname=''; $cname=''; $ctype=''; $cmd=''; $script=''; $exe=''; $q=''
  if($fRef -match 'Name="([^"]+)"'){ $fname=$Matches[1] }
  if($cRef -match 'Name="([^"]+)"'){ $cname=$Matches[1] }
  if($cRef -match ':(CommandLineEventConsumer|ActiveScriptEventConsumer)\.'){ $ctype=$Matches[1] }
  if($filters.ContainsKey($fname)){ $q=[string]$filters[$fname].Query }
  foreach($c in $consumers){
    if($c.Name -eq $cname){ $cmd=$c.Cmd; $script=$c.Script; $exe=$c.Exe; if(-not $ctype){$ctype=$c.Type}; break }
  }
  if(-not $fname -and -not $cname){ return }
  $out += [PSCustomObject]@{ filter=$fname; consumer=$cname; ctype=$ctype; cmdline=$cmd; script=$script; exe=$exe; query=$q }
}
$out | ConvertTo-Json -Compress -Depth 4
`
	raw, err := runCmd(25*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
	if err != nil {
		return nil, err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return nil, nil
	}
	if strings.HasPrefix(raw, "{") {
		var one wmiSubRow
		if json.Unmarshal([]byte(raw), &one) == nil {
			return []wmiSubRow{one}, nil
		}
	}
	var rows []wmiSubRow
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return nil, err
	}
	return rows, nil
}
