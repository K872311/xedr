//go:build windows

package main

import (
	"fmt"
	"sort"
	"strings"
)

// 给服务 / 计划任务 / 进程打风险分，系统噪声沉底，可疑项优先保留。

func isMicrosoftNoisePath(p string) bool {
	l := strings.ToLower(strings.TrimSpace(p))
	if l == "" {
		return false
	}
	if isWindowsSystemPath(l) {
		return true
	}
	return strings.Contains(l, `\windows\`) ||
		strings.Contains(l, `\program files\windows`) ||
		strings.Contains(l, `\program files (x86)\windows`)
}

func isMicrosoftTask(name, author string) bool {
	n := strings.ToLower(name)
	a := strings.ToLower(author)
	if strings.Contains(n, `\microsoft\`) || strings.HasPrefix(n, `\microsoft\`) {
		return true
	}
	if strings.Contains(a, "microsoft") || strings.Contains(a, "windows operating system") {
		return true
	}
	return false
}

func scoreService(m map[string]any) {
	path := firstPathToken(asString(m["path"]))
	account := strings.ToLower(asString(m["account"]))
	status := strings.ToLower(asString(m["status"]))
	start := strings.ToLower(asString(m["start_type"]))
	signed := strings.ToLower(asString(m["signed"]))
	score := 0
	tags := make([]string, 0, 4)
	noise := false

	if isMicrosoftNoisePath(path) && (strings.Contains(account, "localsystem") ||
		strings.Contains(account, "local service") ||
		strings.Contains(account, "network service") || account == "") {
		noise = true
	}
	if pathLooksSuspicious(path) {
		score += 45
		tags = append(tags, "可疑路径")
	}
	if path != "" && !isMicrosoftNoisePath(path) && !strings.Contains(strings.ToLower(path), `\program files`) {
		score += 20
		tags = append(tags, "非标准目录")
	}
	if strings.Contains(account, `\`) && !strings.Contains(account, "localsystem") &&
		!strings.Contains(account, "local service") && !strings.Contains(account, "network service") {
		score += 25
		tags = append(tags, "用户账户运行")
	}
	if signed != "" && !strings.Contains(signed, "valid") {
		score += 30
		tags = append(tags, "签名异常")
	}
	if (start == "auto" || start == "automatic") && (status == "stopped" || status == "stop") {
		score += 10
		tags = append(tags, "自启但停止")
	}
	if noise && score < 25 {
		m["noise"] = true
		m["risk_score"] = 0
		m["risk_tags"] = "系统服务"
		return
	}
	m["noise"] = false
	m["risk_score"] = score
	if len(tags) > 0 {
		m["risk_tags"] = strings.Join(tags, ",")
	} else if score > 0 {
		m["risk_tags"] = "关注"
	} else {
		m["risk_tags"] = ""
	}
}

func scoreTask(m map[string]any) {
	name := asString(m["task_name"])
	author := asString(m["author"])
	exe := firstPathToken(asString(m["execute"]))
	if exe == "" {
		exe = firstPathToken(asString(m["path"]))
	}
	cmd := asString(m["command"]) + " " + asString(m["arguments"])
	status := strings.ToLower(asString(m["status"]))
	score := 0
	tags := make([]string, 0, 4)

	if isMicrosoftTask(name, author) && !pathLooksSuspicious(exe) && !pathLooksSuspicious(cmd) {
		m["noise"] = true
		m["risk_score"] = 0
		m["risk_tags"] = "系统任务"
		return
	}
	if pathLooksSuspicious(exe) || pathLooksSuspicious(cmd) {
		score += 50
		tags = append(tags, "可疑路径")
	}
	blob := strings.ToLower(cmd + " " + exe)
	for _, k := range []string{"powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "bitsadmin", "certutil", "curl ", "wget "} {
		if strings.Contains(blob, k) {
			score += 25
			tags = append(tags, "脚本/LOLBin")
			break
		}
	}
	if author == "" || (!strings.Contains(strings.ToLower(author), "microsoft") && author != "") {
		if !isMicrosoftTask(name, author) {
			score += 10
			tags = append(tags, "非微软作者")
		}
	}
	if status == "ready" || status == "running" {
		score += 5
	}
	m["noise"] = false
	m["risk_score"] = score
	if len(tags) > 0 {
		m["risk_tags"] = strings.Join(tags, ",")
	} else {
		m["risk_tags"] = ""
	}
}

func scoreProcess(m map[string]any) {
	path := asString(m["path"])
	cmd := asString(m["command_line"])
	signed := strings.ToLower(asString(m["signed"]))
	name := strings.ToLower(asString(m["name"]))
	score := 0
	tags := make([]string, 0, 4)
	noise := false

	if isMicrosoftNoisePath(path) && (signed == "" || strings.Contains(signed, "valid")) {
		noise = true
	}
	if pathLooksSuspicious(path) || pathLooksSuspicious(cmd) {
		score += 40
		tags = append(tags, "可疑路径")
	}
	for _, k := range []string{"powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "cmd.exe"} {
		if strings.Contains(name, k) || strings.Contains(strings.ToLower(cmd), k) {
			score += 15
			tags = append(tags, "解释器")
			break
		}
	}
	if signed != "" && !strings.Contains(signed, "valid") {
		score += 25
		tags = append(tags, "签名异常")
	}
	if path == "" && name != "" && name != "system" && name != "idle" && name != "registry" {
		score += 10
		tags = append(tags, "无路径")
	}
	if noise && score < 20 {
		m["noise"] = true
		m["risk_score"] = 0
		m["risk_tags"] = "系统进程"
		return
	}
	m["noise"] = false
	m["risk_score"] = score
	if len(tags) > 0 {
		m["risk_tags"] = strings.Join(tags, ",")
	} else {
		m["risk_tags"] = ""
	}
}

func sortByRisk(items []any) {
	sort.SliceStable(items, func(i, j int) bool {
		a, _ := items[i].(map[string]any)
		b, _ := items[j].(map[string]any)
		an, bn := false, false
		if a != nil {
			an, _ = a["noise"].(bool)
		}
		if b != nil {
			bn, _ = b["noise"].(bool)
		}
		if an != bn {
			return !an && bn // 非噪声在前
		}
		return asInt(a["risk_score"]) > asInt(b["risk_score"])
	})
}

func applyRiskAndSort(items []any, kind string) []any {
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		switch kind {
		case "service":
			scoreService(m)
		case "task":
			scoreTask(m)
		case "process":
			scoreProcess(m)
		}
	}
	sortByRisk(items)
	return truncateItems(items)
}

// enrichProcessModules 为高价值进程补充已加载 DLL（排除 System32 噪声，保留可疑/第三方模块）。
func enrichProcessModules(items []any, maxProcs int) {
	if maxProcs <= 0 {
		maxProcs = 20
	}
	type cand struct {
		pid   int
		score int
	}
	var cands []cand
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		pid := asInt(m["pid"])
		if pid <= 4 {
			continue
		}
		sc := asInt(m["risk_score"])
		if noise, _ := m["noise"].(bool); noise && sc < 15 {
			continue
		}
		if sc < 10 && !pathLooksSuspicious(asString(m["path"])) {
			continue
		}
		cands = append(cands, cand{pid: pid, score: sc})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].score > cands[j].score })
	if len(cands) > maxProcs {
		cands = cands[:maxProcs]
	}
	if len(cands) == 0 {
		return
	}
	pidList := make([]string, 0, len(cands))
	for _, c := range cands {
		pidList = append(pidList, fmt.Sprintf("%d", c.pid))
	}
	ps := fmt.Sprintf(`
$pids = @(%s)
$__rows = @()
foreach($pid in $pids){
  try {
    $proc = Get-Process -Id $pid -ErrorAction Stop
    $mods = @($proc.Modules | Select-Object -First 120)
    foreach($m in $mods){
      $fp = [string]$m.FileName
      if(-not $fp){ continue }
      $low = $fp.ToLowerInvariant()
      $sys = ($low -match '\\windows\\(system32|syswow64|winsxs)\\')
      $__rows += [PSCustomObject]@{
        pid = [int]$pid
        name = [string]$m.ModuleName
        path = $fp
        size = [int64]$m.Size
        system = [bool]$sys
      }
    }
  } catch {}
}
$__rows
`, strings.Join(pidList, ","))
	rows := decodeJSONRows(runPS(ps))
	byPID := map[int][]map[string]any{}
	totalByPID := map[int]int{}
	for _, r := range rows {
		pid := asInt(r["pid"])
		if pid <= 0 {
			continue
		}
		totalByPID[pid]++
		sys := false
		switch v := r["system"].(type) {
		case bool:
			sys = v
		case string:
			sys = strings.EqualFold(v, "true") || v == "1"
		}
		if sys {
			continue
		}
		p := asString(r["path"])
		entry := map[string]any{
			"name": asString(r["name"]),
			"path": p,
			"size": asInt(r["size"]),
		}
		if pathLooksSuspicious(p) {
			entry["hot"] = true
		}
		byPID[pid] = append(byPID[pid], entry)
	}
	// 合并所有待展示模块，补签名/公司/版本/可疑路径哈希
	allMods := make([]any, 0, 64)
	for _, list := range byPID {
		for _, e := range list {
			allMods = append(allMods, e)
		}
	}
	if len(allMods) > 0 {
		enrichPEMeta(allMods, "path", 24)
	}
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		pid := asInt(m["pid"])
		hot := byPID[pid]
		if len(hot) > 40 {
			hot = hot[:40]
		}
		if n := totalByPID[pid]; n > 0 {
			m["module_count"] = n
			m["module_third_count"] = len(hot)
		}
		if len(hot) == 0 {
			continue
		}
		// 未签名 / 可疑路径优先排前，方便研判
		sort.SliceStable(hot, func(i, j int) bool {
			si, sj := asString(hot[i]["signed"]), asString(hot[j]["signed"])
			hi, hj := hot[i]["hot"] == true, hot[j]["hot"] == true
			ui := hi || (si != "" && !strings.EqualFold(si, "Valid"))
			uj := hj || (sj != "" && !strings.EqualFold(sj, "Valid"))
			if ui != uj {
				return ui
			}
			return asString(hot[i]["name"]) < asString(hot[j]["name"])
		})
		m["modules"] = hot
		names := make([]string, 0, 8)
		for i, h := range hot {
			if i >= 8 {
				break
			}
			names = append(names, asString(h["name"]))
		}
		m["modules_summary"] = strings.Join(names, ", ")
	}
}
