//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type peMeta struct {
	Signed      string
	Signer      string
	Company     string
	FileVersion string
	SHA256      string
	CheckedAt   time.Time
}

type peReq struct {
	idx  int
	path string
	hash bool
}

var peCache sync.Map // key: lower(path) -> peMeta

// peMetaOf 查签名缓存；未命中则单路径批量查询（PowerShell），结果写回缓存。
func peMetaOf(path string) peMeta {
	if path == "" {
		return peMeta{}
	}
	k := strings.ToLower(path)
	if v, ok := peCache.Load(k); ok {
		pm := v.(peMeta)
		if time.Since(pm.CheckedAt) < 10*time.Minute {
			return pm
		}
	}
	meta := batchPEMeta([]peReq{{path: path}})
	if pm, ok := meta[k]; ok {
		return pm
	}
	return peMeta{}
}

// peSignedCached 只读缓存，不触发 PowerShell（供 ETW 热路径）。
// known=true 仅表示缓存里有「明确」结论（Valid 或 NotSigned/HashMismatch 等）；空串/UnknownError 视为未知。
func peSignedCached(path string) (valid bool, status string, known bool) {
	if path == "" {
		return false, "", false
	}
	k := strings.ToLower(path)
	v, ok := peCache.Load(k)
	if !ok {
		return false, "", false
	}
	pm := v.(peMeta)
	if time.Since(pm.CheckedAt) >= 10*time.Minute {
		return false, "", false
	}
	status = pm.Signed
	if strings.EqualFold(status, "Valid") {
		return true, status, true
	}
	if peSignedExplicitBad(status) {
		return false, status, true
	}
	return false, status, false
}

// peSignedExplicitBad 明确未签名 / 签名损坏（不含 UnknownError、空串）。
func peSignedExplicitBad(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "notsigned", "hashmismatch", "nottrusted", "incompatible":
		return true
	default:
		return false
	}
}

// peSignedValid 已有 Authenticode Valid；空串表示查不到（文件消失/权限不足）。
func peSignedValid(path string) (valid bool, status string) {
	pm := peMetaOf(path)
	status = pm.Signed
	return strings.EqualFold(status, "Valid"), status
}

// pe 预热队列：ETW ImageLoad 很密，禁止每个路径各起一个 PowerShell。
var (
	peWarmOnce sync.Once
	peWarmCh   = make(chan string, 64)
)

func peMetaWarmAsync(path string) {
	if path == "" {
		return
	}
	k := strings.ToLower(path)
	if v, ok := peCache.Load(k); ok {
		if pm := v.(peMeta); time.Since(pm.CheckedAt) < 10*time.Minute {
			return
		}
	}
	peWarmOnce.Do(func() {
		go func() {
			for p := range peWarmCh {
				_ = peMetaOf(p)
				time.Sleep(200 * time.Millisecond)
			}
		}()
	})
	select {
	case peWarmCh <- path:
	default: // 队列满则丢弃，保主机不卡
	}
}

func pathLooksSuspicious(p string) bool {
	l := strings.ToLower(p)
	keys := []string{
		`\temp\`, `\tmp\`, `\appdata\`, `\users\public\`, `\downloads\`,
		`\programdata\`, `\desktop\`, `\documents\`,
	}
	for _, k := range keys {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

func isWindowsSystemPath(p string) bool {
	l := strings.ToLower(filepath.Clean(p))
	return strings.Contains(l, `\windows\system32\`) ||
		strings.Contains(l, `\windows\syswow64\`) ||
		strings.Contains(l, `\windows\winsxs\`)
}

// enrichPEMeta 为条目补签名/公司名/可选哈希。可疑路径优先哈希。
func enrichPEMeta(items []any, pathKey string, maxHash int) {
	if len(items) == 0 {
		return
	}
	reqs := make([]peReq, 0, len(items))
	hashLeft := maxHash
	for i, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		p := asString(m[pathKey])
		if p == "" {
			p = firstPathToken(asString(m["path"]))
		}
		if p == "" || !strings.Contains(p, `\`) {
			continue
		}
		wantHash := pathLooksSuspicious(p) && hashLeft > 0 && !isWindowsSystemPath(p)
		if wantHash {
			hashLeft--
		}
		reqs = append(reqs, peReq{idx: i, path: p, hash: wantHash})
	}
	if len(reqs) == 0 {
		return
	}
	if len(reqs) > 120 {
		reqs = reqs[:120]
	}
	meta := batchPEMeta(reqs)
	for _, r := range reqs {
		pm, ok := meta[strings.ToLower(r.path)]
		if !ok {
			continue
		}
		m := items[r.idx].(map[string]any)
		if pm.Company != "" {
			m["company"] = pm.Company
		}
		if pm.FileVersion != "" {
			m["file_version"] = pm.FileVersion
		}
		if pm.Signed != "" {
			m["signed"] = pm.Signed
			m["signer"] = pm.Signer
		}
		if pm.SHA256 != "" {
			m["sha256"] = pm.SHA256
		}
	}
}

func firstPathToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, `"`) {
		if i := strings.Index(s[1:], `"`); i >= 0 {
			return s[1 : 1+i]
		}
	}
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return s
	}
	return parts[0]
}

func batchPEMeta(reqs []peReq) map[string]peMeta {
	out := map[string]peMeta{}
	type one struct {
		path string
		hash bool
	}
	uniq := []one{}
	seen := map[string]int{}
	for _, r := range reqs {
		k := strings.ToLower(r.path)
		if i, ok := seen[k]; ok {
			if r.hash {
				uniq[i].hash = true
			}
			continue
		}
		seen[k] = len(uniq)
		uniq = append(uniq, one{path: r.path, hash: r.hash})
	}

	need := make([]one, 0, len(uniq))
	for _, u := range uniq {
		if v, ok := peCache.Load(strings.ToLower(u.path)); ok {
			pm := v.(peMeta)
			if time.Since(pm.CheckedAt) < 10*time.Minute && (!u.hash || pm.SHA256 != "") {
				out[strings.ToLower(u.path)] = pm
				continue
			}
		}
		need = append(need, u)
	}
	if len(need) == 0 {
		return out
	}

	var b strings.Builder
	b.WriteString("$__rows = @()\n$items = @(\n")
	for _, u := range need {
		hp := "0"
		if u.hash {
			hp = "1"
		}
		fmt.Fprintf(&b, "  [PSCustomObject]@{ path = '%s'; hash = %s }\n",
			strings.ReplaceAll(u.path, "'", "''"), hp)
	}
	b.WriteString(")\n")
	b.WriteString(`
foreach($it in $items){
  $p = [string]$it.path
  $company = ''; $fver = ''; $signed = ''; $signer = ''; $sha = ''
  if($p -and (Test-Path -LiteralPath $p)){
    try {
      $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($p)
      $company = [string]$vi.CompanyName
      $fver = [string]$vi.FileVersion
    } catch {}
    try {
      $sig = Get-AuthenticodeSignature -LiteralPath $p
      $signed = [string]$sig.Status
      if($sig.SignerCertificate){ $signer = [string]$sig.SignerCertificate.Subject }
    } catch {}
    if([int]$it.hash -eq 1){
      try { $sha = [string](Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash } catch {}
    }
  }
  $__rows += [PSCustomObject]@{
    path = $p; company = $company; file_version = $fver
    signed = $signed; signer = $signer; sha256 = $sha
  }
}
`)
	rows := decodeJSONRows(runPS(b.String()))
	now := time.Now()
	for _, r := range rows {
		p := asString(r["path"])
		if p == "" {
			continue
		}
		pm := peMeta{
			Signed:      asString(r["signed"]),
			Signer:      asString(r["signer"]),
			Company:     asString(r["company"]),
			FileVersion: asString(r["file_version"]),
			SHA256:      asString(r["sha256"]),
			CheckedAt:   now,
		}
		peCache.Store(strings.ToLower(p), pm)
		out[strings.ToLower(p)] = pm
	}
	return out
}

func attachParentAndUptime(items []any) {
	byPID := map[int]string{}
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		pid := asInt(m["pid"])
		if pid > 0 {
			byPID[pid] = asString(m["name"])
		}
	}
	now := time.Now()
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		ppid := asInt(m["ppid"])
		if ppid > 0 {
			if n, ok := byPID[ppid]; ok {
				m["parent_name"] = n
			}
		}
		ct := asString(m["create_time"])
		if ct == "" {
			continue
		}
		t, err := time.ParseInLocation("2006-01-02T15:04:05", ct, time.Local)
		if err != nil {
			continue
		}
		sec := int(now.Sub(t).Seconds())
		if sec < 0 {
			sec = 0
		}
		m["uptime_sec"] = sec
		m["uptime"] = formatUptime(sec)
	}
}

func formatUptime(sec int) string {
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	if sec < 3600 {
		return fmt.Sprintf("%dm%ds", sec/60, sec%60)
	}
	if sec < 86400 {
		return fmt.Sprintf("%dh%dm", sec/3600, (sec%3600)/60)
	}
	return fmt.Sprintf("%dd%dh", sec/86400, (sec%86400)/3600)
}

func quickPIDNames() []any {
	raw, _ := runCmd(20*time.Second, "tasklist", "/FO", "CSV", "/NH")
	var out []any
	for _, cols := range parseCSV(raw) {
		if len(cols) < 2 {
			continue
		}
		name := strings.TrimSpace(cols[0])
		pid, _ := strconv.Atoi(strings.TrimSpace(cols[1]))
		if name == "" || pid <= 0 {
			continue
		}
		out = append(out, map[string]any{"pid": pid, "name": name})
	}
	return out
}

func attachProcessNamesToNetwork(conns []any, procs []any) {
	byPID := map[int]string{}
	for _, it := range procs {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		pid := asInt(m["pid"])
		if pid > 0 {
			byPID[pid] = asString(m["name"])
		}
	}
	for _, it := range conns {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		pid := asInt(m["pid"])
		if pid > 0 {
			if n, ok := byPID[pid]; ok {
				m["process_name"] = n
			}
		}
	}
}
