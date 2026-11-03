package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

const maxItems = 500

func collectModule(module string) ([]any, error) {
	switch strings.ToLower(module) {
	case "sysinfo":
		return collectSysinfo()
	case "service":
		return collectServices()
	case "task":
		return collectTasks()
	case "startup":
		return collectStartup()
	case "network":
		return collectNetwork()
	case "process":
		return collectProcesses()
	case "file":
		return collectFiles()
	case "user":
		return collectUsers()
	case "software":
		return collectSoftware()
	case "hotfix":
		return collectHotfix()
	case "listen":
		return collectListen()
	case "driver":
		return collectDrivers()
	case "browser":
		return collectBrowser()
	default:
		return nil, nil
	}
}

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	hideWindow(cmd)
	err := cmd.Run()
	raw := stdout.Bytes()
	if len(raw) == 0 && stderr.Len() > 0 {
		raw = stderr.Bytes()
	}
	return decodeConsoleBytes(raw), err
}

func decodeConsoleBytes(b []byte) string {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	if len(b) == 0 {
		return ""
	}
	if utf8.Valid(b) && !bytes.Contains(b, []byte{0xEF, 0xBF, 0xBD}) {
		return strings.TrimSpace(string(b))
	}
	if decoded, err := io.ReadAll(transform.NewReader(bytes.NewReader(b), simplifiedchinese.GBK.NewDecoder())); err == nil {
		return strings.TrimSpace(string(decoded))
	}
	return strings.TrimSpace(string(b))
}

func runPS(script string) string {
	tmp, err := os.CreateTemp("", "fa-ps-*.json")
	if err != nil {
		return ""
	}
	path := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(path)
	ep := escapePSPath(path)

	// 采集脚本本身产出对象；由包装层统一转 JSON 并以 UTF-8 无 BOM 落盘
	core := strings.TrimSpace(script)
	core = strings.TrimSuffix(core, "| ConvertTo-Json -Compress")
	core = strings.TrimSuffix(core, "| ConvertTo-Json -Compress -Depth 4")
	core = strings.TrimSpace(core)

	psFile, err := os.CreateTemp("", "fa-ps-*.ps1")
	if err != nil {
		return ""
	}
	psPath := psFile.Name()
	content := fmt.Sprintf(`
$ErrorActionPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$OutputEncoding = [Console]::OutputEncoding
$__out = '%s'
try {
%s
  if ($null -eq $__rows) { $__json = '[]' }
  else { $__json = ($__rows | ConvertTo-Json -Compress -Depth 8) }
  if (-not $__json) { $__json = '[]' }
  $utf8 = New-Object System.Text.UTF8Encoding $false
  [System.IO.File]::WriteAllText($__out, $__json, $utf8)
} catch {
  $utf8 = New-Object System.Text.UTF8Encoding $false
  [System.IO.File]::WriteAllText($__out, '[]', $utf8)
}
`, ep, indentAsRows(core))
	_, _ = psFile.Write([]byte{0xEF, 0xBB, 0xBF})
	_, _ = psFile.Write([]byte(content))
	_ = psFile.Close()
	defer os.Remove(psPath)

	_, _ = runCmd(120*time.Second, "powershell",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", psPath)
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	return strings.TrimSpace(string(b))
}

func indentAsRows(core string) string {
	// 把采集脚本结果赋给 $__rows
	if strings.Contains(core, "$__rows") {
		return core
	}
	return "$__rows = @(\n" + core + "\n)\n"
}

func escapePSPath(p string) string {
	return strings.ReplaceAll(p, "'", "''")
}

func decodeJSONRows(raw string) []map[string]any {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(raw), &rows); err == nil {
		return rows
	}
	var one map[string]any
	if err := json.Unmarshal([]byte(raw), &one); err == nil {
		return []map[string]any{one}
	}
	return nil
}

// anySlice 安全读取 JSON 数组；缺失或非数组时返回 nil（避免 nil.([]any) panic）。
func anySlice(v any) []any {
	if v == nil {
		return nil
	}
	s, ok := v.([]any)
	if !ok {
		return nil
	}
	return s
}

func stringsFromAnySlice(v any) []string {
	raw := anySlice(v)
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s := asString(x); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(strings.ReplaceAll(t, "\uFFFD", ""))
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func asInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case uint32:
		return int(t)
	case int32:
		return int(t)
	case int64:
		return int(t)
	case uint64:
		return int(t)
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
	}
}

func parseCSV(raw string) [][]string {
	r := csv.NewReader(strings.NewReader(raw))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil
	}
	return rows
}

func colIdx(headers []string, names ...string) int {
	for i, h := range headers {
		hl := strings.ToLower(strings.TrimSpace(h))
		for _, n := range names {
			if hl == strings.ToLower(n) || strings.Contains(hl, strings.ToLower(n)) {
				return i
			}
		}
	}
	return -1
}

func truncateItems(items []any) []any {
	if len(items) > maxItems {
		return items[:maxItems]
	}
	return items
}

func goOS() string { return runtime.GOOS }
