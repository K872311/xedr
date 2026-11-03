//go:build windows

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// collectDrivers 内核/文件系统驱动清单（SCM 驱动服务）：路径、状态、启动类型、签名。
// 未签名/非系统目录/投放区驱动加风险分，供 BYOVD 与 rootkit 排查。
func collectDrivers() ([]any, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	var need, count, resume uint32
	_ = windows.EnumServicesStatusEx(m.Handle, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_DRIVER,
		windows.SERVICE_STATE_ALL, nil, 0, &need, &count, &resume, nil)
	if need == 0 {
		return []any{}, nil
	}
	buf := make([]byte, need+4096)
	resume = 0
	if err := windows.EnumServicesStatusEx(m.Handle, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_DRIVER,
		windows.SERVICE_STATE_ALL, &buf[0], uint32(len(buf)), &need, &count, &resume, nil); err != nil {
		return nil, err
	}
	ents := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count)
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	out := make([]any, 0, count)
	for _, e := range ents {
		name := windows.UTF16PtrToString(e.ServiceName)
		item := map[string]any{
			"name":         name,
			"display_name": windows.UTF16PtrToString(e.DisplayName),
			"status":       driverState(e.ServiceStatusProcess.CurrentState),
			"kind":         "kernel",
			"inventory":    "driver",
		}
		if e.ServiceStatusProcess.ServiceType&windows.SERVICE_FILE_SYSTEM_DRIVER != 0 {
			item["kind"] = "filesystem"
		}
		if s, err := m.OpenService(name); err == nil {
			if c, err := s.Config(); err == nil {
				item["path"] = normalizeDriverPath(c.BinaryPathName, sysRoot, name)
				item["start_type"] = driverStart(c.StartType)
				item["group"] = c.LoadOrderGroup
			}
			s.Close()
		}
		out = append(out, item)
	}
	// 只给不在系统目录的驱动查签名（签名查询走 PowerShell，量要小；系统目录驱动受 DSE 约束）
	var nonSys []any
	for _, it := range out {
		if p := asString(it.(map[string]any)["path"]); p != "" && !isWindowsSystemPath(p) {
			nonSys = append(nonSys, it)
		}
	}
	enrichPEMeta(nonSys, "path", 0)
	for _, it := range out {
		scoreDriver(it.(map[string]any))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return asInt(out[i].(map[string]any)["risk_score"]) > asInt(out[j].(map[string]any)["risk_score"])
	})
	return truncateItems(out), nil
}

func normalizeDriverPath(p, sysRoot, name string) string {
	p = strings.TrimSpace(strings.Trim(p, `"`))
	low := strings.ToLower(p)
	switch {
	case p == "":
		return filepath.Join(sysRoot, `System32\drivers`, name+".sys")
	case strings.HasPrefix(low, `\systemroot\`):
		return filepath.Join(sysRoot, p[len(`\systemroot\`):])
	case strings.HasPrefix(low, `system32\`):
		return filepath.Join(sysRoot, p)
	case strings.HasPrefix(p, `\??\`):
		return p[4:]
	}
	return p
}

func driverState(s uint32) string {
	switch s {
	case windows.SERVICE_RUNNING:
		return "Running"
	case windows.SERVICE_STOPPED:
		return "Stopped"
	case windows.SERVICE_START_PENDING:
		return "StartPending"
	case windows.SERVICE_STOP_PENDING:
		return "StopPending"
	}
	return "Unknown"
}

func driverStart(t uint32) string {
	switch t {
	case windows.SERVICE_BOOT_START:
		return "Boot"
	case windows.SERVICE_SYSTEM_START:
		return "System"
	case windows.SERVICE_AUTO_START:
		return "Automatic"
	case windows.SERVICE_DEMAND_START:
		return "Manual"
	case windows.SERVICE_DISABLED:
		return "Disabled"
	}
	return ""
}

func scoreDriver(m map[string]any) {
	path := asString(m["path"])
	signed := strings.ToLower(asString(m["signed"]))
	score := 0
	var tags []string
	if pathLooksSuspicious(path) || pathInDropZone(path) {
		score += 50
		tags = append(tags, "可疑路径")
	}
	if path != "" && !isWindowsSystemPath(path) && !strings.Contains(strings.ToLower(path), `\windows\`) {
		score += 15
		tags = append(tags, "非系统目录")
	}
	if signed != "" && !strings.Contains(signed, "valid") {
		score += 40
		tags = append(tags, "签名异常")
	}
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			score += 10
			tags = append(tags, "文件缺失")
		}
	}
	m["risk_score"] = score
	m["risk_tags"] = strings.Join(tags, ",")
	m["noise"] = score == 0
}
