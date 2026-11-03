//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualQueryEx       = modKernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory    = modKernel32.NewProc("ReadProcessMemory")
	procCreateToolhelp32Snap = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW      = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW       = modKernel32.NewProc("Process32NextW")
)

const (
	th32csSnapProcess = 0x00000002
	memCommit         = 0x1000
	pageExecuteRead   = 0x20
	pageExecuteRW     = 0x40
	pageExecuteWrite  = 0x80
	pageReadWrite     = 0x04
	pageWriteCopy     = 0x08
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type processEntry32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

// 内存扫描：启发式 + rules.json 字符串 +（-tags yara 时）YARA。
func scanMemory(params map[string]any) (map[string]any, error) {
	ms := memoryScanSettingsSnapshot()
	mode := ms.Mode
	if force := strings.TrimSpace(asString(params["force_mode"])); force != "" {
		mode = force
	}
	if mode == memModeOff {
		return map[string]any{"ok": true, "skipped": true, "mode": mode}, nil
	}
	useHeuristic := mode == memModeHeuristic || !memoryScanUsesYara(ms)
	useRules := mode != memModeOff && (memoryScanUsesYara(ms) || mode == memModeHeuristic)

	maxProc := ms.MaxProcesses
	if maxProc <= 0 {
		maxProc = 20
	}
	if v, ok := params["max_processes"].(float64); ok && v > 0 {
		maxProc = int(v)
	}
	targetPID := 0
	switch v := params["pid"].(type) {
	case float64:
		targetPID = int(v)
	case int:
		targetPID = v
	}

	self := uint32(os.Getpid())
	procs, err := listPIDs()
	if err != nil {
		return nil, err
	}
	findings := []map[string]any{}
	scanned := 0
	for _, p := range procs {
		if p.pid == self || p.pid == 0 {
			continue
		}
		if targetPID > 0 && int(p.pid) != targetPID {
			continue
		}
		if scanned >= maxProc && targetPID == 0 {
			break
		}
		// 跳过明显系统关键进程
		low := strings.ToLower(p.name)
		if low == "csrss.exe" || low == "smss.exe" || low == "wininit.exe" || low == "services.exe" {
			continue
		}
		hits := scanProcess(p.pid, p.name, scanProcessOpts{
			heuristic: useHeuristic,
			rules:     useRules,
			yara:      memoryScanUsesYara(ms),
			maxReadKB: ms.MaxRegionReadKB,
		})
		scanned++
		findings = append(findings, hits...)
		if len(findings) >= 50 {
			break
		}
	}
	return map[string]any{
		"ok":            true,
		"mode":          mode,
		"yara_engine":   yaraEngineOK,
		"rules_rev":     memRulesRev,
		"trigger":       asString(params["trigger"]),
		"scanned":       scanned,
		"findings":      findings,
		"finding_count": len(findings),
		"ts":            time.Now().Format("2006-01-02T15:04:05"),
	}, nil
}

type scanProcessOpts struct {
	heuristic bool
	rules     bool
	yara      bool
	maxReadKB int
}

type pidName struct {
	pid        uint32
	ppid       uint32
	name       string
	createTime string
	guid       string
}

func listPIDs() ([]pidName, error) {
	snap, _, err := procCreateToolhelp32Snap.Call(th32csSnapProcess, 0)
	if snap == 0 || snap == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %v", err)
	}
	h := windows.Handle(snap)
	defer windows.CloseHandle(h)
	var pe processEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	r, _, err := procProcess32FirstW.Call(uintptr(h), uintptr(unsafe.Pointer(&pe)))
	if r == 0 {
		return nil, fmt.Errorf("Process32First: %v", err)
	}
	var out []pidName
	for {
		name := windows.UTF16ToString(pe.ExeFile[:])
		out = append(out, pidName{pid: pe.ProcessID, ppid: pe.ParentProcessID, name: name})
		pe.Size = uint32(unsafe.Sizeof(pe))
		r, _, _ = procProcess32NextW.Call(uintptr(h), uintptr(unsafe.Pointer(&pe)))
		if r == 0 {
			break
		}
	}
	return out, nil
}

func scanProcess(pid uint32, name string, opt scanProcessOpts) []map[string]any {
	if opt.maxReadKB <= 0 {
		opt.maxReadKB = 512
	}
	maxRead := uintptr(opt.maxReadKB * 1024)
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)

	var findings []map[string]any
	var addr uintptr
	rwxRegions := 0
	mzInPrivate := 0
	suspiciousStr := 0

	for {
		var mbi memoryBasicInformation
		n, _, _ := procVirtualQueryEx.Call(uintptr(h), addr, uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
		if n == 0 {
			break
		}
		size := mbi.RegionSize
		if size == 0 {
			break
		}
		next := mbi.BaseAddress + size
		if next <= addr {
			break
		}
		addr = next

		if mbi.State != memCommit {
			continue
		}
		prot := mbi.Protect
		execish := prot&(pageExecuteRead|pageExecuteRW|pageExecuteWrite) != 0
		rw := prot&(pageReadWrite|pageWriteCopy|pageExecuteRW) != 0
		if !execish && !rw {
			continue
		}
		// 限制单区读取
		readSize := size
		if readSize > maxRead {
			readSize = maxRead
		}
		if readSize < 64 {
			continue
		}
		buf := make([]byte, readSize)
		var read uintptr
		r, _, _ := procReadProcessMemory.Call(uintptr(h), mbi.BaseAddress, uintptr(unsafe.Pointer(&buf[0])), readSize, uintptr(unsafe.Pointer(&read)))
		if r == 0 || read < 64 {
			continue
		}
		chunk := buf[:read]
		if execish && rw {
			rwxRegions++
		}
		if opt.heuristic {
			if len(chunk) >= 2 && chunk[0] == 'M' && chunk[1] == 'Z' && (execish || rw) {
				mzInPrivate++
				findings = append(findings, map[string]any{
					"type":     "mz_in_memory",
					"pid":      pid,
					"name":     name,
					"address":  fmt.Sprintf("0x%X", mbi.BaseAddress),
					"protect":  fmt.Sprintf("0x%X", prot),
					"severity": "high",
					"engine":   "heuristic",
					"summary":  fmt.Sprintf("内存 MZ 头: %s pid=%d @0x%X", name, pid, mbi.BaseAddress),
				})
			}
			low := strings.ToLower(string(chunk))
			for _, sig := range []string{"meterpreter", "reflective loader"} {
				if strings.Contains(low, sig) {
					suspiciousStr++
					findings = append(findings, map[string]any{
						"type": "suspicious_string", "pid": pid, "name": name, "sig": sig,
						"address": fmt.Sprintf("0x%X", mbi.BaseAddress), "severity": "high", "engine": "heuristic",
						"summary": fmt.Sprintf("内存可疑串[%s]: %s pid=%d", sig, name, pid),
					})
					break
				}
			}
		}
		if opt.rules {
			for _, hit := range matchJSONMemoryRules(chunk) {
				hit["pid"] = pid
				hit["name"] = name
				hit["address"] = fmt.Sprintf("0x%X", mbi.BaseAddress)
				if hit["summary"] == nil {
					hit["summary"] = fmt.Sprintf("内存规则[%s]: %s pid=%d", hit["rule_id"], name, pid)
				}
				findings = append(findings, hit)
			}
		}
		if opt.yara && yaraEngineOK {
			for _, hit := range scanYaraOnRegion(chunk, mbi.BaseAddress, pid, name) {
				findings = append(findings, hit)
			}
		}
		if len(findings) >= 30 {
			break
		}
	}
	if opt.heuristic && rwxRegions >= 3 {
		findings = append(findings, map[string]any{
			"type": "multi_rwx", "pid": pid, "name": name, "count": rwxRegions,
			"severity": "medium", "engine": "heuristic",
			"summary": fmt.Sprintf("多处 RWX 区: %s pid=%d count=%d", name, pid, rwxRegions),
		})
	}
	_ = filepath.Separator
	return findings
}
