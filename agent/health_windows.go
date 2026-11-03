//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modPsapi                = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemInfo   = modPsapi.NewProc("GetProcessMemoryInfo")
	modKernel32Health       = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessHandleCnt = modKernel32Health.NewProc("GetProcessHandleCount")
)

type processMemoryCounters struct {
	cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// processUsage 返回本进程累计 CPU 时间(100ns)、工作集字节、句柄数。
func processUsage() (cpu100ns uint64, rss uint64, handles uint32) {
	h := windows.CurrentProcess()
	var cr, ex, kr, us windows.Filetime
	if err := windows.GetProcessTimes(h, &cr, &ex, &kr, &us); err == nil {
		cpu100ns = (uint64(kr.HighDateTime)<<32 | uint64(kr.LowDateTime)) +
			(uint64(us.HighDateTime)<<32 | uint64(us.LowDateTime))
	}
	var pmc processMemoryCounters
	pmc.cb = uint32(unsafe.Sizeof(pmc))
	if r, _, _ := procGetProcessMemInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.cb)); r != 0 {
		rss = uint64(pmc.WorkingSetSize)
	}
	var hc uint32
	if r, _, _ := procGetProcessHandleCnt.Call(uintptr(h), uintptr(unsafe.Pointer(&hc))); r != 0 {
		handles = hc
	}
	return
}
