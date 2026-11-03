//go:build windows

package main

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// currentBootID 本次开机的稳定标识：优先系统自增的 BootId，其次按开机时刻（分钟）推算。
func currentBootID() string {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`, registry.QUERY_VALUE); err == nil {
		v, _, e := k.GetIntegerValue("BootId")
		k.Close()
		if e == nil && v > 0 {
			return fmt.Sprintf("b%d", v)
		}
	}
	up := time.Duration(windows.DurationSinceBoot())
	boot := time.Now().Add(-up).Unix() / 60
	return fmt.Sprintf("t%x", boot)
}

// lookupProcInfo 读取现存进程的真实创建时间 / 父 PID / 映像。
func lookupProcInfo(pid uint32) (procInfo, bool) {
	if pid == 0 || pid == 4 {
		return procInfo{}, false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return procInfo{}, false
	}
	defer windows.CloseHandle(h)
	var ct, et, kt, ut windows.Filetime
	if windows.GetProcessTimes(h, &ct, &et, &kt, &ut) != nil {
		return procInfo{}, false
	}
	out := procInfo{Start: int64(ct.HighDateTime)<<32 | int64(ct.LowDateTime)}
	var pbi windows.PROCESS_BASIC_INFORMATION
	if windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil) == nil {
		out.PPID = uint32(pbi.InheritedFromUniqueProcessId)
	}
	buf := make([]uint16, windows.MAX_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
		out.Image = windows.UTF16ToString(buf[:n])
		out.Name = out.Image
		if i := strings.LastIndexAny(out.Image, `\/`); i >= 0 {
			out.Name = out.Image[i+1:]
		}
	}
	return out, true
}

func livePIDSet() map[uint32]bool {
	ps, err := listPIDs()
	if err != nil || len(ps) == 0 {
		return nil
	}
	m := make(map[uint32]bool, len(ps))
	for _, p := range ps {
		m[p.pid] = true
	}
	return m
}
