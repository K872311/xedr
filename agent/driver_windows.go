//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 与 driver/fakmon.h 对应：CTL_CODE(0x8A00, fn, METHOD_BUFFERED, access)
const (
	ioctlFaReadEvents = 0x8A006004
	ioctlFaProtectPID = 0x8A00A008
	ioctlFaGetStats   = 0x8A00600C

	faEvProcessCreate = 1
	faEvProcessExit   = 2
	faEvImageLoad     = 3
	faEvRemoteThread  = 4
	faEvProtectBlock  = 5
	faEvProcessOpen   = 6
	faEvRegistry      = 7
	faEvRegProtect    = 8

	faBatch = 128
)

// faEvent 布局必须与 FA_EVENT 一致（544 字节）。
type faEvent struct {
	Type uint32
	Pid  uint32
	Ppid uint32
	Tid  uint32
	Time int64
	Path [260]uint16
}

type faStats struct {
	Queued       uint32
	Dropped      uint32
	ProtectedPid uint32
	Flags        uint32
}

type kernelWatcher struct {
	mu      sync.Mutex
	h       windows.Handle
	events  []map[string]any
	cancel  context.CancelFunc
	running bool
}

func newKernelWatcher() *kernelWatcher {
	return &kernelWatcher{h: windows.InvalidHandle}
}

func openFaDevice() (windows.Handle, error) {
	name, _ := windows.UTF16PtrFromString(`\\.\FaKmon`)
	return windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
}

// start 仅在驱动已加载时生效；返回是否进入内核模式。
func (w *kernelWatcher) start(ctx context.Context) bool {
	h, err := openFaDevice()
	if err != nil {
		return false
	}
	w.mu.Lock()
	w.h = h
	cctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.running = true
	w.mu.Unlock()
	log.Printf("kernel: FaKmon 驱动已连接")
	go w.loop(cctx)
	return true
}

func (w *kernelWatcher) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		w.cancel()
	}
	if w.h != windows.InvalidHandle {
		_ = windows.CloseHandle(w.h)
		w.h = windows.InvalidHandle
	}
	w.running = false
}

func (w *kernelWatcher) active() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.running
}

func (w *kernelWatcher) drain() []map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.events
	w.events = nil
	return out
}

func (w *kernelWatcher) protectSelf(pid uint32) error {
	w.mu.Lock()
	h := w.h
	w.mu.Unlock()
	if h == windows.InvalidHandle {
		return fmt.Errorf("驱动未连接")
	}
	var ret uint32
	return windows.DeviceIoControl(h, ioctlFaProtectPID, (*byte)(unsafe.Pointer(&pid)), 4, nil, 0, &ret, nil)
}

func (w *kernelWatcher) stats() (faStats, error) {
	var s faStats
	w.mu.Lock()
	h := w.h
	w.mu.Unlock()
	if h == windows.InvalidHandle {
		return s, fmt.Errorf("驱动未连接")
	}
	var ret uint32
	err := windows.DeviceIoControl(h, ioctlFaGetStats, nil, 0, (*byte)(unsafe.Pointer(&s)), uint32(unsafe.Sizeof(s)), &ret, nil)
	return s, err
}

func (w *kernelWatcher) loop(ctx context.Context) {
	buf := make([]faEvent, faBatch)
	names := map[uint32]string{}
	refreshNames := func() {
		if ps, err := listPIDs(); err == nil {
			m := make(map[uint32]string, len(ps))
			for _, p := range ps {
				m[p.pid] = p.name
			}
			names = m
		}
	}
	refreshNames()
	lastRefresh := time.Now()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		w.mu.Lock()
		h := w.h
		w.mu.Unlock()
		if h == windows.InvalidHandle {
			return
		}
		var ret uint32
		size := uint32(unsafe.Sizeof(buf[0])) * faBatch
		if err := windows.DeviceIoControl(h, ioctlFaReadEvents, nil, 0, (*byte)(unsafe.Pointer(&buf[0])), size, &ret, nil); err != nil {
			log.Printf("kernel read: %v", err)
			w.stop()
			return
		}
		n := int(ret / uint32(unsafe.Sizeof(buf[0])))
		if n == 0 {
			continue
		}
		if time.Since(lastRefresh) > 5*time.Second {
			refreshNames()
			lastRefresh = time.Now()
		}
		var out []map[string]any
		for i := 0; i < n; i++ {
			if ev := convertFaEvent(&buf[i], names); ev != nil {
				out = append(out, ev)
			}
		}
		w.mu.Lock()
		w.events = append(w.events, out...)
		if len(w.events) > 1000 {
			w.events = w.events[len(w.events)-1000:]
		}
		w.mu.Unlock()
	}
}

func convertFaEvent(e *faEvent, names map[uint32]string) map[string]any {
	path := windows.UTF16ToString(e.Path[:])
	ts := filetimeToTime(e.Time).Format("2006-01-02T15:04:05")
	base := path
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		base = path[i+1:]
	}
	switch e.Type {
	case faEvProcessCreate:
		sev, sum := "info", "内核进程创建: "+base
		if pathLooksHot(path) {
			sev, sum = "medium", "可疑路径进程(内核): "+base
		}
		return map[string]any{
			"etype": "process_create_kernel", "summary": sum, "severity": sev, "ts": ts,
			"detail": map[string]any{
				"source": "kernel", "pid": e.Pid, "ppid": e.Ppid, "name": base, "path": path,
				"parent_name": names[e.Ppid],
			},
		}
	case faEvProcessExit:
		return map[string]any{
			"etype": "process_exit_kernel", "summary": "内核进程退出: " + names[e.Pid], "severity": "info", "ts": ts,
			"detail": map[string]any{"source": "kernel", "pid": e.Pid, "name": names[e.Pid]},
		}
	case faEvImageLoad:
		// 驱动侧已过滤为「内核模块 + 可疑目录映像」；PID 0 表示内核模块（驱动）加载
		if e.Pid == 0 {
			sev := "info"
			if pathLooksHot(path) {
				sev = "high"
			}
			return map[string]any{
				"etype": "driver_load_kernel", "summary": "内核驱动加载: " + base, "severity": sev, "ts": ts,
				"detail": map[string]any{"source": "kernel", "pid": 0, "name": base, "path": path},
			}
		}
		if !pathLooksHot(path) {
			return nil
		}
		// 只用缓存：有签名放过；未知不报（异步预热）；明确未签名才报
		valid, st, known := peSignedCached(path)
		if known && valid {
			return nil
		}
		if !known {
			peMetaWarmAsync(path)
			return nil
		}
		return map[string]any{
			"etype": "image_load_kernel", "summary": "可疑目录未签名模块: " + base, "severity": "high", "ts": ts,
			"detail": map[string]any{
				"source": "kernel", "pid": e.Pid,
				"name": base, "module": base, "module_name": base,
				"path": path, "image": path,
				"process_name": names[e.Pid], "host_process": names[e.Pid],
				"ext": ".dll", "signed": st,
			},
		}
	case faEvRemoteThread:
		return map[string]any{
			"etype": "remote_thread_kernel",
			"summary": fmt.Sprintf("远程线程注入: %s → %s", nameOr(names, e.Ppid), nameOr(names, e.Pid)),
			"severity": "high", "ts": ts,
			"detail": map[string]any{
				"source": "kernel", "pid": e.Pid, "name": names[e.Pid], "tid": e.Tid,
				"ppid": e.Ppid, "parent_name": names[e.Ppid],
			},
		}
	case faEvProtectBlock:
		return map[string]any{
			"etype": "protect_block_kernel",
			"summary": "拦截对 Agent 的结束/写内存: " + nameOr(names, e.Ppid), "severity": "high", "ts": ts,
			"detail": map[string]any{"source": "kernel", "pid": e.Ppid, "name": names[e.Ppid], "target_pid": e.Pid},
		}
	case faEvProcessOpen:
		acc := e.Tid
		req := nameOr(names, e.Ppid)
		if kernelProcNoise(req) {
			return nil
		}
		want := uint32(0x10 | 0x20 | 0x8 | 0x2 | 0x400)
		if acc&want == 0 {
			return nil
		}
		return map[string]any{
			"etype": "process_access_kernel",
			"summary": fmt.Sprintf("进程打开 lsass(内核): %s access=0x%X", req, acc),
			"severity": "high", "ts": ts,
			"detail": map[string]any{
				"source": "kernel", "pid": e.Ppid, "name": names[e.Ppid],
				"target_pid": e.Pid, "target_name": "lsass.exe", "access": fmt.Sprintf("0x%X", acc),
			},
		}
	case faEvRegistry:
		return map[string]any{
			"etype": "registry_write_kernel",
			"summary": "注册表写入(内核): " + path, "severity": "medium", "ts": ts,
			"detail": map[string]any{
				"source": "kernel", "pid": e.Pid, "name": names[e.Pid], "path": path, "notify_class": e.Ppid,
			},
		}
	case faEvRegProtect:
		return map[string]any{
			"etype": "reg_protect_kernel",
			"summary": "拦截 Agent 服务键篡改: " + nameOr(names, e.Pid), "severity": "high", "ts": ts,
			"detail": map[string]any{"source": "kernel", "pid": e.Pid, "name": names[e.Pid], "path": path},
		}
	}
	return nil
}

func kernelProcNoise(name string) bool {
	switch strings.ToLower(name) {
	case "msmpeng.exe", "nissrv.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
		"svchost.exe", "taskmgr.exe", "procexp.exe", "procexp64.exe", "vmtoolsd.exe":
		return true
	}
	return false
}

func nameOr(m map[uint32]string, pid uint32) string {
	if n := m[pid]; n != "" {
		return n
	}
	return fmt.Sprintf("pid-%d", pid)
}

func filetimeToTime(ft int64) time.Time {
	const epochDiff = 116444736000000000
	if ft <= epochDiff {
		return time.Now()
	}
	return time.Unix(0, (ft-epochDiff)*100)
}
