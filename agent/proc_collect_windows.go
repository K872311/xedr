//go:build windows

package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 原生进程枚举：Toolhelp 快照 + 逐进程查询映像/命令行/用户/创建时间/内存/句柄。
// 取代逐进程 CIM GetOwner 的 PowerShell 方案（数百进程需数十秒且 PowerShell 自身 CPU 很高）。

const processCommandLineInformation = 60 // Win 8.1+

var sidNameCache sync.Map // sid string -> "DOMAIN\user"

func sidAccount(sid *windows.SID) string {
	if sid == nil {
		return ""
	}
	key := sid.String()
	if v, ok := sidNameCache.Load(key); ok {
		return v.(string)
	}
	acc, dom, _, err := sid.LookupAccount("")
	name := key
	if err == nil {
		name = strings.Trim(dom+`\`+acc, `\`)
	}
	sidNameCache.Store(key, name)
	return name
}

func processCommandLine(h windows.Handle) string {
	buf := make([]byte, 2048)
	for i := 0; i < 3; i++ {
		var ret uint32
		err := windows.NtQueryInformationProcess(h, processCommandLineInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &ret)
		if err == windows.STATUS_INFO_LENGTH_MISMATCH || err == windows.STATUS_BUFFER_OVERFLOW || err == windows.STATUS_BUFFER_TOO_SMALL {
			if ret <= uint32(len(buf)) || ret > 1<<20 {
				return ""
			}
			buf = make([]byte, ret)
			continue
		}
		if err != nil {
			return ""
		}
		us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
		if us.Buffer == nil || us.Length == 0 {
			return ""
		}
		return windows.UTF16ToString(unsafe.Slice(us.Buffer, us.Length/2))
	}
	return ""
}

func processUser(h windows.Handle) string {
	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) != nil {
		return ""
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	return sidAccount(tu.User.Sid)
}

// queryProcCmdUser 新进程的命令行与用户（ETW 热路径用，失败返回空）。
func queryProcCmdUser(pid uint32) (cmd, user string) {
	return queryProcCmdUserRetry(pid, 1, 0)
}

// queryProcCmdUserRetry：短命进程（wscript 等）常在 ETW 创建瞬间尚无命令行，需短暂重试。
func queryProcCmdUserRetry(pid uint32, tries int, delay time.Duration) (cmd, user string) {
	if pid <= 4 {
		return "", ""
	}
	if tries < 1 {
		tries = 1
	}
	for i := 0; i < tries; i++ {
		if i > 0 && delay > 0 {
			time.Sleep(delay)
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			continue
		}
		cmd = processCommandLine(h)
		user = processUser(h)
		windows.CloseHandle(h)
		if len(cmd) > 2000 {
			cmd = cmd[:2000]
		}
		if cmd != "" || user != "" {
			return cmd, user
		}
	}
	return "", ""
}

func queryProcUserSID(pid uint32) string {
	if pid <= 4 {
		if pid == 4 {
			return "S-1-5-18"
		}
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) != nil {
		return ""
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil || tu.User.Sid == nil {
		return ""
	}
	return tu.User.Sid.String()
}

func collectProcessesNative() ([]any, error) {
	list, err := listPIDs()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(list))
	for _, p := range list {
		item := map[string]any{"pid": int(p.pid), "ppid": int(p.ppid), "name": p.name}
		if p.pid == 0 || p.pid == 4 {
			if p.pid == 0 {
				continue
			}
			item["user"] = `NT AUTHORITY\SYSTEM`
			out = append(out, item)
			continue
		}
		var sess uint32
		if windows.ProcessIdToSessionId(p.pid, &sess) == nil {
			item["session_id"] = int(sess)
		}
		// 内存计数需要 VM_READ；受保护进程拿不到时退回仅查询权限
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, p.pid)
		if err != nil {
			h, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid)
		}
		if err != nil {
			item["path"], item["command_line"], item["user"], item["create_time"] = "", "", "", ""
			item["process_guid"] = fmt.Sprintf("%d_", p.pid)
			out = append(out, item)
			continue
		}
		path := ""
		buf := make([]uint16, windows.MAX_PATH)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
			path = windows.UTF16ToString(buf[:n])
		}
		ct := ""
		var c, e, k, u windows.Filetime
		if windows.GetProcessTimes(h, &c, &e, &k, &u) == nil {
			ct = time.Unix(0, c.Nanoseconds()).Format("2006-01-02T15:04:05")
		}
		var pmc processMemoryCounters
		pmc.cb = uint32(unsafe.Sizeof(pmc))
		mem := 0.0
		if r, _, _ := procGetProcessMemInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.cb)); r != 0 {
			mem = float64(int(float64(pmc.WorkingSetSize)/(1<<20)*10)) / 10
		}
		var hc uint32
		_, _, _ = procGetProcessHandleCnt.Call(uintptr(h), uintptr(unsafe.Pointer(&hc)))
		item["path"] = path
		item["command_line"] = processCommandLine(h)
		item["user"] = processUser(h)
		item["create_time"] = ct
		item["memory_mb"] = mem
		item["handles"] = int(hc)
		item["process_guid"] = fmt.Sprintf("%d_%s", p.pid, ct)
		windows.CloseHandle(h)
		out = append(out, item)
	}
	return out, nil
}
