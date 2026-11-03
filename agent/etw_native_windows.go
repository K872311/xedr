//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/0xrawsec/golang-etw/etw"
	"golang.org/x/sys/windows"
)

const etwSessionName = "ForensicAgentETW"

var (
	guidKernelProcess = etw.MustParseGUIDFromString("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")
	guidKernelNetwork = etw.MustParseGUIDFromString("{7DD42A49-5329-4832-8DFD-43D979153A88}")
	guidKernelFile    = etw.MustParseGUIDFromString("{EDD08927-9CC4-4E65-B970-C2560FB5C289}")
	guidDNSClient     = etw.MustParseGUIDFromString("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}")
	guidAMSI          = etw.MustParseGUIDFromString("{17489600-3900-4396-B6E6-7B572478086D}")
	guidWin32k        = etw.MustParseGUIDFromString("{8c416c79-d49b-4f01-a467-e56d3aa8234c}")
	guidThreatIntel   = etw.MustParseGUIDFromString("{11cdeda0-043e-11d1-0eb4-00c04fd3251b}")
	guidWMIActivity   = etw.MustParseGUIDFromString("{1418ef04-b0b4-4623-8fd3-43dae2e8896d}")
	guidLDAPClient    = etw.MustParseGUIDFromString("{098f7910-4617-4158-adbb-0485d76b4e32}")
)

const amsiEventScanBuffer = 1101

var win32kEventAPI = map[uint16]string{
	1000: "SetWinEventHook",
	1001: "RegisterRawInputDevices",
	1002: "SetWindowsHookEx",
	1003: "GetAsyncKeyState",
}

// Threat Intelligence ETW（Windows 10+）；事件 ID → API 名近似映射。
var threatIntelEventAPI = map[uint16]string{
	1001: "WriteProcessMemory",
	1003: "ReadProcessMemory",
	1004: "OpenProcess",
	1007: "VirtualAllocEx",
	1008: "VirtualFreeEx",
	1010: "VirtualProtect",
	1024: "QueueUserAPC",
	1025: "SetThreadContext",
	1036: "MapViewOfFile",
	1037: "UnmapViewOfFile",
}

var wmiActivityEvents = map[uint16]bool{
	5859: true, 5860: true, 5861: true,
}

var ldapClientEvents = map[uint16]bool{
	10: true, 11: true, 30: true,
}

// 进程 1/2：ProcessStart/Stop；5：ImageLoad。部分主机不下发 1/2，
// 因此以每个 PID 首次加载的 .exe 映像作为进程创建。
// 网络 12/28：TCP v4/v6 connect。文件 30：CreateNewFile。
// DNS-Client 3008：发起进程上下文的"查询完成"（状态 87 表示交给 dnscache 异步处理，结果另见 3020）；
// 3020：dnscache 服务记录的应答，带 ClientPID 用于归属到真正发起查询的进程。
var etwWantIDs = map[string]map[uint16]bool{
	"process": {1: true, 2: true, 5: true},
	"network": {12: true, 28: true},
	"file":    {30: true},
	"dns":     {3008: true, 3020: true},
}

var hotFileExt = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".scr": true, ".ps1": true, ".bat": true,
	".cmd": true, ".vbs": true, ".js": true, ".jse": true, ".hta": true, ".lnk": true, ".msi": true,
}

type etwNativeState struct {
	mu        sync.Mutex
	started   map[uint32]bool
	netSeen   map[string]time.Time
	pidCache  map[uint32]pidName
	pidAt     time.Time
	devPrefix map[string]string // \Device\HarddiskVolumeN -> C:
	emit      func(map[string]any)
	dll       *dllGate
}

func newETWNativeState() *etwNativeState {
	st := &etwNativeState{
		started:  map[uint32]bool{},
		netSeen:  map[string]time.Time{},
		pidCache: map[uint32]pidName{},
		emit:     func(map[string]any) {},
		dll:      newDLLGate(),
	}
	st.devPrefix = dosDeviceMap()
	return st
}

func dosDeviceMap() map[string]string {
	m := map[string]string{}
	buf := make([]uint16, 512)
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		d, _ := windows.UTF16PtrFromString(drive)
		n, err := windows.QueryDosDevice(d, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		m[strings.ToLower(windows.UTF16ToString(buf[:n]))] = drive
	}
	return m
}

func (st *etwNativeState) dosPath(p string) string {
	low := strings.ToLower(p)
	for dev, drive := range st.devPrefix {
		if strings.HasPrefix(low, dev+`\`) {
			return drive + p[len(dev):]
		}
	}
	return strings.TrimPrefix(p, `\??\`)
}

// queryProc 直接查询进程父 PID 与映像名（快照里还没有刚创建的进程）。
func queryProc(pid uint32) (pidName, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return pidName{}, false
	}
	defer windows.CloseHandle(h)
	out := pidName{pid: pid}
	var pbi windows.PROCESS_BASIC_INFORMATION
	if windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil) == nil {
		out.ppid = uint32(pbi.InheritedFromUniqueProcessId)
	}
	buf := make([]uint16, windows.MAX_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
		full := windows.UTF16ToString(buf[:n])
		if i := strings.LastIndexAny(full, `\/`); i >= 0 {
			full = full[i+1:]
		}
		out.name = full
	}
	return out, true
}

func (st *etwNativeState) proc(pid uint32) pidName {
	st.mu.Lock()
	defer st.mu.Unlock()
	if p, ok := st.pidCache[pid]; ok {
		return p
	}
	if p, ok := queryProc(pid); ok && p.name != "" {
		st.pidCache[pid] = p
		return p
	}
	// 进程已退出：最多每秒刷新一次快照兜底
	if time.Since(st.pidAt) > time.Second {
		if ps, err := listPIDs(); err == nil {
			m := make(map[uint32]pidName, len(ps))
			for _, p := range ps {
				m[p.pid] = p
			}
			st.pidCache = m
			st.pidAt = time.Now()
		}
	}
	return st.pidCache[pid]
}

// runNative 建立实时 ETW 会话；需要管理员权限，失败时由调用方回退。
func (w *etwWatcher) runNative(ctx context.Context) error {
	s := etw.NewRealTimeSession(etwSessionName)
	if err := s.EnableProvider(etw.Provider{GUID: guidKernelProcess.String(), EnableLevel: 0xff, MatchAnyKeyword: 0x10 | 0x40}); err != nil {
		_ = s.Stop()
		return fmt.Errorf("enable Kernel-Process: %w", err)
	}
	if err := s.EnableProvider(etw.Provider{GUID: guidKernelNetwork.String(), EnableLevel: 0xff, MatchAnyKeyword: 0x10}); err != nil {
		log.Printf("etw: Kernel-Network 不可用: %v", err)
	}
	if err := s.EnableProvider(etw.Provider{GUID: guidKernelFile.String(), EnableLevel: 0xff, MatchAnyKeyword: 0x1000}); err != nil {
		log.Printf("etw: Kernel-File 不可用: %v", err)
	}
	// DNS-Client 事件关键字在高 32 位（含通道位），必须用 64 位全掩码
	if err := s.EnableProvider(etw.Provider{GUID: guidDNSClient.String(), EnableLevel: 0xff, MatchAnyKeyword: 0xffffffffffffffff}); err != nil {
		log.Printf("etw: DNS-Client 不可用: %v", err)
	}
	if integrationEnabled("amsi") {
		if err := s.EnableProvider(etw.Provider{GUID: guidAMSI.String(), EnableLevel: 0xff, MatchAnyKeyword: 0xffffffffffffffff}); err != nil {
			log.Printf("etw: AMSI 不可用（需管理员/策略允许）: %v", err)
		}
	}
	if integrationEnabled("api_etw") {
		if err := s.EnableProvider(etw.Provider{GUID: guidWin32k.String(), EnableLevel: 0xff, MatchAnyKeyword: 0x5120}); err != nil {
			log.Printf("etw: Win32k API 不可用: %v", err)
		}
		if err := s.EnableProvider(etw.Provider{GUID: guidThreatIntel.String(), EnableLevel: 0xff, MatchAnyKeyword: 0xffffffffffffffff}); err != nil {
			log.Printf("etw: Threat-Intelligence API 不可用: %v", err)
		}
		if err := s.EnableProvider(etw.Provider{GUID: guidWMIActivity.String(), EnableLevel: 0xff, MatchAnyKeyword: 0xffffffffffffffff}); err != nil {
			log.Printf("etw: WMI-Activity 不可用: %v", err)
		}
		if err := s.EnableProvider(etw.Provider{GUID: guidLDAPClient.String(), EnableLevel: 0xff, MatchAnyKeyword: 0xffffffffffffffff}); err != nil {
			log.Printf("etw: LDAP-Client 不可用: %v", err)
		}
	}

	st := newETWNativeState()
	st.emit = w.push
	debugDNS := os.Getenv("FA_ETW_DEBUG") == "dns"
	c := etw.NewRealTimeConsumer(ctx)
	c.FromSessions(s)
	c.EventRecordCallback = func(er *etw.EventRecord) bool {
		id := er.EventHeader.EventDescriptor.Id
		pg := &er.EventHeader.ProviderId
		switch {
		case pg.Equals(guidKernelProcess):
			return etwWantIDs["process"][id]
		case pg.Equals(guidKernelNetwork):
			return etwWantIDs["network"][id]
		case pg.Equals(guidKernelFile):
			return etwWantIDs["file"][id]
		case pg.Equals(guidDNSClient):
			return etwWantIDs["dns"][id] || debugDNS
		case pg.Equals(guidAMSI):
			return integrationEnabled("amsi") && id == amsiEventScanBuffer
		case pg.Equals(guidWin32k):
			_, ok := win32kEventAPI[id]
			return integrationEnabled("api_etw") && ok
		case pg.Equals(guidThreatIntel):
			return integrationEnabled("api_etw") && threatIntelEventAPI[id] != ""
		case pg.Equals(guidWMIActivity):
			return integrationEnabled("api_etw") && wmiActivityEvents[id]
		case pg.Equals(guidLDAPClient):
			return integrationEnabled("api_etw") && ldapClientEvents[id]
		}
		return false
	}
	c.EventCallback = func(e *etw.Event) error {
		if debugDNS && strings.Contains(e.System.Provider.Name, "DNS") {
			log.Printf("etw-debug dns id=%d provider=%s pid=%d data=%v", e.System.EventID, e.System.Provider.Name, e.System.Execution.ProcessID, e.EventData)
		}
		if ev := st.convert(e); ev != nil {
			w.push(ev)
		}
		return nil
	}
	if err := c.Start(); err != nil {
		_ = s.Stop()
		return fmt.Errorf("consumer start: %w", err)
	}
	w.mu.Lock()
	w.mode = "etw_native"
	w.mu.Unlock()
	setSensorPipeline("etw_native", "winevent", "")
	log.Printf("etw: 原生实时会话 %s 已启动（进程/网络/文件）", etwSessionName)
	w.push(map[string]any{
		"etype": "etw_status", "summary": "ETW 原生会话: Process/Network/File/DNS", "severity": "info",
		"ts": time.Now().Format("2006-01-02T15:04:05"), "detail": map[string]any{"mode": "etw_native"},
	})

	gc := time.NewTicker(time.Minute)
	defer gc.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = c.Stop()
			_ = s.Stop()
			return nil
		case <-gc.C:
			st.gc()
			if now := time.Now(); dnsCache.due(now) {
				for _, ev := range dnsCache.flush(now) {
					w.push(ev)
				}
			}
		}
	}
}

func (st *etwNativeState) gc() {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.started) > 20000 {
		st.started = map[uint32]bool{}
	}
	for k, t := range st.netSeen {
		if time.Since(t) > 10*time.Minute {
			delete(st.netSeen, k)
		}
	}
	st.dll.gc(time.Now())
}

func propStr(e *etw.Event, k string) string {
	if v, ok := e.EventData[k]; ok {
		return fmt.Sprint(v)
	}
	return ""
}

func propU32(e *etw.Event, k string) uint32 {
	s := propStr(e, k)
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), baseOf(s), 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func baseOf(s string) int {
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		return 16
	}
	return 10
}

func (st *etwNativeState) convert(e *etw.Event) map[string]any {
	ts := e.System.TimeCreated.SystemTime.Format("2006-01-02T15:04:05")
	switch e.System.Provider.Name {
	case "Microsoft-Windows-Kernel-Process":
		return st.convertProcess(e, e.System.EventID, ts)
	case "Microsoft-Windows-Kernel-Network":
		return st.convertNetwork(e, ts)
	case "Microsoft-Windows-Kernel-File":
		return st.convertFile(e, ts)
	case "Microsoft-Windows-DNS-Client":
		return st.convertDNS(e, ts)
	case "Microsoft-Windows-AMSI":
		return st.convertAMSI(e, ts)
	case "Microsoft-Windows-Win32k":
		return st.convertWin32kAPI(e, ts)
	case "Microsoft-Windows-Threat-Intelligence":
		return st.convertThreatIntelAPI(e, ts)
	case "Microsoft-Windows-WMI-Activity":
		return st.convertWMIActivity(e, ts)
	case "Microsoft-Windows-LDAP-Client":
		return st.convertLDAPClient(e, ts)
	}
	return nil
}

func attachUserSID(detail map[string]any, pid uint32) {
	if detail == nil || pid == 0 {
		return
	}
	if asString(detail["user_id"]) != "" {
		return
	}
	if sid := queryProcUserSID(pid); sid != "" {
		detail["user_id"] = sid
	}
}

func (st *etwNativeState) convertWMIActivity(e *etw.Event, ts string) map[string]any {
	pid := propU32(e, "ClientProcessId")
	if pid == 0 {
		pid = uint32(e.System.Execution.ProcessID)
	}
	op := strings.TrimSpace(propStr(e, "Operation"))
	if op == "" {
		op = strings.TrimSpace(propStr(e, "PossibleCause"))
	}
	if op == "" && e.System.EventID != 5859 {
		return nil
	}
	api := "IWbemServices::ExecMethod"
	low := strings.ToLower(op)
	switch {
	case strings.Contains(low, "execquery"):
		api = "IWbemServices::ExecQuery"
	case strings.Contains(low, "execmethod"), strings.Contains(low, "putinstance"), strings.Contains(low, "createinstance"), strings.Contains(low, "deleteinstance"):
		api = "IWbemServices::ExecMethod"
	case e.System.EventID == 5859:
		// 5859 常带 WQL 查询文本
		api = "IWbemServices::ExecQuery"
	default:
		if op == "" {
			return nil
		}
	}
	p := st.proc(pid)
	at := filetimeOf(e.System.TimeCreated.SystemTime)
	detail := map[string]any{
		"source": "wmi_activity_etw", "pid": pid, "api_name": api,
		"process_name": p.name, "operation": op,
		"wmi_namespace": propStr(e, "NamespaceName"),
		"wmi_path":      propStr(e, "Path"),
	}
	attachUserSID(detail, pid)
	enrichProcessExt(detail, at)
	attachHostProcessDetails(detail, at)
	if strings.TrimSpace(asString(detail["command_line"])) == "" {
		if cmd, user := queryProcCmdUserRetry(pid, 4, 45*time.Millisecond); cmd != "" || user != "" {
			if cmd != "" {
				detail["command_line"] = cmd
			}
			if user != "" {
				detail["user"] = user
			}
			procEntities.applyCmdLine(pid, at, cmd, user)
		}
	}
	sev := "medium"
	if strings.Contains(strings.ToLower(op), "mppreference") || strings.Contains(strings.ToLower(op), "defender") {
		sev = "high"
	}
	return map[string]any{
		"etype": "api_call", "summary": "WMI API: " + api + " " + p.name,
		"severity": sev, "ts": ts, "detail": detail,
	}
}

func (st *etwNativeState) convertLDAPClient(e *etw.Event, ts string) map[string]any {
	pid := propU32(e, "ProcessId")
	if pid == 0 {
		pid = uint32(e.System.Execution.ProcessID)
	}
	filter := propStr(e, "SearchFilter")
	if filter == "" {
		filter = propStr(e, "LdapFilter")
	}
	if filter == "" {
		filter = propStr(e, "Filter")
	}
	if len(filter) < 4 {
		return nil
	}
	if len(filter) > 4096 {
		filter = filter[:4096]
	}
	p := st.proc(pid)
	at := filetimeOf(e.System.TimeCreated.SystemTime)
	detail := map[string]any{
		"source": "ldap_client_etw", "pid": pid, "api_name": "ldap_search",
		"process_name": p.name, "search_filter": filter,
		"ldap_host": propStr(e, "HostName"),
	}
	attachUserSID(detail, pid)
	enrichProcessExt(detail, at)
	return map[string]any{
		"etype": "api_call", "summary": "LDAP 搜索: " + p.name,
		"severity": "low", "ts": ts, "detail": detail,
	}
}

func (st *etwNativeState) convertWin32kAPI(e *etw.Event, ts string) map[string]any {
	api := win32kEventAPI[e.System.EventID]
	if api == "" {
		return nil
	}
	pid := uint32(e.System.Execution.ProcessID)
	if pid == 0 {
		pid = propU32(e, "ProcessId")
	}
	p := st.proc(pid)
	at := filetimeOf(e.System.TimeCreated.SystemTime)
	detail := map[string]any{
		"source": "win32k_etw", "pid": pid, "api_name": api,
		"process_name": p.name,
		"hook_filter_type":    propU32(e, "FilterType"),
		"background_call_count": propU32(e, "BackgroundCallCount"),
		"ms_since_last_key":     propU32(e, "MsSinceLastKeyEvent"),
	}
	enrichProcessExt(detail, at)
	sev := "info"
	if api == "GetAsyncKeyState" || api == "SetWindowsHookEx" {
		sev = "low"
	}
	return map[string]any{
		"etype": "api_call", "summary": "Win32k API: " + api + " " + p.name,
		"severity": sev, "ts": ts, "detail": detail,
	}
}

func (st *etwNativeState) convertThreatIntelAPI(e *etw.Event, ts string) map[string]any {
	api := threatIntelEventAPI[e.System.EventID]
	if api == "" {
		api = propStr(e, "ApiName")
	}
	if api == "" {
		return nil
	}
	pid := uint32(e.System.Execution.ProcessID)
	if pid == 0 {
		pid = propU32(e, "CallingProcessId")
	}
	if pid == 0 {
		pid = propU32(e, "ProcessId")
	}
	p := st.proc(pid)
	at := filetimeOf(e.System.TimeCreated.SystemTime)
	detail := map[string]any{
		"source": "threat_intel_etw", "pid": pid, "api_name": api,
		"process_name": p.name, "target_pid": propU32(e, "TargetProcessId"),
	}
	enrichProcessExt(detail, at)
	sev := "medium"
	switch api {
	case "WriteProcessMemory", "VirtualProtect", "QueueUserAPC", "SetThreadContext":
		sev = "high"
	}
	return map[string]any{
		"etype": "api_call", "summary": "内核 API: " + api + " " + p.name,
		"severity": sev, "ts": ts, "detail": detail,
	}
}

func (st *etwNativeState) convertAMSI(e *etw.Event, ts string) map[string]any {
	if e.System.EventID != amsiEventScanBuffer {
		return nil
	}
	pid := uint32(e.System.Execution.ProcessID)
	if pid == 0 {
		pid = propU32(e, "ProcessId")
	}
	content := propStr(e, "Content")
	if content == "" {
		content = propStr(e, "ScriptContent")
	}
	if content == "" {
		content = propStr(e, "Buffer")
	}
	if len(content) < 8 {
		return nil
	}
	const maxBuf = 16384
	if len(content) > maxBuf {
		content = content[:maxBuf]
	}
	app := propStr(e, "ApplicationName")
	if app == "" {
		app = propStr(e, "AppName")
	}
	cname := propStr(e, "ContentName")
	p := st.proc(pid)
	at := filetimeOf(e.System.TimeCreated.SystemTime)
	detail := map[string]any{
		"source": "amsi_etw", "pid": pid, "api_name": "AmsiScanBuffer",
		"app_name": app, "content_name": cname, "buffer": content,
		"process_name": p.name,
	}
	enrichProcessExt(detail, at)
	return map[string]any{
		"etype": "api_amsi", "summary": "AMSI 扫描: " + p.name, "severity": "info", "ts": ts, "detail": detail,
	}
}

func (st *etwNativeState) convertDNS(e *etw.Event, ts string) map[string]any {
	q := propStr(e, "QueryName")
	if q == "" {
		q = propStr(e, "Query")
	}
	if q == "" {
		return nil
	}
	if normalizeDomain(q) == "" {
		return nil
	}
	var pid, status uint32
	switch e.System.EventID {
	case 3008:
		status = propU32(e, "QueryStatus")
		if status == 87 {
			return nil // 异步交给 dnscache，等 3020
		}
		pid = uint32(e.System.Execution.ProcessID)
	case 3020:
		status = propU32(e, "Status")
		// 1460 超时 / 1223 取消 / 9701 无缓存 等是单网卡中间态，只认最终应答与否定应答
		if status != 0 && !isNXStatus(status) && status != 9501 {
			return nil
		}
		pid = propU32(e, "ClientPID")
		if pid == 0 {
			pid = uint32(e.System.Execution.ProcessID)
		}
	default:
		return nil
	}
	at := e.System.TimeCreated.SystemTime
	rec := dnsRecord{
		Query: q, QType: uint16(propU32(e, "QueryType")), Status: status,
		PID: pid, Proc: st.proc(pid).name, At: at,
	}
	rec.Answers, rec.CNAMEs = parseDNSResults(propStr(e, "QueryResults"))
	if ent := procEntities.resolve(pid, filetimeOf(at)); ent != nil {
		rec.Entity = ent.ID
		if rec.Proc == "" {
			rec.Proc = ent.Name
		}
	}
	for _, ev := range dnsCache.observe(rec) {
		st.emit(ev)
	}
	return nil
}

func (st *etwNativeState) convertProcess(e *etw.Event, id uint16, ts string) map[string]any {
	pid := propU32(e, "ProcessID")
	img := st.dosPath(propStr(e, "ImageName"))
	base := img
	if i := strings.LastIndexAny(img, `\/`); i >= 0 {
		base = img[i+1:]
	}
	switch id {
	case 1, 5:
		if id == 5 && !strings.HasSuffix(strings.ToLower(img), ".exe") {
			lowImg := strings.ToLower(img)
			if strings.HasSuffix(lowImg, ".sys") && pathLooksInterestingDriver(img) {
				p := st.proc(pid)
				at := e.System.TimeCreated.SystemTime
				valid, sigStatus, known := peSignedCached(img)
				if known && valid {
					return nil
				}
				if !known {
					peMetaWarmAsync(img)
					return nil
				}
				sev := "high"
				sum := "未签名驱动模块加载: " + base
				if strings.Contains(lowImg, `\system32\drivers\`) {
					sum = "系统目录未签名驱动: " + base
					sev = "critical"
				}
				detail := map[string]any{
					"source": "etw", "pid": pid, "name": base, "path": img, "image": img,
					"module": base, "ext": ".sys", "signed": sigStatus,
					"process_name": p.name,
				}
				procEntities.annotate(detail, filetimeOf(at))
				return map[string]any{
					"etype": "driver_load_etw", "summary": sum, "severity": sev, "ts": ts,
					"detail": detail,
				}
			}
			if strings.HasSuffix(lowImg, ".dll") && pathLooksInterestingDLL(img) {
				p := st.proc(pid)
				at := e.System.TimeCreated.SystemTime
				entID := ""
				if ent := procEntities.resolve(pid, filetimeOf(at)); ent != nil {
					entID = ent.ID
					if p.name == "" {
						p.name = ent.Name
					}
				}
				drop := pathInDropZone(img)
				sysDLL := isWindowsSystemPath(img) || strings.Contains(strings.ToLower(img), `\windows\`)
				// ETW 回调内禁止同步 PowerShell 验签（会拖慢开应用并导致掉线），只用缓存 + 异步预热
				valid, sigStatus, known := peSignedCached(img)
				if known && valid {
					return nil
				}
				if !known {
					peMetaWarmAsync(img)
					return nil
				}
				// 已确认明确未签名/损坏：系统目录与投放区才上报；其他目录（开发/软件）不刷屏
				if !sysDLL && !drop {
					return nil
				}
				unsigned := known && !valid
				if !st.dll.allow(p.name, img, entID, drop || sysDLL, unsigned || !known, at) {
					return nil
				}
				sev := "high"
				sum := "未签名 DLL 加载: " + base
				switch {
				case sysDLL && unsigned:
					sum = "系统目录未签名 DLL: " + base
				case drop && unsigned:
					sum = "可疑目录未签名 DLL: " + base
				}
				detail := map[string]any{
					"source": "etw", "pid": pid,
					"name": base, "module": base, "module_name": base,
					"path": img, "image": img,
					"process_name": p.name, "process_path": "",
					"ext": ".dll",
				}
				if sigStatus != "" {
					detail["signed"] = sigStatus
					if pm, ok := peCache.Load(strings.ToLower(img)); ok {
						if s := pm.(peMeta).Signer; s != "" {
							detail["signer"] = s
						}
					}
				}
				if p.name != "" {
					detail["host_process"] = p.name
				}
				if sysDLL {
					detail["system_dir"] = true
				}
				procEntities.annotate(detail, filetimeOf(at))
				return map[string]any{
					"etype": "image_load_etw", "summary": sum, "severity": sev, "ts": ts,
					"detail": detail,
				}
			}
			return nil
		}
		// 以真实创建时间确定实例：同一实例的 1/5 事件只报一次，PID 复用的新实例照常上报
		evAt := e.System.TimeCreated.SystemTime
		evFT := filetimeOf(evAt)
		start, approx := evFT, true
		info, alive := lookupProcInfo(pid)
		if alive && absI64(info.Start-evFT) <= 5*ftPerSec {
			start, approx = info.Start, false
		}
		ppid := propU32(e, "ParentProcessID")
		if ppid == 0 && alive && !approx {
			ppid = info.PPID
		}
		ent, isNew := procEntities.onStart(pid, ppid, start, base, img, approx)
		if !isNew {
			return nil
		}
		st.mu.Lock()
		st.started[pid] = true
		// 新进程：缓存里同 PID 的条目属于已退出的旧进程（PID 复用）
		delete(st.pidCache, pid)
		st.mu.Unlock()
		if ppid == 0 {
			ppid = st.proc(pid).ppid
		}
		sev, sum := "info", "ETW进程创建: "+base
		if pathLooksHot(img) {
			sev, sum = "medium", "可疑路径进程(ETW): "+base
		}
		detail := map[string]any{
			"source": "etw", "pid": pid, "name": base, "path": img,
			"create_time": ts,
		}
		if id == 5 {
			detail["process_infer"] = "image_load"
		}
		// 短命进程在事件送达前已退出，父进程无法解析时宁缺勿错
		if ppid != 0 {
			detail["ppid"] = ppid
			parent := st.proc(ppid)
			if parent.name != "" {
				detail["parent_name"] = parent.name
			}
			if parent.createTime != "" {
				detail["parent_create_time"] = parent.createTime
			}
		}
		attachIdentityToDetail(detail, ts)
		mergeInto(detail, procEntities.fieldsOf(ent))
		enrichProcessExt(detail, start)
		if px, ok := detail["process_ext"].(map[string]any); ok {
			if pp := asString(px["parent_path"]); pp != "" {
				detail["parent_path"] = pp
			}
		}
		st.mu.Lock()
		st.pidCache[pid] = pidName{pid: pid, ppid: ppid, name: base, createTime: ts, guid: asString(detail["process_guid"])}
		st.mu.Unlock()
		elev, integ := queryTokenMeta(pid)
		if elev != "" {
			detail["elevated"] = elev
		}
		if integ != "" {
			detail["integrity"] = integ
		}
		// 命令行 / 用户：LOLBin 检测依赖；原生 API，不走 PowerShell
		tries, delay := 3, 40*time.Millisecond
		switch strings.ToLower(base) {
		case "wscript.exe", "cscript.exe":
			tries, delay = 6, 50*time.Millisecond
		case "cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe":
			tries, delay = 5, 45*time.Millisecond
		case "rundll32.exe", "regsvr32.exe", "msbuild.exe":
			tries, delay = 4, 45*time.Millisecond
		}
		if cmd, user := queryProcCmdUserRetry(pid, tries, delay); cmd != "" || user != "" {
			if cmd != "" {
				detail["command_line"] = cmd
			}
			if user != "" {
				detail["user"] = user
			}
		}
		enrichLOLBinFields(detail)
		return map[string]any{
			"etype": "process_create_etw", "summary": sum, "severity": sev, "ts": ts, "detail": detail,
		}
	case 2:
		onProcessExitForBackfill(pid)
		st.mu.Lock()
		delete(st.started, pid)
		st.mu.Unlock()
		at := filetimeOf(e.System.TimeCreated.SystemTime)
		ent := procEntities.onExit(pid, at, propU32(e, "ExitCode"))
		if ent == nil {
			return nil // 未登记过的进程（Agent 启动前就存在且从未产生事件）不补退出
		}
		name := ent.Name
		if name == "" {
			name = base
		}
		detail := map[string]any{
			"source": "etw", "pid": pid, "name": name, "path": ent.Image,
			"exit_code": ent.ExitCode, "ppid": ent.PPID,
		}
		mergeInto(detail, procEntities.fieldsOf(ent))
		if ent.Start > 0 && at > ent.Start {
			detail["duration_sec"] = float64((at-ent.Start)/ftPerSec*10) / 10
		}
		return map[string]any{
			"etype": "process_exit_etw", "summary": "ETW进程退出: " + name, "severity": "info", "ts": ts, "detail": detail,
		}
	}
	return nil
}

func (st *etwNativeState) convertNetwork(e *etw.Event, ts string) map[string]any {
	daddr := propStr(e, "daddr")
	dport := propStr(e, "dport")
	if daddr == "" || strings.HasPrefix(daddr, "127.") || daddr == "::1" || daddr == "0.0.0.0" {
		return nil
	}
	pid := propU32(e, "PID")
	key := fmt.Sprintf("%d|%s|%s", pid, daddr, dport)
	st.mu.Lock()
	// OpenEDR 风格：同远端 10 分钟合并
	if t, ok := st.netSeen[key]; ok && time.Since(t) < 10*time.Minute {
		st.mu.Unlock()
		return nil
	}
	st.netSeen[key] = time.Now()
	st.mu.Unlock()
	p := st.proc(pid)
	remote := daddr + ":" + dport
	if strings.Contains(daddr, ":") {
		remote = "[" + daddr + "]:" + dport
	}
	sev := "info"
	if looksExternal(remote) {
		sev = "medium"
	}
	detail := map[string]any{
		"source": "etw", "pid": pid, "process_name": p.name, "remote": remote,
		"remote_ip": daddr, "remote_port": dport,
		"local": propStr(e, "saddr") + ":" + propStr(e, "sport"),
	}
	target := remote
	if dom := dnsCache.domainForIP(daddr); dom != "" {
		detail["domain"] = dom
		target = dom + " (" + remote + ")"
	}
	atNet := filetimeOf(e.System.TimeCreated.SystemTime)
	procEntities.annotate(detail, atNet)
	attachHostProcessDetails(detail, atNet)
	return map[string]any{
		"etype": "network_connect_etw", "summary": fmt.Sprintf("ETW外联: %s → %s", nameOr2(p.name, pid), target),
		"severity": sev, "ts": ts, "detail": detail,
	}
}

func (st *etwNativeState) convertFile(e *etw.Event, ts string) map[string]any {
	fp := st.dosPath(propStr(e, "FileName"))
	if fp == "" || isAgentSelfNoisePath(fp) {
		return nil
	}
	ext := ""
	if i := strings.LastIndex(fp, "."); i >= 0 {
		ext = strings.ToLower(fp[i:])
	}
	if !hotFileExt[ext] {
		return nil
	}
	pid := e.System.Execution.ProcessID
	at := filetimeOf(e.System.TimeCreated.SystemTime)
	// 记下"谁创建了这个文件"，供 FIM 变更事件归属进程（RDCW 本身不带进程信息）
	pname := st.proc(pid).name
	ent := procEntities.resolve(pid, at)
	entID := ""
	if ent != nil {
		entID = ent.ID
	}
	fileActors.note(fp, pid, pname, entID)
	if isAgentSelfNoisePath(fp) || !pathLooksHot(fp) {
		return nil
	}
	base := fp
	if i := strings.LastIndexAny(fp, `\/`); i >= 0 {
		base = fp[i+1:]
	}
	detail := map[string]any{"source": "etw", "path": fp, "name": base, "ext": ext, "pid": pid}
	if pname != "" {
		detail["process_name"] = pname
	}
	if entID != "" {
		detail["entity_id"] = entID
	}
	// 投放区可执行/脚本落地：时间线记录；后台只对脚本类晋升告警
	sev := "info"
	sum := "ETW文件创建: " + base
	if pathAtDriveRoot(fp) && hotFileExt[ext] {
		sev = "high"
		sum = "盘符根目录文件创建: " + base
	} else if pathInDropZone(fp) {
		sev = "medium"
		sum = "ETW可疑目录文件创建: " + base
		switch ext {
		case ".ps1", ".vbs", ".js", ".jse", ".hta", ".bat", ".cmd", ".scr", ".wsf":
			sev = "high"
		}
	}
	return map[string]any{
		"etype": "file_create", "summary": sum, "severity": sev, "ts": ts,
		"detail": detail,
	}
}

// pathInDropZone 比 pathLooksHot 更窄：不含 AppData 下大量正常安装的软件目录。
func pathAtDriveRoot(p string) bool {
	p = strings.ReplaceAll(p, "/", `\`)
	if len(p) < 4 || p[1] != ':' || p[2] != '\\' {
		return false
	}
	return !strings.Contains(p[3:], `\`)
}

func pathLooksInterestingDriver(p string) bool {
	l := strings.ToLower(p)
	if !strings.HasSuffix(l, ".sys") {
		return false
	}
	if strings.Contains(l, `\system32\drivers\`) || strings.Contains(l, `\windows\`) {
		return true
	}
	return pathInDropZone(l) || pathLooksHot(l)
}

func pathInDropZone(p string) bool {
	l := strings.ToLower(p)
	for _, k := range []string{`\temp\`, `\tmp\`, `\downloads\`, `\users\public\`} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

// pathLooksInterestingDLL：系统目录纳入（仅后续过滤无签名/异常）；Program Files 等厂商目录跳过。
func pathLooksInterestingDLL(p string) bool {
	l := strings.ToLower(p)
	if l == "" {
		return false
	}
	// 系统目录：关注无签名/签名异常（在 convert 里用缓存验签过滤，避免全量同步验签卡机）
	if isWindowsSystemPath(l) || strings.Contains(l, `\windows\`) {
		return true
	}
	// 厂商安装位置跳过（有签名的正常软件）
	trusted := []string{
		`\program files\`, `\program files (x86)\`,
		`\programdata\microsoft\`, `\programdata\package cache\`,
	}
	for _, k := range trusted {
		if strings.Contains(l, k) {
			return false
		}
	}
	if pathInDropZone(l) || pathLooksHot(l) {
		return true
	}
	if strings.Contains(l, `\users\`) {
		return true
	}
	return true
}

