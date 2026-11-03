//go:build windows

package main

import (
	"encoding/xml"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type winevtXML struct {
	System struct {
		EventID     int    `xml:"EventID"`
		Channel     string `xml:"Channel"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name string `xml:"Name,attr"`
			Text string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func winevtParseXML(xmlText string, logChannel string) map[string]any {
	var doc winevtXML
	if err := xml.Unmarshal([]byte(xmlText), &doc); err != nil {
		return nil
	}
	data := map[string]string{}
	for _, d := range doc.EventData.Data {
		if d.Name != "" {
			data[d.Name] = strings.TrimSpace(d.Text)
		}
	}
	eid := doc.System.EventID
	chanName := doc.System.Channel
	if chanName == "" {
		chanName = logChannel
	}
	ts := winevtFormatTime(doc.System.TimeCreated.SystemTime)
	return winevtMapEvent(eid, ts, chanName, data)
}

func winevtFormatTime(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Now().Format("2006-01-02T15:04:05")
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.Local().Format("2006-01-02T15:04:05")
	}
	if t, err := time.Parse("2006-01-02T15:04:05.9999999Z", raw); err == nil {
		return t.Local().Format("2006-01-02T15:04:05")
	}
	return raw
}

func winevtMapEvent(eid int, ts, chanName string, data map[string]string) map[string]any {
	withChan := func(d map[string]any) map[string]any {
		d["channel"] = chanName
		return d
	}
	lowChan := strings.ToLower(chanName)
	// 按通道优先：BITS/SMB 的 EventID 与 Sysmon/其它通道重叠，不能只靠 ID。
	if strings.Contains(lowChan, "bits") {
		return winevtBITSEvent(eid, ts, chanName, data)
	}
	if strings.Contains(lowChan, "smb") {
		return winevtSMBEvent(eid, ts, chanName, data)
	}
	switch eid {
	case 4624:
		logonType := data["LogonType"]
		if logonType == "0" || logonType == "5" || logonType == "11" {
			return nil
		}
		user := data["TargetUserName"]
		if user == "ANONYMOUS LOGON" || user == "SYSTEM" || user == "LOCAL SERVICE" || user == "NETWORK SERVICE" {
			return nil
		}
		if winevtUserNoise(user) {
			return nil
		}
		ip := data["IpAddress"]
		if logonType == "3" && (ip == "127.0.0.1" || ip == "::1" || ip == "-" || ip == "") {
			return nil
		}
		return map[string]any{
			"etype": "win_logon", "summary": "登录成功: " + user + " type=" + logonType,
			"severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "user": user, "domain": data["TargetDomainName"],
				"logon_type": logonType, "ip": ip, "process": data["ProcessName"],
			}),
		}
	case 4625:
		u := data["TargetUserName"]
		if strings.HasSuffix(u, "$") || u == "SYSTEM" || u == "LOCAL SERVICE" || u == "NETWORK SERVICE" || u == "-" || u == "" {
			return nil
		}
		return map[string]any{
			"etype": "win_logon_fail", "summary": "登录失败: " + u,
			"severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "user": u, "ip": data["IpAddress"],
				"status": data["Status"], "substatus": data["SubStatus"],
			}),
		}
	case 4648:
		proc := data["ProcessName"]
		if winevtPathEnds(proc, `\svchost.exe`, `\taskhostw.exe`, `\trustedinstaller.exe`, `\lsass.exe`, `\services.exe`, `\winlogon.exe`, `\consent.exe`) {
			return nil
		}
		user := data["TargetUserName"]
		return map[string]any{
			"etype": "win_explicit_logon", "summary": "显式凭据登录: " + user,
			"severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "user": user, "process": proc, "target": data["TargetServerName"],
			}),
		}
	case 4720:
		u := data["TargetUserName"]
		return map[string]any{
			"etype": "win_account_create", "summary": "账号创建: " + u, "severity": "high", "ts": ts,
			"detail": withChan(map[string]any{"source": "security", "event_id": eid, "user": u, "by": data["SubjectUserName"]}),
		}
	case 4722:
		u := data["TargetUserName"]
		return map[string]any{
			"etype": "win_account_enable", "summary": "账号启用: " + u, "severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{"source": "security", "event_id": eid, "user": u}),
		}
	case 4724:
		u := data["TargetUserName"]
		return map[string]any{
			"etype": "win_password_reset", "summary": "密码重置: " + u, "severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{"source": "security", "event_id": eid, "user": u}),
		}
	case 4728, 4732, 4756:
		member, group := data["MemberName"], data["TargetUserName"]
		sum := "加入组: " + member + " → " + group
		if eid == 4732 {
			sum = "加入本地组: " + member + " → " + group
		}
		if eid == 4756 {
			sum = "加入通用组: " + member + " → " + group
		}
		return map[string]any{
			"etype": "win_group_add", "summary": sum, "severity": "high", "ts": ts,
			"detail": withChan(map[string]any{"source": "security", "event_id": eid, "member": member, "group": group}),
		}
	case 4697:
		sp := data["ServiceFileName"]
		if winevtWinDirPath(sp) {
			return nil
		}
		ev := map[string]any{
			"etype": "win_service_install", "summary": "服务安装: " + data["ServiceName"], "severity": "high", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "name": data["ServiceName"], "service_name": data["ServiceName"],
				"path": sp, "account": data["ServiceAccount"],
			}),
		}
		enrichServiceInstallEvent(ev)
		return ev
	case 4698:
		tn := data["TaskName"]
		if winevtTaskMicrosoft(tn) {
			return nil
		}
		ev := map[string]any{
			"etype": "win_task_create", "summary": "计划任务创建: " + tn, "severity": "high", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "task": tn, "task_name": tn,
				"content": data["TaskContent"],
			}),
		}
		enrichWinTaskEvent(ev, tn, data["TaskContent"])
		return ev
	case 4702:
		tn := data["TaskName"]
		if winevtTaskMicrosoft(tn) {
			return nil
		}
		ev := map[string]any{
			"etype": "win_task_update", "summary": "计划任务更新: " + tn, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "task": tn, "task_name": tn,
				"content": data["TaskContent"],
			}),
		}
		if strings.TrimSpace(data["TaskContent"]) != "" {
			enrichWinTaskEvent(ev, tn, data["TaskContent"])
		}
		return ev
	case 1102:
		return map[string]any{
			"etype": "win_audit_clear", "summary": "安全日志被清空", "severity": "critical", "ts": ts,
			"detail": withChan(map[string]any{"source": "security", "event_id": eid}),
		}
	case 4672:
		su := data["SubjectUserName"]
		if su == "SYSTEM" || su == "LOCAL SERVICE" || su == "NETWORK SERVICE" || strings.HasSuffix(su, "$") || winevtUserNoise(su) {
			return nil
		}
		priv := data["PrivilegeList"]
		if priv == "" || !winevtPrivInteresting(priv) {
			return nil
		}
		return map[string]any{
			"etype": "win_special_priv", "summary": "特殊权限分配: " + su, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "user": su, "domain": data["SubjectDomainName"], "privileges": priv,
			}),
		}
	case 7045:
		ip := data["ImagePath"]
		if winevtWinDirPath(ip) {
			return nil
		}
		ev := map[string]any{
			"etype": "win_service_install", "summary": "服务安装: " + data["ServiceName"], "severity": "high", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "system", "event_id": eid, "name": data["ServiceName"], "service_name": data["ServiceName"],
				"path": ip, "account": data["AccountName"], "start_type": data["StartType"],
			}),
		}
		enrichServiceInstallEvent(ev)
		return ev
	case 7036:
		return map[string]any{
			"etype": "win_service_state", "summary": "服务状态: " + data["param1"] + " → " + data["param2"],
			"severity": "info", "ts": ts,
			"detail": withChan(map[string]any{"source": "system", "event_id": eid, "name": data["param1"], "state": data["param2"]}),
		}
	case 7040:
		disp := data["param1"]
		short := data["param4"]
		if short == "" {
			short = disp
		}
		if winevtServiceNoise(short) {
			return nil
		}
		to := data["param3"]
		if !strings.Contains(strings.ToLower(to), "disabled") && !strings.Contains(to, "禁用") {
			return nil
		}
		return map[string]any{
			"etype": "win_service_config", "summary": "服务被禁用: " + disp, "severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "system", "event_id": eid, "name": disp, "service": short, "from": data["param2"], "to": to,
			}),
		}
	case 4103:
		payload := data["Payload"]
		if payload == "" {
			payload = data["MessageNumber"]
		}
		snip := winevtSnip(payload, 180)
		return map[string]any{
			"etype": "win_ps_module", "summary": "PowerShell 模块日志: " + snip, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{"source": "powershell", "event_id": eid, "payload": payload, "context": data["ContextInfo"]}),
		}
	case 4104:
		script := data["ScriptBlockText"]
		if script == "" {
			return nil
		}
		sev, sum := "info", "PowerShell 脚本块"
		if winevtSuspiciousPS(script) {
			sev, sum = "high", "可疑 PowerShell 脚本块"
		}
		det := withChan(map[string]any{
			"source": "powershell", "event_id": eid, "script_block": script,
			"script_block_id": data["ScriptBlockId"], "path": data["Path"],
			"host_application_id": data["HostApplicationId"], "host_id": data["HostId"],
		})
		winevtEnrichScriptBlock(det, ts)
		return map[string]any{
			"etype": "win_ps_scriptblock", "summary": sum + ": " + winevtSnip(script, 160),
			"severity": sev, "ts": ts,
			"detail": det,
		}
	case 8:
		src := data["SourceImage"]
		if winevtSysmonSrcNoise(src) {
			return nil
		}
		tgt := data["TargetImage"]
		if winevtBrowserPair(src, tgt) {
			return nil
		}
		return map[string]any{
			"etype": "remote_thread", "summary": "远程线程(Sysmon): " + filepath.Base(src) + " → " + filepath.Base(tgt),
			"severity": "high", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "path": src, "target_path": tgt,
				"pid": winevtInt(data["SourceProcessId"]), "target_pid": winevtInt(data["TargetProcessId"]),
				"start_address": data["StartAddress"],
			}),
		}
	case 10:
		am := data["GrantedAccess"]
		if am == "" {
			return nil
		}
		mask, ok := winevtParseHex64(am)
		if !ok {
			return nil
		}
		want := uint64(0x20 | 0x2 | 0x8)
		if (mask&want) == 0 && mask != 0x1FFFFF && mask != 0x1F0FFF {
			return nil
		}
		src := data["SourceImage"]
		if winevtSysmonAccessNoise(src) {
			return nil
		}
		tgt := data["TargetImage"]
		return map[string]any{
			"etype": "process_access", "summary": "进程打开(Sysmon): " + filepath.Base(src) + " → " + filepath.Base(tgt),
			"severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "path": src, "target_path": tgt,
				"pid": winevtInt(data["SourceProcessId"]), "target_pid": winevtInt(data["TargetProcessId"]),
				"access": am, "call_trace": data["CallTrace"],
			}),
		}
	case 13:
		to := data["TargetObject"]
		if !winevtRegASEP(to) {
			return nil
		}
		return map[string]any{
			"etype": "registry_write", "summary": "注册表写入(Sysmon): " + to, "severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "path": to, "value": data["Details"],
				"pid": winevtInt(data["ProcessId"]), "process_name": filepath.Base(data["Image"]),
			}),
		}
	case 22:
		if strings.Contains(strings.ToLower(chanName), "terminalservices") {
			user := data["User"]
			if user == "" {
				user = data["Account"]
			}
			return map[string]any{
				"etype": "win_rdp_session", "summary": "终端会话: " + user, "severity": "info", "ts": ts,
				"detail": withChan(map[string]any{"source": "terminalservices", "event_id": eid, "user": user, "ip": data["Address"]}),
			}
		}
		qname := data["QueryName"]
		if qname == "" || strings.HasSuffix(strings.ToLower(qname), ".arpa") || strings.HasSuffix(strings.ToLower(qname), ".local") {
			return nil
		}
		return map[string]any{
			"etype": "dns_query", "summary": "DNS(Sysmon): " + qname, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "query": qname, "type": data["QueryType"],
				"pid": winevtInt(data["ProcessId"]), "process_name": filepath.Base(data["Image"]),
			}),
		}
	case 4688:
		img := data["NewProcessName"]
		cmd := data["CommandLine"]
		name := filepath.Base(img)
		return map[string]any{
			"etype": "process_create_etw", "summary": "进程创建(4688): " + name, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security_4688", "event_id": eid, "pid": winevtInt(data["NewProcessId"]),
				"ppid": winevtInt(data["ProcessId"]), "name": name, "path": img, "command_line": cmd,
				"user": data["SubjectUserName"],
			}),
		}
	case 1:
		img := data["Image"]
		if winevtSysmonSrcNoise(img) {
			return nil
		}
		return map[string]any{
			"etype": "process_create_etw", "summary": "进程创建(Sysmon): " + filepath.Base(img), "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "pid": winevtInt(data["ProcessId"]),
				"ppid": winevtInt(data["ParentProcessId"]), "name": filepath.Base(img), "path": img,
				"command_line": data["CommandLine"], "user": data["User"],
				"hash": data["Hashes"],
			}),
		}
	case 3:
		return map[string]any{
			"etype": "network_connect", "summary": "网络(Sysmon): " + data["DestinationIp"] + ":" + data["DestinationPort"],
			"severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "remote_ip": data["DestinationIp"], "remote_port": data["DestinationPort"],
				"local": data["SourceIp"], "proto": data["Protocol"], "pid": winevtInt(data["ProcessId"]),
				"process_name": filepath.Base(data["Image"]),
			}),
		}
	case 11:
		target := data["TargetFilename"]
		if target == "" {
			return nil
		}
		return map[string]any{
			"etype": "file_create", "summary": "文件创建(Sysmon): " + filepath.Base(target), "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "path": target, "pid": winevtInt(data["ProcessId"]),
				"process_name": filepath.Base(data["Image"]),
			}),
		}
	case 1116, 1117:
		threat := data["Threat Name"]
		if threat == "" {
			threat = data["Threat_Name"]
		}
		sev := "high"
		if eid == 1117 {
			sev = "info"
		}
		return map[string]any{
			"etype": "defender_detection", "summary": "Defender: " + threat, "severity": sev, "ts": ts,
			"detail": withChan(map[string]any{
				"source": "defender", "event_id": eid, "threat": threat, "path": data["Path"],
				"action": data["Action"], "user": data["User"],
			}),
		}
	case 1150, 5001:
		return map[string]any{
			"etype": "defender_status", "summary": "Defender 状态变更", "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{"source": "defender", "event_id": eid, "detail": data["Product Name"]}),
		}
	case 106, 140, 141, 200, 201:
		task := data["TaskName"]
		if task == "" {
			task = data["Path"]
		}
		ev := map[string]any{
			"etype": "win_task_ops", "summary": "任务计划(Sysmon/TS): " + task, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "winevent", "event_id": eid, "task": task, "task_name": task, "channel": chanName,
			}),
		}
		enrichWinTaskOpsFromCache(ev, task)
		return ev
	case 21, 23, 24, 25:
		if !strings.Contains(strings.ToLower(chanName), "terminalservices") {
			return nil
		}
		user := data["User"]
		if user == "" {
			user = data["Account"]
		}
		return map[string]any{
			"etype": "win_rdp_session", "summary": "终端会话: " + user, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{"source": "terminalservices", "event_id": eid, "user": user, "ip": data["Address"]}),
		}
	case 2004, 2005, 2006, 2010, 2011:
		rule := data["RuleName"]
		if rule == "" {
			rule = data["Rule Id"]
		}
		return map[string]any{
			"etype": "win_firewall", "summary": "防火墙: " + rule, "severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{"source": "firewall", "event_id": eid, "rule": rule, "app": data["Application"]}),
		}
	case 8001, 8002, 8003, 8004:
		app := data["AppName"]
		if app == "" {
			app = data["FilePath"]
		}
		sev := "medium"
		if eid == 8004 {
			sev = "info"
		}
		return map[string]any{
			"etype": "win_applocker", "summary": "AppLocker: " + filepath.Base(app), "severity": sev, "ts": ts,
			"detail": withChan(map[string]any{"source": "applocker", "event_id": eid, "path": app, "user": data["User"]}),
		}
	case 3033, 3063, 3076, 3077:
		return map[string]any{
			"etype": "win_code_integrity", "summary": "代码完整性事件", "severity": "high", "ts": ts,
			"detail": withChan(map[string]any{"source": "codeintegrity", "event_id": eid, "file": data["FileName"], "detail": data["Status"]}),
		}
	}
	if ev := winevtGenericEvent(eid, ts, chanName, data); ev != nil {
		return ev
	}
	return nil
}

func winevtGenericEvent(eid int, ts, chanName string, data map[string]string) map[string]any {
	low := strings.ToLower(chanName)
	// BITS / SMB 已有专用 mapper；仅 TaskScheduler 等兜底时带上关键 EventData
	if strings.Contains(low, "bits") || strings.Contains(low, "smb") {
		return nil
	}
	if !strings.Contains(low, "taskscheduler") {
		return nil
	}
	sum := chanName + " E" + strconv.Itoa(eid)
	d := map[string]any{"source": "winevent", "event_id": eid, "channel": chanName}
	for _, k := range []string{"TaskName", "Path", "UserContext", "ResultCode"} {
		if v := data[k]; v != "" {
			d[strings.ToLower(k)] = v
		}
	}
	return map[string]any{
		"etype": "winevent_generic", "summary": sum, "severity": "info", "ts": ts, "detail": d,
	}
}

func winevtPick(data map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(data[k]); v != "" {
			return v
		}
	}
	// 大小写不敏感兜底
	lowWant := map[string]bool{}
	for _, k := range keys {
		lowWant[strings.ToLower(k)] = true
	}
	for k, v := range data {
		if lowWant[strings.ToLower(k)] && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func winevtBITSEvent(eid int, ts, chanName string, data map[string]string) map[string]any {
	job := winevtPick(data, "jobTitle", "JobTitle", "name", "Name", "TransferId", "jobId", "JobId")
	url := winevtPick(data, "url", "Url", "RemoteName", "remoteName", "RemoteUrl")
	local := winevtPick(data, "localName", "LocalName", "fileName", "FileName", "Path")
	owner := winevtPick(data, "jobOwner", "JobOwner", "User", "Owner")
	sev := "info"
	sum := "BITS: " + firstNonEmpty(job, url, local, "job")
	if url != "" || local != "" {
		sev = "medium"
		if taskSuspiciousExecute(local) || strings.Contains(strings.ToLower(url), "http") {
			sev = "high"
		}
	}
	return map[string]any{
		"etype": "win_bits", "summary": sum, "severity": sev, "ts": ts,
		"detail": map[string]any{
			"source": "bits", "event_id": eid, "channel": chanName,
			"job_name": job, "remote_url": url, "local_path": local, "owner": owner,
			"payload_path": firstNonEmpty(local, url), "matched": firstNonEmpty(url, local, job),
		},
	}
}

func winevtSMBEvent(eid int, ts, chanName string, data map[string]string) map[string]any {
	share := winevtPick(data, "ShareName", "shareName", "ObjectName", "ServerName", "serverName")
	user := winevtPick(data, "SubjectUserName", "UserName", "AccountName", "user")
	status := winevtPick(data, "Status", "status", "ErrorCode")
	path := winevtPick(data, "ObjectName", "ShareName", "Path", "FileName")
	sum := "SMB: " + firstNonEmpty(share, path, "access")
	sev := "medium"
	if eid == 31001 || eid == 31010 {
		sev = "info"
	}
	return map[string]any{
		"etype": "win_smb", "summary": sum, "severity": sev, "ts": ts,
		"detail": map[string]any{
			"source": "smbclient", "event_id": eid, "channel": chanName,
			"share": share, "path": path, "user": user, "status": status,
			"matched": firstNonEmpty(share, path),
		},
	}
}

func enrichWinTaskOpsFromCache(ev map[string]any, taskName string) {
	if ev == nil {
		return
	}
	key := taskKeyFromTaskName(taskName)
	p, ok := lookupTaskDefinition(key)
	if !ok || len(p.Actions) == 0 {
		return
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		d = map[string]any{}
		ev["detail"] = d
	}
	defPath := scheduledTaskFilePath(taskName)
	applyScheduledTaskFields(d, defPath, p, filepath.Base(defPath))
	if exe := firstTaskExecute(p); exe != "" {
		ev["summary"] = "任务计划: " + filepath.Base(exe) + " · " + strings.TrimSpace(taskName)
		if taskSuspiciousExecute(exe) {
			ev["severity"] = "high"
		}
	}
}

var (
	winevtDWM   = regexp.MustCompile(`(?i)^(DWM-|UMFD-)`)
	winevtSvcRe = regexp.MustCompile(`(?i)^(BITS|wuauserv|UsoSvc|DoSvc|TrustedInstaller|WaaSMedicSvc|wlidsvc|DiagTrack|WpnService|SystemEventsBroker|WinDefend|WdNisSvc|Sense|edgeupdate|edgeupdatem|gupdate|gupdatem|gpsvc|Schedule|WSearch|SysMain|ClickToRunSvc|MapsBroker|lfsvc|InstallService|AppXSvc|ClipSVC|StorSvc|TokenBroker|CDPSvc|CDPUserSvc.*|OneSyncSvc.*|PimIndexMaintenanceSvc.*|UnistoreSvc.*|UserDataSvc.*|WpnUserService.*)$`)
	winevtWinRe = regexp.MustCompile(`(?i)\\windows\\(system32|syswow64|winsxs)\\`)
	winevtPSRe  = regexp.MustCompile(`(?i)(-enc|frombase64string|iex\s|invoke-expression|downloadstring|system\.reflection\.assembly)`)
	winevtPriv  = regexp.MustCompile(`(?i)SeDebugPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege`)
	winevtASEP  = regexp.MustCompile(`(?i)\\(CurrentVersion\\Run|RunOnce|Winlogon|Image File Execution Options|AppInit_DLLs|Services\\[^\\]+\\(ImagePath|ServiceDll)|Windows Defender\\Exclusions|Policies\\Microsoft\\Windows Defender|Lsa\\|WDigest)`)
)

func winevtUserNoise(user string) bool {
	return winevtDWM.MatchString(user) || strings.HasSuffix(user, "$")
}

func winevtPathEnds(path string, suffixes ...string) bool {
	low := strings.ToLower(path)
	for _, s := range suffixes {
		if strings.HasSuffix(low, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func winevtWinDirPath(p string) bool { return winevtWinRe.MatchString(p) }

func winevtTaskMicrosoft(tn string) bool {
	return strings.HasPrefix(strings.ToLower(tn), `\microsoft\`)
}

func winevtPrivInteresting(priv string) bool { return winevtPriv.MatchString(priv) }

func winevtServiceNoise(short string) bool { return winevtSvcRe.MatchString(short) }

func winevtSnip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func winevtSuspiciousPS(s string) bool { return winevtPSRe.MatchString(s) }

func winevtSysmonSrcNoise(src string) bool {
	return winevtPathEnds(src, `\MsMpEng.exe`, `\NisSrv.exe`, `\csrss.exe`, `\wininit.exe`, `\services.exe`, `\lsass.exe`, `\svchost.exe`, `\smss.exe`, `\dwm.exe`, `\audiodg.exe`, `\MpDefenderCoreService.exe`, `\SecurityHealthService.exe`)
}

func winevtSysmonAccessNoise(src string) bool {
	return winevtPathEnds(src, `\MsMpEng.exe`, `\NisSrv.exe`, `\csrss.exe`, `\wininit.exe`, `\services.exe`, `\lsass.exe`, `\svchost.exe`, `\taskmgr.exe`, `\procexp.exe`, `\procexp64.exe`, `\vmtoolsd.exe`)
}

func winevtBrowserPair(src, tgt string) bool {
	browsers := []string{`\chrome.exe`, `\msedge.exe`, `\firefox.exe`, `\opera.exe`, `\brave.exe`}
	for _, b := range browsers {
		if strings.HasSuffix(strings.ToLower(src), b) && strings.HasSuffix(strings.ToLower(tgt), b) {
			return true
		}
	}
	return false
}

func winevtRegASEP(to string) bool { return winevtASEP.MatchString(to) }

func winevtParseHex64(s string) (uint64, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 64)
	return v, err == nil
}

func winevtInt(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		v, _ := strconv.ParseInt(s[2:], 16, 64)
		return int(v)
	}
	v, _ := strconv.Atoi(s)
	return v
}

// winevtEnrichScriptBlock 4104 绑定进程实体，便于 PTM/EVM 串链。
func winevtEnrichScriptBlock(det map[string]any, ts string) {
	if det == nil {
		return
	}
	at := parseLocalTS(ts)
	path := strings.TrimSpace(asString(det["path"]))
	if path != "" {
		det["process_path"] = path
		det["image"] = path
		det["process_name"] = filepath.Base(path)
	}
	// HostApplicationId 常为 PowerShell 实例 GUID；用 path + 时间窗匹配实体
	if ent := procEntities.bestRecentUserProcess(8 * time.Second); ent != nil {
		if path == "" || strings.EqualFold(ent.Image, path) || strings.Contains(strings.ToLower(path), strings.ToLower(ent.Name)) {
			det["entity_id"] = ent.ID
			det["pid"] = ent.PID
			det["ppid"] = ent.PPID
			if ent.CommandLine != "" {
				det["command_line"] = ent.CommandLine
			}
			det["correlation_id"] = "ps4104|" + ent.ID
			return
		}
	}
	if path != "" {
		procEntities.annotate(det, at)
		if eid := asString(det["entity_id"]); eid != "" {
			det["correlation_id"] = "ps4104|" + eid
		}
	}
}
