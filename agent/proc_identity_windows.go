//go:build windows

package main

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// enrichProcessIdentity 补 process_guid / parent_guid / elevated / integrity。
func enrichProcessIdentity(items []any) {
	byPID := map[int]map[string]any{}
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		pid := asInt(m["pid"])
		if pid <= 0 {
			continue
		}
		ct := asString(m["create_time"])
		if asString(m["process_guid"]) == "" {
			m["process_guid"] = processGUID(pid, ct)
		}
		byPID[pid] = m
	}
	for _, m := range byPID {
		ppid := asInt(m["ppid"])
		if ppid > 0 {
			if parent, ok := byPID[ppid]; ok {
				m["parent_guid"] = asProcessGUID(parent)
				if asString(m["parent_name"]) == "" {
					m["parent_name"] = asString(parent["name"])
				}
			} else if asString(m["parent_guid"]) == "" {
				m["parent_guid"] = processGUID(ppid, "")
			}
		}
		pid := asInt(m["pid"])
		elev, integ := queryTokenMeta(uint32(pid))
		if elev != "" {
			m["elevated"] = elev
		}
		if integ != "" {
			m["integrity"] = integ
		}
	}
}

func queryTokenMeta(pid uint32) (elevated string, integrity string) {
	if pid == 0 {
		return "", ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", ""
	}
	defer windows.CloseHandle(h)
	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return "", ""
	}
	defer token.Close()

	var elev struct{ TokenIsElevated uint32 }
	var retLen uint32
	if err := windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elev)), uint32(unsafe.Sizeof(elev)), &retLen); err == nil {
		if elev.TokenIsElevated != 0 {
			elevated = "true"
		} else {
			elevated = "false"
		}
	}

	buf := make([]byte, 256)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buf[0], uint32(len(buf)), &retLen); err == nil && retLen >= 8 {
		tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
		if tml.Label.Sid != nil {
			integrity = integrityLabel(tml.Label.Sid.String())
		}
	}
	return elevated, integrity
}

func integrityLabel(sid string) string {
	switch {
	case strings.HasSuffix(sid, "-16384"):
		return "System"
	case strings.HasSuffix(sid, "-12288"):
		return "High"
	case strings.HasSuffix(sid, "-8192"):
		return "Medium"
	case strings.HasSuffix(sid, "-4096"):
		return "Low"
	case strings.HasSuffix(sid, "-0"):
		return "Untrusted"
	default:
		return sid
	}
}
