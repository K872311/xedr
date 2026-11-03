//go:build windows

package main

import (
	"bufio"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

func parseShortcutFile(path string) (shortcutInfo, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	info := shortcutInfo{ShortcutPath: path, Kind: strings.TrimPrefix(ext, ".")}
	switch ext {
	case ".url":
		ok := parseURLFile(path, &info)
		return info, ok
	case ".lnk":
		ok := parseLNKFile(path, &info)
		if !ok {
			ok = parseLNKViaPowerShell(path, &info)
		}
		return info, ok && (info.TargetPath != "" || info.URL != "")
	default:
		return info, false
	}
}

func parseURLFile(path string, out *shortcutInfo) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			k := strings.ToLower(strings.TrimSpace(line[:i]))
			v := strings.TrimSpace(line[i+1:])
			switch k {
			case "url":
				out.URL = v
			case "workingdirectory", "workingdir":
				out.WorkingDir = v
			case "iconfile":
				if out.TargetPath == "" && strings.HasSuffix(strings.ToLower(v), ".exe") {
					out.TargetPath = v
				}
			}
		}
	}
	return out.URL != ""
}

// parseLNKFile：解析 Shell Link 二进制（常见本机路径 + 参数 + 工作目录）。
func parseLNKFile(path string, out *shortcutInfo) bool {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 0x4c {
		return false
	}
	if binary.LittleEndian.Uint32(b[0:4]) != 0x4c {
		return false
	}
	flags := binary.LittleEndian.Uint32(b[0x14:0x18])
	off := 0x4c
	// LinkTargetIDList
	if flags&0x01 != 0 {
		if off+2 > len(b) {
			return false
		}
		idLen := int(binary.LittleEndian.Uint16(b[off : off+2]))
		off += 2 + idLen
	}
	if flags&0x02 != 0 {
		if off+4 > len(b) {
			return false
		}
		liSize := int(binary.LittleEndian.Uint32(b[off : off+4]))
		if liSize < 0x1c || off+liSize > len(b) {
			return false
		}
		li := b[off : off+liSize]
		// LocalBasePathOffset at 0x10 within LinkInfo (when volumeID+localBasePath)
		flagsLI := binary.LittleEndian.Uint32(li[8:12])
		if flagsLI&0x01 != 0 { // VolumeIDAndLocalBasePath
			lbpOff := int(binary.LittleEndian.Uint32(li[16:20]))
			if lbpOff > 0 && lbpOff < len(li) {
				out.TargetPath = readCString(li[lbpOff:])
			}
			// Optional Unicode local base path
			if len(li) >= 0x24 {
				uniOff := int(binary.LittleEndian.Uint32(li[0x1c:0x20]))
				if uniOff > 0 && uniOff+2 < len(li) {
					if u := readUTF16Z(li[uniOff:]); u != "" {
						out.TargetPath = u
					}
				}
			}
		}
		off += liSize
	}
	isUnicode := flags&0x80 != 0
	readStr := func() string {
		if off+2 > len(b) {
			return ""
		}
		n := int(binary.LittleEndian.Uint16(b[off : off+2]))
		off += 2
		if n <= 0 {
			return ""
		}
		if isUnicode {
			need := n * 2
			if off+need > len(b) {
				return ""
			}
			u := utf16.Decode(bytesToUint16(b[off : off+need]))
			off += need
			return strings.TrimRight(string(u), "\x00")
		}
		if off+n > len(b) {
			return ""
		}
		s := string(b[off : off+n])
		off += n
		return strings.TrimRight(s, "\x00")
	}
	if flags&0x04 != 0 { // NAME
		_ = readStr()
	}
	if flags&0x08 != 0 { // RELATIVE_PATH
		rel := readStr()
		if out.TargetPath == "" {
			out.TargetPath = rel
		}
	}
	if flags&0x10 != 0 { // WORKING_DIR
		out.WorkingDir = readStr()
	}
	if flags&0x20 != 0 { // ARGUMENTS
		out.Arguments = readStr()
	}
	return out.TargetPath != "" || out.Arguments != "" || out.WorkingDir != ""
}

func parseLNKViaPowerShell(path string, out *shortcutInfo) bool {
	ps := `$ErrorActionPreference='Stop'; $s=(New-Object -ComObject WScript.Shell).CreateShortcut(` +
		`'` + strings.ReplaceAll(path, `'`, `''`) + `');` +
		`Write-Output ('T='+$s.TargetPath); Write-Output ('A='+$s.Arguments); Write-Output ('W='+$s.WorkingDirectory)`
	raw, err := runCmd(8*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "T="):
			out.TargetPath = strings.TrimSpace(line[2:])
		case strings.HasPrefix(line, "A="):
			out.Arguments = strings.TrimSpace(line[2:])
		case strings.HasPrefix(line, "W="):
			out.WorkingDir = strings.TrimSpace(line[2:])
		}
	}
	return out.TargetPath != ""
}

func readCString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func readUTF16Z(b []byte) string {
	u16 := bytesToUint16(b)
	for i, v := range u16 {
		if v == 0 {
			u16 = u16[:i]
			break
		}
	}
	return string(utf16.Decode(u16))
}

func bytesToUint16(b []byte) []uint16 {
	n := len(b) / 2
	out := make([]uint16, n)
	for i := 0; i < n; i++ {
		out[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return out
}
