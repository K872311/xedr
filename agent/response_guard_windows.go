//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// verifyProcessIdentity 校验 pid 现在仍是 guid（pid_创建时间）所指的那个进程，
// 防止“管理员看到的是 A，下发时 PID 已被复用为 B”而误杀。
func verifyProcessIdentity(pid int, guid string) error {
	guid = strings.TrimSpace(guid)
	i := strings.Index(guid, "_")
	if i <= 0 || i == len(guid)-1 {
		return nil // guid 不含创建时间，无法校验（沿用旧行为）
	}
	if g := strings.TrimSpace(guid[:i]); g != fmt.Sprint(pid) {
		return fmt.Errorf("process_guid 与 pid 不一致: guid=%s pid=%d", guid, pid)
	}
	want := parseCreateTime(guid[i+1:])
	if want.IsZero() {
		return nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("进程 %d 已不存在或无法打开: %v", pid, err)
	}
	defer windows.CloseHandle(h)
	var cr, ex, kr, us windows.Filetime
	if err := windows.GetProcessTimes(h, &cr, &ex, &kr, &us); err != nil {
		return fmt.Errorf("读取进程创建时间失败: %v", err)
	}
	got := time.Unix(0, cr.Nanoseconds())
	if d := got.Sub(want); d < -3*time.Second || d > 3*time.Second {
		// 采集端可能用 UTC 也可能用本地时间，换一种解释再比一次
		alt := reinterpretLocalAsUTC(want)
		if d2 := got.Sub(alt); d2 < -3*time.Second || d2 > 3*time.Second {
			return fmt.Errorf("PID %d 已被复用：期望创建于 %s，实际 %s", pid,
				want.Format("2006-01-02T15:04:05"), got.Local().Format("2006-01-02T15:04:05"))
		}
	}
	return nil
}

func reinterpretLocalAsUTC(t time.Time) time.Time {
	y, m, d := t.Date()
	hh, mm, ss := t.Clock()
	return time.Date(y, m, d, hh, mm, ss, 0, time.UTC)
}

// parseCreateTime 兼容 ISO 's' 格式（无时区，按本地解释）与 RFC3339。
func parseCreateTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if t, err := time.ParseInLocation("2006-01-02T15:04:05", s, time.Local); err == nil {
		return t
	}
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// fileIdentity 返回 卷序列号:文件索引，rename/硬链接后仍稳定，可识别“同路径换了个文件”。
func fileIdentity(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return ""
	}
	return fmt.Sprintf("%08x:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow)
}
