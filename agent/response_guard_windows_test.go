//go:build windows

package main

import (
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func selfCreateTime(t *testing.T) time.Time {
	t.Helper()
	var cr, ex, kr, us windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &cr, &ex, &kr, &us); err != nil {
		t.Fatal(err)
	}
	return time.Unix(0, cr.Nanoseconds())
}

func TestVerifyProcessIdentity(t *testing.T) {
	pid := os.Getpid()
	ct := selfCreateTime(t)
	good := fmt.Sprintf("%d_%s", pid, ct.Local().Format("2006-01-02T15:04:05"))
	if err := verifyProcessIdentity(pid, good); err != nil {
		t.Fatalf("本地时间 guid 应通过: %v", err)
	}
	goodUTC := fmt.Sprintf("%d_%s", pid, ct.UTC().Format("2006-01-02T15:04:05"))
	if err := verifyProcessIdentity(pid, goodUTC); err != nil {
		t.Fatalf("UTC guid 应通过: %v", err)
	}
	reused := fmt.Sprintf("%d_%s", pid, ct.Add(-48*time.Hour).Local().Format("2006-01-02T15:04:05"))
	if err := verifyProcessIdentity(pid, reused); err == nil {
		t.Fatal("创建时间不符（PID 复用）必须拒绝")
	}
	if err := verifyProcessIdentity(pid, fmt.Sprintf("%d_%s", pid+1, ct.Format("2006-01-02T15:04:05"))); err == nil {
		t.Fatal("guid 中的 pid 与参数不一致必须拒绝")
	}
	if err := verifyProcessIdentity(pid, fmt.Sprintf("%d", pid)); err != nil {
		t.Fatalf("无创建时间无法校验，应沿用旧行为放行: %v", err)
	}
}

func TestFileIdentityStableAcrossRename(t *testing.T) {
	dir := t.TempDir()
	a := dir + `\a.txt`
	_ = os.WriteFile(a, []byte("x"), 0600)
	id1 := fileIdentity(a)
	if id1 == "" {
		t.Skip("文件系统不支持文件 ID")
	}
	b := dir + `\b.txt`
	_ = os.Rename(a, b)
	if id2 := fileIdentity(b); id2 != id1 {
		t.Fatalf("rename 后文件 ID 应不变: %s vs %s", id1, id2)
	}
	_ = os.Remove(b)
	_ = os.WriteFile(a, []byte("x"), 0600)
	if id3 := fileIdentity(a); id3 == id1 {
		t.Log("同路径新文件复用了相同 ID（NTFS 可能复用），哈希校验兜底")
	}
}
