//go:build windows

package main

import (
	"log"
	"os"
	"os/exec"
)

// protectStateDir：用 icacls 收紧目录，去掉 Users 写权限（失败则忽略）。
func protectStateDir(dir string) {
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	// 继承关闭 + 仅 SYSTEM/Administrators 完全控制
	cmds := [][]string{
		{"icacls", dir, "/inheritance:r"},
		{"icacls", dir, "/grant:r", "SYSTEM:(OI)(CI)F", "Administrators:(OI)(CI)F"},
	}
	for _, a := range cmds {
		cmd := exec.Command(a[0], a[1:]...)
		hideWindow(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("自保护 ACL: %v %s", err, string(out))
		}
	}
}
