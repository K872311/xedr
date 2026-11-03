package main

import (
	"os"
	"sync/atomic"
)

// selfProtectOn 为 true 时：服务忽略普通 Stop；状态目录收紧；拒杀自身。
var selfProtectOn atomic.Bool

var protectStatePath atomic.Value // string

func setSelfProtect(on bool) {
	selfProtectOn.Store(on)
	if on {
		if p, ok := protectStatePath.Load().(string); ok && p != "" {
			protectStateDir(p)
		}
	}
}

func setProtectStateDir(dir string) {
	if dir == "" {
		return
	}
	protectStatePath.Store(dir)
	if selfProtectOn.Load() {
		protectStateDir(dir)
	}
}

func isSelfProtect() bool {
	return selfProtectOn.Load()
}

func refuseKillSelf(pid int) bool {
	if pid == os.Getpid() {
		return true
	}
	return false
}
