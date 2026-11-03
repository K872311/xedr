//go:build !windows

package main

import "fmt"

func currentBootID() string { return fmt.Sprintf("u%d", 0) }

func lookupProcInfo(uint32) (procInfo, bool) { return procInfo{}, false }

func livePIDSet() map[uint32]bool { return nil }
