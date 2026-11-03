//go:build !windows

package main

import "runtime"

func processUsage() (cpu100ns uint64, rss uint64, handles uint32) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return 0, ms.Sys, 0
}
