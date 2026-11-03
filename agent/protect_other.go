//go:build !windows

package main

func protectStateDir(dir string) {
	_ = dir
}
