//go:build !windows

package main

var globalRegWatcher *regWatcher

func applyRegistryFIMSync(regw *regWatcher) {}
