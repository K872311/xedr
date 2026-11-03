//go:build !windows

package main

func armUpgradeWatchdog(cfg Config, self, bak, version string) {}
func markUpgradeHealthy(cfg Config)                          {}
func checkUpgradeWatchdog(cfg Config)                        {}
