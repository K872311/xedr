//go:build !windows

package main

import (
	"fmt"
	"os"
)

func isWindowsService() bool { return false }

func runAsService(cfg Config, cfgPath string) error {
	return fmt.Errorf("仅 Windows 支持服务模式")
}

func installService(cfgPath string) error {
	return fmt.Errorf("仅 Windows 支持 install")
}

func uninstallService() error {
	return fmt.Errorf("仅 Windows 支持 uninstall")
}

func startServiceCmd() error {
	return fmt.Errorf("仅 Windows 支持 start")
}

func stopServiceCmd() error {
	return fmt.Errorf("仅 Windows 支持 stop")
}

func serviceStatus() error {
	fmt.Fprintln(os.Stderr, "非 Windows 平台无服务状态")
	return nil
}
