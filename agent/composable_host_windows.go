//go:build windows

package main

import (
	"os/exec"
	"strings"
)

func hostMetadata() map[string]any {
	m := map[string]any{
		"os_family":              "windows",
		"hostname":               hostname(),
		"is_domain_controller":   probeDomainController(),
		"is_domain_joined":       probeDomainJoined(),
	}
	return m
}

func probeDomainJoined() bool {
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-CimInstance Win32_ComputerSystem).PartOfDomain`).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "True"
}

func probeDomainController() bool {
	ps := `$r=Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue; if($r -and $r.ProductType -eq 2){'yes'}else{'no'}`
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "yes"
}
