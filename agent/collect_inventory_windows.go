//go:build windows

package main

import (
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// collectSoftware：卸载表 + 少量 AppX（Wazuh syscollector 思路，轻量版）。
func collectSoftware() ([]any, error) {
	var out []any
	seen := map[string]bool{}
	addUninstall := func(root registry.Key, path, arch string) {
		k, err := registry.OpenKey(root, path, registry.READ)
		if err != nil {
			return
		}
		defer k.Close()
		names, err := k.ReadSubKeyNames(0)
		if err != nil {
			return
		}
		for _, n := range names {
			sk, err := registry.OpenKey(k, n, registry.READ)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			ver, _, _ := sk.GetStringValue("DisplayVersion")
			pub, _, _ := sk.GetStringValue("Publisher")
			loc, _, _ := sk.GetStringValue("InstallLocation")
			src, _, _ := sk.GetStringValue("InstallSource")
			uninstall, _, _ := sk.GetStringValue("UninstallString")
			sk.Close()
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			key := strings.ToLower(name + "|" + ver + "|" + arch)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, map[string]any{
				"name":         name,
				"version":      ver,
				"publisher":    pub,
				"arch":         arch,
				"install_path": loc,
				"source":       src,
				"uninstall":    uninstall,
				"inventory":    "software",
			})
			if len(out) >= maxItems {
				return
			}
		}
	}
	addUninstall(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "64")
	addUninstall(registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "32")
	return truncateItems(out), nil
}

// collectHotfix：CBS Packages 中的 KB（多源去重的轻量实现）。
func collectHotfix() ([]any, error) {
	ps := `
$seen = @{}
$out = @()
try {
  Get-HotFix | ForEach-Object {
    $id = [string]$_.HotFixID
    if(-not $id -or $seen.ContainsKey($id)){ return }
    $seen[$id] = $true
    $out += [PSCustomObject]@{
      kb = $id
      description = [string]$_.Description
      installed_on = if($_.InstalledOn){ $_.InstalledOn.ToString('s') } else { '' }
      installed_by = [string]$_.InstalledBy
      source = 'Get-HotFix'
    }
  }
} catch {}
try {
  $k = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages' -ErrorAction SilentlyContinue
  if($k){
    Get-ChildItem $k.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
      $n = $_.PSChildName
      if($n -match 'KB(\d{6,})'){
        $id = 'KB' + $Matches[1]
        if($seen.ContainsKey($id)){ return }
        $seen[$id] = $true
        $out += [PSCustomObject]@{
          kb = $id
          description = 'CBS Package'
          installed_on = ''
          installed_by = ''
          source = 'CBS'
        }
      }
    }
  }
} catch {}
$out | Sort-Object kb
`
	rows := decodeJSONRows(runPS(ps))
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		kb := asString(r["kb"])
		if kb == "" {
			continue
		}
		out = append(out, map[string]any{
			"kb":           kb,
			"description":  asString(r["description"]),
			"installed_on": asString(r["installed_on"]),
			"installed_by": asString(r["installed_by"]),
			"source":       asString(r["source"]),
			"inventory":    "hotfix",
		})
	}
	return truncateItems(out), nil
}

// collectListen：仅监听端口（与 network 连接表分离，对标 Wazuh ports）。
func collectListen() ([]any, error) {
	items, err := collectNetwork()
	if err != nil {
		return nil, err
	}
	var out []any
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		state := strings.ToUpper(asString(m["state"]))
		proto := strings.ToUpper(asString(m["proto"]))
		remote := asString(m["remote"])
		isListen := state == "LISTENING" || state == "LISTEN"
		if !isListen && strings.HasPrefix(proto, "UDP") {
			// UDP 无 LISTEN 态：远端为 *:* / 0.0.0.0:* 视为监听
			if remote == "*.*" || remote == "*:*" || strings.HasSuffix(remote, ":*") || remote == "0.0.0.0:0" || remote == "[::]:0" {
				isListen = true
			}
		}
		if !isListen {
			continue
		}
		out = append(out, map[string]any{
			"proto":        proto,
			"local":        asString(m["local"]),
			"state":        state,
			"pid":          asInt(m["pid"]),
			"process_name": asString(m["process_name"]),
			"inventory":    "listen",
			"collected_at": time.Now().Format("2006-01-02T15:04:05"),
		})
	}
	return truncateItems(out), nil
}
