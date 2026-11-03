//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"strings"
	"time"
)

var globalRegWatcher *regWatcher

func parseRegSpecFromDisplay(path string) (regSpec, bool) {
	p := strings.TrimSpace(strings.ReplaceAll(path, "/", `\`))
	up := strings.ToUpper(p)
	var hive, rest string
	switch {
	case strings.HasPrefix(up, `HKLM\`):
		hive, rest = "HKLM", p[5:]
	case strings.HasPrefix(up, `HKEY_LOCAL_MACHINE\`):
		hive, rest = "HKLM", p[18:]
	case strings.HasPrefix(up, `HKU\`):
		parts := strings.SplitN(p[4:], `\`, 2)
		if len(parts) < 2 {
			return regSpec{}, false
		}
		return regSpec{
			ID:       "extra_hku_" + shortID(parts[0]+parts[1]),
			Hive:     "HKU",
			SID:      parts[0],
			Path:     parts[1],
			Subtree:  true,
			Depth:    1,
			Category: "defense_evasion",
			Label:    "FIM扩展",
			Severity: "high",
		}, true
	default:
		return regSpec{}, false
	}
	rest = strings.TrimLeft(rest, `\`)
	if rest == "" {
		return regSpec{}, false
	}
	subtree := strings.Count(rest, `\`) >= 1
	depth := 0
	if subtree {
		depth = 1
	}
	return regSpec{
		ID:          "extra_" + shortID(hive+rest),
		Hive:        hive,
		Path:        rest,
		Subtree:     subtree,
		Depth:       depth,
		Category:    "defense_evasion",
		Label:       "FIM扩展",
		Severity:    "high",
		MinInterval: 2 * time.Second,
	}, true
}

func shortID(s string) string {
	h := sha256.Sum256([]byte(strings.ToLower(s)))
	return hex.EncodeToString(h[:])[:12]
}

func (w *regWatcher) SyncExtraPaths(paths []string) {
	if w == nil || !w.running() {
		return
	}
	added := 0
	for _, p := range paths {
		spec, ok := parseRegSpecFromDisplay(p)
		if !ok {
			continue
		}
		w.mu.Lock()
		dup := false
		for _, rw := range w.watches {
			if rw.spec.ID == spec.ID {
				dup = true
				break
			}
		}
		w.mu.Unlock()
		if dup {
			continue
		}
		w.addSpec(spec, false)
		added++
	}
	if added > 0 {
		log.Printf("regwatch: 动态追加 FIM 扩展键 %d 个", added)
	}
}

func applyRegistryFIMSync(regw *regWatcher) {
	if regw == nil {
		return
	}
	ex := registryFIMExtras()
	if len(ex) == 0 {
		return
	}
	regw.SyncExtraPaths(ex)
}
