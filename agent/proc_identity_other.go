//go:build !windows

package main

func enrichProcessIdentity(items []any) {
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		pid := asInt(m["pid"])
		if pid <= 0 {
			continue
		}
		if asString(m["process_guid"]) == "" {
			m["process_guid"] = processGUID(pid, asString(m["create_time"]))
		}
	}
}

func queryTokenMeta(pid uint32) (elevated string, integrity string) {
	return "", ""
}
