//go:build !windows

package main

func hostMetadata() map[string]any {
	return map[string]any{
		"os_family": osFamily(),
		"hostname":  hostname(),
	}
}
