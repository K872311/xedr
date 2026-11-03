//go:build !windows

package main

import "fmt"

func liveQueryManifest() []map[string]any { return nil }

func liveQueryExec(params map[string]any) (map[string]any, error) {
	return nil, fmt.Errorf("live_query only on windows")
}
