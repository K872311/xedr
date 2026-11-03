//go:build !windows

package main

import "fmt"

func cancelUpgrade(cfg Config, params map[string]any) (map[string]any, error) {
	return nil, fmt.Errorf("cancel_upgrade only on windows")
}
