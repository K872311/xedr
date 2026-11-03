//go:build !windows

package main

import "fmt"

func doUpgrade(cfg Config, params map[string]any) (map[string]any, error) {
	return nil, fmt.Errorf("upgrade 仅支持 Windows")
}
