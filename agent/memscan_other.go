//go:build !windows

package main

import "fmt"

func scanMemory(params map[string]any) (map[string]any, error) {
	return nil, fmt.Errorf("内存扫描仅支持 Windows")
}
