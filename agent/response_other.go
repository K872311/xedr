//go:build !windows

package main

import "fmt"

func execCommand(cfg Config, cmd agentCommand) (map[string]any, error) {
	return nil, fmt.Errorf("当前平台暂不支持远程处置: %s", cmd.Action)
}
