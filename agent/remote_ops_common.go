package main

import "strings"

func isRemoteOpsAction(action string) bool {
	switch strings.ToLower(action) {
	case "reg_read", "fs_list", "fs_stat", "fs_read", "fs_volumes", "live_query", "run_cmd",
		"shell_open", "shell_write", "shell_poll", "shell_close":
		return true
	}
	return false
}
