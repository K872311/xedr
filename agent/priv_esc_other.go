//go:build !windows

package main

func maybePrivEscTimelineEvent(ppid int, pid int, parentName, childName, ts string) map[string]any {
	return nil
}
