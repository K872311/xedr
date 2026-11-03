//go:build !windows

package main

func parseShortcutFile(path string) (shortcutInfo, bool) { return shortcutInfo{ShortcutPath: path}, false }
