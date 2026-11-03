package main

import (
	"strings"
	"testing"
)

func TestSplitImagePath(t *testing.T) {
	exe, args := splitImagePath(`"C:\Users\Public\a.exe" -s`)
	if exe != `C:\Users\Public\a.exe` || args != "-s" {
		t.Fatalf("got %q %q", exe, args)
	}
	exe, args = splitImagePath(`C:\Windows\System32\svchost.exe -k netsvcs`)
	if !strings.Contains(exe, "svchost.exe") || args == "" {
		t.Fatalf("got %q %q", exe, args)
	}
}
