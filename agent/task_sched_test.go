package main

import "testing"

func TestTaskSuspiciousExecute(t *testing.T) {
	if !taskSuspiciousExecute(`C:\Users\Public\x.exe`) {
		t.Fatal("expected suspicious")
	}
	if taskSuspiciousExecute(`C:\Windows\System32\cmd.exe`) {
		t.Fatal("expected benign")
	}
}
