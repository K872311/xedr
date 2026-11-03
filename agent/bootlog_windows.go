//go:build windows

package main

import (
	"log"
	"os"
	"path/filepath"
	"time"
)

// flushWriter 保证 windowsgui + os.Exit 前日志落盘（defer 不会执行）。
type flushWriter struct{ f *os.File }

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	if err == nil {
		_ = w.f.Sync()
	}
	return n, err
}

func openBootLog() *os.File {
	p := filepath.Join(exeDir(), "agent-boot.log")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil
	}
	return f
}

func noteAgentError(msg string) {
	line := time.Now().Format("2006/01/02 15:04:05.000000") + " " + msg + "\n"
	p := filepath.Join(exeDir(), "agent-last-error.txt")
	_ = os.WriteFile(p, []byte(line), 0600)
	if f := openBootLog(); f != nil {
		_, _ = f.WriteString(line)
		_ = f.Sync()
		_ = f.Close()
	}
}

func setupBootLogger() func() {
	f := openBootLog()
	if f == nil {
		return func() {}
	}
	log.SetOutput(flushWriter{f: f})
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	return func() { _ = f.Close() }
}
