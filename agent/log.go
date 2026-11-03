package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

var logOnce sync.Once

func ensureDir(dir string) error {
	return os.MkdirAll(dir, 0700)
}

func setupFileLog(stateDir string) {
	logOnce.Do(func() {
		_ = os.MkdirAll(stateDir, 0700)
		path := filepath.Join(stateDir, "agent.log")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return
		}
		log.SetOutput(io.MultiWriter(os.Stdout, f))
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	})
}
