//go:build !windows

package main

import (
	"context"
	"time"
)

type etwWatcher struct{}

func newETWWatcher() *etwWatcher               { return &etwWatcher{} }
func (w *etwWatcher) start(ctx context.Context) {}
func (w *etwWatcher) stop()                     {}
func (w *etwWatcher) drain() []map[string]any   { return nil }
func (w *etwWatcher) waitMode(d time.Duration) string {
	_ = d
	return "stopped"
}
func (w *etwWatcher) status() string { return "unsupported" }
