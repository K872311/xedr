//go:build !windows

package main

import "context"

type fimWatcher struct{}

func newFIMWatcher(*stateDB, string) *fimWatcher { return &fimWatcher{} }
func (w *fimWatcher) setExtra([]string)          {}
func (w *fimWatcher) start(context.Context)      {}
func (w *fimWatcher) stop()                      {}
func (w *fimWatcher) running() bool              { return false }
func (w *fimWatcher) drain() []map[string]any    { return nil }
