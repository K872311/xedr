//go:build !windows

package main

import "context"

type processWatcher struct{}

func newProcessWatcher() *processWatcher { return &processWatcher{} }
func (w *processWatcher) start(ctx context.Context) {}
func (w *processWatcher) stop()                     {}
func (w *processWatcher) drain() []map[string]any   { return nil }
