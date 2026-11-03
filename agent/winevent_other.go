//go:build !windows

package main

import "context"

type winEventWatcher struct{}

func newWinEventWatcher() *winEventWatcher             { return &winEventWatcher{} }
func (w *winEventWatcher) start(ctx context.Context)   {}
func (w *winEventWatcher) stop()                       {}
func (w *winEventWatcher) drain() []map[string]any     { return nil }
