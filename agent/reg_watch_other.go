//go:build !windows

package main

import "context"

type regWatcher struct{}

func newRegWatcher(*stateDB) *regWatcher         { return &regWatcher{} }
func (w *regWatcher) start(context.Context) bool { return false }
func (w *regWatcher) stop()                      {}
func (w *regWatcher) running() bool              { return false }
func (w *regWatcher) drain() []map[string]any    { return nil }
