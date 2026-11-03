//go:build !windows

package main

import "context"

type wmiPersistWatcher struct{}

func newWMIPersistWatcher() *wmiPersistWatcher { return &wmiPersistWatcher{} }

func (w *wmiPersistWatcher) drain() []map[string]any { return nil }

func (w *wmiPersistWatcher) start(context.Context) {}
