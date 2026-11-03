//go:build !windows

package main

import "context"

type deviceWatcher struct{}

func newDeviceWatcher() *deviceWatcher { return &deviceWatcher{} }

func (w *deviceWatcher) start(context.Context) {}

func (w *deviceWatcher) stop() {}

func (w *deviceWatcher) drain() []map[string]any { return nil }
