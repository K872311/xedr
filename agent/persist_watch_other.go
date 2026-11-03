//go:build !windows

package main

import "context"

type persistWatcher struct{}

func newPersistWatcher() *persistWatcher                { return &persistWatcher{} }
func (w *persistWatcher) drain() []map[string]any       { return nil }
func (w *persistWatcher) startLoop(ctx context.Context) {}
func (w *persistWatcher) setRegistryRealtime(bool)      {}
