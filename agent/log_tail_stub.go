//go:build !windows

package main

import "context"

type logTailWatcher struct{}

func newLogTailWatcher() *logTailWatcher { return &logTailWatcher{} }

func (w *logTailWatcher) setPaths([]string) {}
func (w *logTailWatcher) drain() []map[string]any { return nil }
func (w *logTailWatcher) start(context.Context) {}

func applyLogTailPolicy(map[string]any) {}

var logTailGlobal *logTailWatcher
