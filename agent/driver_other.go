//go:build !windows

package main

import (
	"context"
	"fmt"
)

type kernelWatcher struct{}

func newKernelWatcher() *kernelWatcher                  { return &kernelWatcher{} }
func (w *kernelWatcher) start(ctx context.Context) bool { return false }
func (w *kernelWatcher) stop()                          {}
func (w *kernelWatcher) active() bool                   { return false }
func (w *kernelWatcher) drain() []map[string]any        { return nil }
func (w *kernelWatcher) protectSelf(pid uint32) error   { return fmt.Errorf("unsupported") }
