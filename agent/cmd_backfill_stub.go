//go:build !windows

package main

import "context"

func prepareProcessCreateEvent(ev map[string]any) map[string]any { return ev }

func normalizeLiveProcessEvents(events []map[string]any) []map[string]any { return events }

func attachHostProcessDetails(detail map[string]any, at int64) {}

func startCmdBackfillLoop(ctx context.Context) {}

func onProcessExitForBackfill(pid uint32) {}
