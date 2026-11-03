//go:build !windows

package main

import "context"

func startSCALoop(ctx context.Context, box *outbox, aid func() string) {}
