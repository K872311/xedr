//go:build !windows

package main

import "context"

func startRootcheckLoop(ctx context.Context, box *outbox, aid func() string) {}
