//go:build !windows

package main

import "context"

func startSensorHealLoop(ctx context.Context, etw *etwWatcher) {}
