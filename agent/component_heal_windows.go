//go:build windows

package main

import (
	"context"
	"time"
)

// startSensorHealLoop 周期性刷新 sensor_pipeline / 遥测快照（供心跳与 Fleet 漂移）。
func startSensorHealLoop(ctx context.Context, etw *etwWatcher) {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if etw == nil {
					continue
				}
				refreshSensorPipelineFromETW(etw.status())
			}
		}
	}()
}

func refreshSensorPipelineFromETW(mode string) {
	switch mode {
	case "etw_native":
		setSensorPipeline("etw_native", "winevent", "")
	case "etw_evt":
		setSensorPipeline("etw_evt", "winevent", "etw_evtlog_ps")
	case "starting":
		setSensorPipeline("starting", "winevent", "")
	case "stopped":
		setSensorPipeline("stopped", "winevent", "etw_stopped")
	}
}
