package main

import "strings"

// computeCaptureHealthScore：采集质量评分（0-100）与处置建议。
func computeCaptureHealthScore(sensors map[string]any) map[string]any {
	score := 100
	var advises []string
	cs, _ := sensors["capture_status"].(map[string]any)
	if cs == nil {
		cs = map[string]any{}
	}
	pipe, _ := sensors["sensor_pipeline"].(map[string]any)
	tele, _ := sensors["telemetry"].(map[string]any)

	etwOK, _ := cs["etw_session_ok"].(bool)
	mode := asString(cs["etw_mode"])
	if pipe != nil {
		if p := asString(pipe["primary"]); p != "" {
			mode = p
		}
	}
	if !etwOK || mode == "etw_evt" || mode == "starting" {
		score -= 25
		advises = append(advises, "ETW 原生未就绪，正在用 Winlog 回退；建议以管理员重启 Agent")
	}
	if audit, ok := cs["audit_4688_enabled"].(bool); ok && !audit {
		score -= 15
		advises = append(advises, "未开启进程创建审计(4688)，命令行补全可能不足")
	}
	if sysmon, ok := cs["sysmon_present"].(bool); ok && !sysmon {
		score -= 5
		advises = append(advises, "未检测到 Sysmon（可选增强）")
	}
	if tele != nil {
		if pct, ok := tele["proc_cmd_fill_pct"].(float64); ok && pct < 40 {
			score -= 20
			advises = append(advises, "进程命令行填充率偏低，检查 4688/WMI/ETW")
		} else if pct, ok := tele["proc_cmd_fill_pct"].(float64); ok && pct < 70 {
			score -= 8
			advises = append(advises, "进程命令行填充率一般")
		}
	}
	if ch, ok := sensors["winevent_channels"].(int); ok && ch < 4 {
		score -= 10
		advises = append(advises, "Winlog 可用通道偏少，检查权限与日志策略")
	}
	if score < 0 {
		score = 0
	}
	level := "good"
	if score < 50 {
		level = "poor"
	} else if score < 75 {
		level = "fair"
	}
	return map[string]any{
		"score": score, "level": level, "advise": advises,
		"etw_mode": mode, "cmd_fill_hint": tele != nil,
	}
}

func healthScoreLevelColor(level string) string {
	switch strings.ToLower(level) {
	case "poor":
		return "red"
	case "fair":
		return "yellow"
	default:
		return "green"
	}
}
