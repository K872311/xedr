package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

// 以下三项由 scripts/build_agent.py 通过 -ldflags -X 注入；本地 go build 时为默认值。
var (
	buildID   = "dev"
	buildTime = ""
	sourceRev = ""
)

// 本 Agent 支持的协议范围。服务端按双方交集协商，旧服务端只认 v1。
const (
	protocolMin = 1
	protocolMax = 2
)

// agentCapabilities 只列出已真正实现的能力，供服务端按能力启用新功能。
func agentCapabilities() []string {
	return []string{
		"snapshot.v1",
		"timeline.v1",
		"command.ack.v1",
		"process.identity.v1",
		"sensor.etw",
		"sensor.wevt",
		"upgrade.replace",
		"upgrade.ed25519",   // 升级包 Ed25519 签名校验
		"upgrade.watchdog",  // 升级后健康看门狗，失败自动回滚 N-1
		"ingest.v2",         // 本地 SQLite outbox + v2 幂等批量上报
		"auth.agent_secret", // 每 Agent 独立凭据（DPAPI 保护）
		"command.lease",     // 命令租约重投 + 本地回执去重
		"health.v1",         // 心跳健康指标
		"process.entity.v1", // boot_id+pid+创建时间 进程实体与墓碑
		"registry.realtime", // RegNotifyChangeKeyValue 实时注册表
		"dns.aggregate",     // DNS 查询聚合 / 应答反查 / NXDOMAIN 爆发
		"fim.v1",            // 目录实时变更 + 本地基线对账
		"inventory.delta",   // 增量资产清单（generation 链 + 全量兜底）
		"policy.lkg",        // 策略整体校验/试用期/LKG 回滚，心跳回报 policy 状态
		"fleet.checkin.v1",  // PolicyApplied + local/server rev + 心跳内联 command ack
		"diagnostics.v2",    // Elastic 风格诊断包（state/components/redact）
		"composable.host.v1",
		// 内核驱动：不嵌入第三方开源驱动（OpenEDR CASL / Wazuh GPL）；可选自研需微软签名
	}
}

func buildInfoMap() map[string]any {
	return map[string]any{
		"version":      agentVersion,
		"build_id":     buildID,
		"build_time":   buildTime,
		"source_rev":   sourceRev,
		"protocol_min": protocolMin,
		"protocol_max": protocolMax,
		"capabilities": agentCapabilities(),
		"go_version":   runtime.Version(),
		"goos":         runtime.GOOS,
		"goarch":       runtime.GOARCH,
	}
}

// printBuildInfo 将构建信息写到文件（windowsgui 无控制台，故支持落盘）；path 为空则输出到 stdout。
func printBuildInfo(path string) error {
	b, err := json.MarshalIndent(buildInfoMap(), "", "  ")
	if err != nil {
		return err
	}
	if path == "" {
		fmt.Println(string(b))
		return nil
	}
	return os.WriteFile(path, b, 0644)
}

// registerExtras 注册/心跳附带的构建与协议信息。
func registerExtras() map[string]any {
	return map[string]any{
		"build_id":     buildID,
		"build_time":   buildTime,
		"source_rev":   sourceRev,
		"protocol_min": protocolMin,
		"protocol_max": protocolMax,
		"capabilities": agentCapabilities(),
		"host":         hostMetadata(),
	}
}
