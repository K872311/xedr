# Agent 内存扫描（YARA）

## 模式（策略 `memory_scan.mode`）

| 模式 | 说明 |
|------|------|
| `off` | 关闭 |
| `heuristic` | MZ / RWX / 少量硬编码串 |
| `yara_on_demand` | 仅平台下发 `scan_memory` 时扫描 |
| `yara_triggered` | 远程线程 / LSASS 访问 / 映像加载 / 提权事件后扫目标 PID |
| `yara_scheduled` | 按 `schedule_interval_sec` 轮询（默认 1800s） |

- **主 YARA 库**：仓库根目录 `yara/valhalla-rules.yar`（Valhalla，约千条 PE 规则）
- **Agent 轻量包**：`rules/memory-yara/`（`rules.json` 字符串 + 少量 `.yar`）
- 拉取：`POST /api/agent/memory-yara`（包内可含 `valhalla-rules.yar`，需 go-yara + libyara 才真正编译扫描）

## 编译

```powershell
cd agent
.\build-agent.ps1                    # 默认：字符串规则 + 启发式
.\build-agent.ps1 -Yara              # 内置 go-yara（需 libyara）
```

### Windows 启用 go-yara

1. 安装 [vcpkg](https://github.com/microsoft/vcpkg) 后：`vcpkg install yara:x64-windows`
2. 设置 `PKG_CONFIG_PATH` 或把 `yara.dll` 与 Agent 同目录
3. `set CGO_ENABLED=1` 后执行 `.\build-agent.ps1 -Yara`

未链 libyara 时，`-tags yara` 不可用；默认构建仍可用 `rules.json` 字符串匹配。
