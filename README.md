# EDR（独立工程）

终端检测与响应（EDR）+ Agentic SOC 管理台。

| 目录/文件 | 说明 |
|-----------|------|
| `agent/` | ForensicAgent 终端源码（Go） |
| `agent_admin/` | EDR 管理台前端（Vue） |
| `backend/` | EDR 服务端 API / 协议 / 遥测 / 情报匹配 |
| `rules/` | 检测规则 |
| `config/` | 配置（提交 `*.example.json`，本机复制后改名） |
| `skills/` / `logrules/` / `yara/` / `sigma_high_priority/` | 配套规则与技能资产 |
| `edr_server.py` | EDR 入口（默认 `:8100`） |

## 首次配置

```powershell
cd config
copy ai_config.example.json ai_config.json
copy db_config.example.json db_config.json
copy platform_settings.example.json platform_settings.json
copy stack_paths.example.json stack_paths.json
copy hj_stack.example.json hj_stack.json
# 按本机环境编辑上述 json（密钥、数据库、Agent 服务地址等）
```

运行数据（用户、告警、名单、IOC 库、密钥）位于 `reports/`、`lists/`、`ioc/`、`data/`，已由 `.gitignore` 排除，不会进入仓库。

## 启动

```powershell
.\start-edr.ps1
# 或
python edr_server.py --port 8100
```

浏览器打开：`http://127.0.0.1:8100`

## Agent 构建

```powershell
python scripts\build_agent.py
```

## 管理台前端

```powershell
cd agent_admin
npm install
npm run build
```
