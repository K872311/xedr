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

## 有关项目
本项目（含 Agent 端与管理平台）仅面向安全技术学习、研究与交流目的开源，不构成任何商业产品或安全服务承诺。

严禁将本项目用于任何未经授权的主机监控、数据采集、入侵检测部署或其他非法用途；

未经终端所有者明确知情并同意，不得在任何主机上安装、运行本 Agent 或同步其数据。

使用者应自行确保其部署行为符合所在国家/地区的法律法规（包括但不限于《个人信息保护法》《网络安全法》《数据安全法》及《网络产品安`全漏洞管理规定》），并自行承担因不当使用产生的一切法律责任。项目作者不对使用者因

违反上述声明或法律法规而导致的任何直接或间接损失承担责任。如你计划将本项目用于企业生产环境或商业场景，请务必自行完成合规评估并`取得必要授权。
