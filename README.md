# EDR 终端安全平台

轻量级 EDR：Windows 终端 Agent（Go）实时采集进程 / 网络 / 注册表 / 计划任务 / 服务 / 事件日志等数据，上报到服务端（Python FastAPI）做规则检测、威胁情报匹配和响应处置，管理台为 Vue 单页应用。

| 目录 / 文件 | 说明 |
|-------------|------|
| `edr_server.py` | 服务端入口，默认监听 `0.0.0.0:8100` |
| `start-edr.ps1` | Windows 一键启动脚本 |
| `backend/` | 服务端 API、Agent 协议、遥测入库、检测与情报匹配 |
| `agent/` | 终端 Agent 源码（Go，仅 Windows） |
| `agent_admin/` | 管理台前端（Vue 3 + Vite），构建产物在 `agent_admin/dist/` |
| `rules/` `yara/` `log_rules/` `sigma_high_priority/` | 检测规则、YARA、事件日志规则 |
| `config/` | 平台配置；`*.example.json` 为示例模板 |
| `scripts/` | Agent 构建、规则导入、ES 初始化等工具脚本 |
| `deploy/` | Nginx / Caddy 反向代理示例 |

## 环境要求

| 组件 | 版本 | 是否必需 |
|------|------|----------|
| Python | 3.10+ | 必需 |
| Node.js | 20.19+ 或 22.12+ | 构建管理台时需要 |
| Go | 1.26+ | 构建 Agent 时需要 |
| MySQL | 5.7 / 8.0 | 可选，未启用时使用本地 SQLite |
| Redis | 3.0+ | 可选，用于缓存和多进程消息 |
| Elasticsearch | 8.x / 9.x | 可选，用于 EQL 检测和大规模事件检索 |

最小部署只需要 Python：数据默认存放在 `reports/` 下的 SQLite 库中。

## 快速开始（单机）

### 1. 安装 Python 依赖

```powershell
python -m pip install -r requirements.txt
```

### 2. 构建管理台

```powershell
cd agent_admin
npm install
npm run build
cd ..
```

未构建时访问页面会提示「EDR 后台前端尚未构建」。

### 3. 准备配置（可选）

不做任何配置也能启动（SQLite 模式）。需要 MySQL / Redis / ES 时，从示例复制一份再修改：

```powershell
Copy-Item config\db_config.example.json config\db_config.json
```

- `enabled`：是否启用 MySQL；`false` 时使用 SQLite。
- `redis.enabled`：未安装 Redis 时请改为 `false`。
- `elasticsearch`：ES 检测相关字段见 `config\elasticsearch_edr_detection.example.json`。
- 带有本机路径的配置（`stack_paths.json`、`hj_stack.json`）同样从对应的 `.example.json` 复制。

`config\db_config.json` 等含密码的文件已写入 `.gitignore`，不会被提交。

### 4. 启动服务

```powershell
.\start-edr.ps1              # 开发模式，代码改动自动重载
.\start-edr.ps1 -NoReload    # 正式运行
# 或
python edr_server.py --port 8100
```

浏览器打开 `http://<服务器IP>:8100`。

### 5. 首次登录

首次启动且没有任何账号时，会自动创建 `admin` 账号，随机密码**只打印在控制台**，首次登录必须修改密码。

- 预设初始密码：启动前设置环境变量 `EDR_BOOTSTRAP_ADMIN_PASSWORD`。
- 忘记密码：`python edr_server.py --reset-admin`，会打印新的临时密码。
- 其他账号在管理台「平台配置 → 账号管理」中创建。

## 部署终端 Agent

### 1. 构建 Agent

```powershell
python scripts\build_agent.py
```

脚本会生成 `agent\forensic-agent.exe` 和 `agent\build-manifest.json`，平台据此判断安装包版本。服务端已生成升级签名公钥时，会自动写入 EXE，用于后续灰度升级的验签。

需要 YARA 内存扫描时，参考 `agent\MEMORY_YARA.md`，使用 `agent\build-agent.ps1 -Yara` 构建（需要 libyara 和 CGO）。

### 2. 设置平台地址

在管理台「平台配置 → 接入与地址」填写**终端能访问到**的平台地址，例如 `http://<服务器IP>:8100`，不要填 `127.0.0.1`。留空时会使用当前浏览器访问的地址。

### 3. 下载并安装

1. 管理台「部署运营 → 安装包下载」，下载安装包（已内嵌平台地址和接入密钥）。
2. 拷贝到目标机解压，以管理员身份运行 `install.bat`（或双击 `install.vbs` 静默安装）。
3. Agent 注册为 Windows 服务 `ForensicAgent`，开机自启；回到「终端资产 → 终端列表」即可看到该主机。

卸载：在目标机以管理员运行安装包中的 `uninstall.bat`。

轮换接入密钥后，需要重新下载安装包。

### 4. 目标机日志策略（可选）

Agent 默认订阅 Security / System 日志。要采集更多数据，需在目标机开启：

- **审核策略**：登录、账户管理、策略更改等（本地安全策略或域 GPO）。
- **PowerShell 日志**：模块日志 + 脚本块日志（4103 / 4104）。
- **Sysmon**：安装后 Agent 会自动订阅，未安装则静默跳过。

详见 `agent\README.md`。

## 生产部署

### 反向代理 + HTTPS

服务只监听本机回环地址，由 Nginx / Caddy 负责 HTTPS：

```powershell
$env:FORENSIC_TRUST_PROXY = "1"
$env:FORENSIC_TRUSTED_PROXIES = "127.0.0.1,::1"
python edr_server.py --host 127.0.0.1 --port 8100
```

Nginx 示例（把域名和证书路径替换成自己的）：

```nginx
upstream edr_api {
    server 127.0.0.1:8100;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name edr.example.com;

    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    client_max_body_size 100m;

    location / {
        proxy_pass http://edr_api;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }
}
```

`deploy\` 下有更完整的限流示例（`nginx.conf.example`、`Caddyfile.example`），其中端口需改为 8100。启用 HTTPS 后，记得把「接入与地址」改成 `https://` 地址并重新下载安装包。

### 作为 Windows 服务常驻

可以用 [NSSM](https://nssm.cc/) 把服务端注册为系统服务：

```powershell
nssm install EDRServer "C:\Python313\python.exe" "edr_server.py --host 127.0.0.1 --port 8100"
nssm set EDRServer AppDirectory "D:\edr"
nssm start EDRServer
```

### 启用 Elasticsearch 检测（可选）

1. 在 `config\db_config.json` 的 `elasticsearch` 中填写地址和账号，设置 `edr_detection_enabled: true`。
2. 初始化索引：`python scripts\setup_elasticsearch_edr.py`。
3. 重启服务后，控制台出现 `elasticsearch EQL detection loop started` 即表示已生效。

## 常用环境变量

| 变量 | 说明 | 默认 |
|------|------|------|
| `EDR_PORT` / `EDR_HOST` | 监听端口 / 地址 | `8100` / `0.0.0.0` |
| `EDR_BOOTSTRAP_ADMIN_PASSWORD` | 首次启动的 admin 密码 | 随机生成 |
| `EDR_SESSION_TTL_HOURS` | 登录会话最长时间（小时） | `12` |
| `EDR_SESSION_IDLE_MINUTES` | 空闲超时（分钟） | `120` |
| `FORENSIC_MYSQL_ENABLED` / `_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_DATABASE` | 覆盖 MySQL 配置 | 读 `db_config.json` |
| `FORENSIC_ES_PASSWORD` | ES 密码 | 读 `db_config.json` |
| `FORENSIC_IOC_DB` | 威胁情报库路径 | 项目根 `ioc_data.db` |
| `FORENSIC_TRUST_PROXY` / `FORENSIC_TRUSTED_PROXIES` | 信任反向代理的真实 IP 头 | 关闭 |
| `FORENSIC_MAX_BODY_MB` | 请求体上限（MB） | 见配置 |
| `FORENSIC_SKIP_CORPUS_BOOTSTRAP` | 设为 `1` 跳过启动时的检测规则初始化 | 不跳过 |

## 数据与备份

以下内容都是运行时生成的，已写入 `.gitignore`：

| 路径 | 内容 |
|------|------|
| `reports/agents.db` | 终端、事件、时间线、处置记录 |
| `reports/edr_users.db` | 管理台账号与会话 |
| `reports/agent_packages/` | 安装包缓存 |
| `data/agent_upgrades/` | Agent 升级签名密钥（**私钥务必备份并妥善保管**） |
| `config/platform_secret.key` | 平台加密密钥（丢失后已加密的配置无法解密） |
| `ioc_data.db` | 威胁情报库（需自行放置，或用 `FORENSIC_IOC_DB` 指定） |

备份时停止服务后，复制上面这些文件即可；启用 MySQL 时还需备份对应数据库。

## 开发

```powershell
.\start-edr.ps1                  # 后端，自动重载
cd agent_admin; npm run dev      # 前端开发服务器 http://127.0.0.1:5174，/api 代理到 8100
```

## 有关项目
`本项目（含 Agent 端与管理平台）仅面向安全技术学习、研究与交流目的开源，不构成任何商业产品或安全服务承诺。
`严禁将本项目用于任何未经授权的主机监控、数据采集、入侵检测部署或其他非法用途；
`未经终端所有者明确知情并同意，不得在任何主机上安装、运行本 Agent 或同步其数据。使用者应自行确保其部署行为符合所在国家/地区的法律法规（包括但不限于《个人信息保护法》《网络安全法》《数据安全法》及《网络产品安`全漏洞管理规定》），并自行承担因不当使用产生的一切法律责任。项目作者不对使用者因违反上述声明或法律法规而导致的任何直接或间接损失承担责任。如你计划将本项目用于企业生产环境或商业场景，请务必自行完成合规评估并`取得必要授权。
