# forensic-agent — 开箱安装

**推荐用法（不用手改配置）：**

1. 登录平台 → 控制中心 → **在线 Agent** → **下载安装包**
2. 拷到目标机解压，右键 `install.bat` → **以管理员身份运行**
3. 回到平台「在线 Agent」刷新，即可看到本机实时数据

安装包已内嵌平台地址与接入密钥；服务名 `ForensicAgent`，开机自启。

## 本机策略（可选通道）

Agent **默认**订阅 Security / System 中已约定的登录、账号、服务、任务事件，不依赖额外软件。

以下通道需本机先开策略或装组件，Agent 才会采到对应日志：

### PowerShell Operational（4103 / 4104）

在目标机以管理员启用（本地安全策略或 GPO）：

1. `计算机配置 → 管理模板 → Windows 组件 → Windows PowerShell`
2. **打开模块日志**（Module Logging）→ 启用，模块名可填 `*`
3. **打开 PowerShell 脚本块日志**（Script Block Logging）→ 启用
4. 确认事件日志存在：`Microsoft-Windows-PowerShell/Operational`

启用后 Agent 自动订阅；规则管理里可开关「PowerShell 脚本块 / 模块日志」传感器。

### Sysmon（可选增强）

1. 从 Microsoft Sysinternals 安装 Sysmon，并加载一份精简配置（至少保留 Event 1/3/8/10/11/13/22）
2. 确认日志：`Microsoft-Windows-Sysmon/Operational`
3. Agent 在可用时自动订阅；未安装则静默跳过，不影响主通道

### 审计策略提示

登录 / 账号 / 服务安装等依赖 **安全审核** 已开。域环境请用 GPO；单机可在「本地安全策略 → 审核策略」中开启：

- 审核登录事件、账户管理、策略更改（按需）

## 开发者本地编译

```bat
cd agent
set GOPROXY=https://goproxy.cn,direct
go build -o forensic-agent.exe .
```

把 `forensic-agent.exe` 留在 `agent/` 目录，平台即可打包下载。

## 手动命令（一般不需要）

```bat
forensic-agent.exe install -config agent.json
forensic-agent.exe status
forensic-agent.exe uninstall
```
