# EDR 终端安全管理后台（独立部署）

与分析平台完全分离：独立进程、独立端口、独立账号。

## 访问

`http://<服务器IP>:8100/`，打开即是 EDR 登录页。

- 账号体系独立（`reports/edr_users.db`），与分析平台账号互不相通。
- 首次启动自动创建 `admin`，随机密码打印在 EDR 后台窗口里；首次登录必须改密。
  也可在启动前设置环境变量 `EDR_BOOTSTRAP_ADMIN_PASSWORD` 指定初始密码。
- 忘记密码：`python edr_server.py --reset-admin`（打印新的临时密码）。
- 登录后在「配置 → 账号管理」新建分析员 / 只读账号。

## 启动

- 随平台一起启动：`.\start.ps1`（另开窗口运行 EDR，端口 `-EdrPort 8100`，`-SkipEdr` 跳过）
- 单独启动：`python edr_server.py --port 8100`

终端安装包回连 EDR 端口。分析平台 8000 上的 `/api/agent/*` 只做透明转发，
供旧版安装包（回连 8000）继续上报；不转发 Cookie，分析平台账号无法操作 EDR。

## 开发 / 构建

```bat
cd agent_admin
npm install --registry=https://registry.npmmirror.com
npm run build
```

产物在 `agent_admin/dist`，由 `edr_server.py` 在根路径托管。开发时 `npm run dev`，`/api` 代理到 `127.0.0.1:8100`。
