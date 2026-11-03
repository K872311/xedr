# 公网网关

生产环境只让 Uvicorn 监听内网或回环地址：

```powershell
$env:FORENSIC_TRUST_PROXY="1"
$env:FORENSIC_TRUSTED_PROXIES="127.0.0.1,::1"
$env:FORENSIC_SLOW_REQUEST_MS="800"
uvicorn server:app --host 127.0.0.1 --port 8000
```

选择 `nginx.conf.example` 或 `Caddyfile.example`，替换域名和证书路径后部署。不要把
Uvicorn 的 8000 端口直接暴露到互联网。网关负责 HTTPS、HTTP/2、压缩、上传上限、
基础限流、长任务超时和真实 IP 转发；应用继续负责登录失败与敏感操作限流。

每个响应包含 `X-Request-ID` 和 `Server-Timing`。超过
`FORENSIC_SLOW_REQUEST_MS` 的请求会输出 `[slow_request]` 日志，其中包含鉴权、
数据库、总耗时、响应大小和客户端 IP。
