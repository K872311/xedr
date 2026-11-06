# 启动 D:\GeRen\web\hj 下的 Elasticsearch（与 config\stack_paths.json / db_config 一致）
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$stack = Join-Path $root "config\stack_paths.json"
if (-not (Test-Path $stack)) { throw "缺少 $stack" }
$sp = Get-Content $stack -Raw | ConvertFrom-Json
$bat = $sp.elasticsearch_script
$esHome = $sp.elasticsearch_home
if (-not (Test-Path $bat)) { throw "未找到 $bat" }
Write-Host "ES home: $esHome"
Write-Host "启动: $bat"
Start-Process -FilePath $bat -WorkingDirectory (Split-Path $bat -Parent) -WindowStyle Minimized
Write-Host "等待 9200 …"
$deadline = (Get-Date).AddMinutes(3)
while ((Get-Date) -lt $deadline) {
    try {
        $r = Test-NetConnection -ComputerName 127.0.0.1 -Port 9200 -WarningAction SilentlyContinue
        if ($r.TcpTestSucceeded) {
            Write-Host "9200 已监听"
            exit 0
        }
    } catch {}
    Start-Sleep -Seconds 2
}
Write-Host "超时：请查看 $esHome\logs\elasticsearch.log"
exit 1
