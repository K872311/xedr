# EDR 控制台独立启动（与 forensic rules 项目分离）
# 用法: .\start-edr.ps1
#       .\start-edr.ps1 -Port 8100
#       .\start-edr.ps1 -NoReload
param(
  [int]$Port = 8100,
  [string]$HostAddr = "0.0.0.0",
  [switch]$NoReload
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  Write-Host "python not found, install Python 3.10+"
  exit 1
}

function Stop-PortListeners([int]$p) {
  $pids = @()
  try {
    $pids = @(Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |
      Select-Object -ExpandProperty OwningProcess -Unique)
  } catch {}
  foreach ($procId in $pids) {
    if (-not $procId -or $procId -eq 0) { continue }
    try {
      Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
      Write-Host "  freed port $p (PID $procId)"
    } catch {}
  }
  Start-Sleep -Milliseconds 400
}

Write-Host "[edr] check deps..."
python -c "import fastapi,uvicorn" 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Host "missing fastapi/uvicorn; pip install fastapi uvicorn"
  exit 1
}

Stop-PortListeners $Port
$env:EDR_PORT = "$Port"
$reloadArgs = @()
if (-not $NoReload) { $reloadArgs = @("--reload") }

Write-Host "[edr] starting http://${HostAddr}:${Port}  (admin UI: agent_admin/dist)"
Write-Host "      Agent / rules / config live under $PSScriptRoot"
python -m uvicorn edr_server:app --host $HostAddr --port $Port @reloadArgs
