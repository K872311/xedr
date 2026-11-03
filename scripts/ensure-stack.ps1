# Ensure Elasticsearch + Kibana are listening (auto-detect install dirs).
# Usage: .\scripts\ensure-stack.ps1
#        .\scripts\ensure-stack.ps1 -EsHome "D:\...\elasticsearch-9.5.0" -KibanaHome "D:\...\kibana-9.5.0"
param(
  [string]$EsHome = "",
  [string]$KibanaHome = "",
  [int]$EsPort = 9200,
  [int]$KibanaPort = 5601,
  [int]$EsWaitSec = 90,
  [switch]$Quiet,
  [switch]$SkipKibana
)

$ErrorActionPreference = "Continue"

# Load saved paths from config (service manager UI writes these — no need to edit start.ps1)
function Read-StackConfig {
  $root = Split-Path -Parent $PSScriptRoot
  $out = @{ es = ""; kb = "" }
  $sp = Join-Path $root "config\stack_paths.json"
  if (Test-Path -LiteralPath $sp) {
    try {
      $j = Get-Content -LiteralPath $sp -Raw -Encoding UTF8 | ConvertFrom-Json
      if ($j.elasticsearch_home) { $out.es = [string]$j.elasticsearch_home }
      if ($j.kibana_home) { $out.kb = [string]$j.kibana_home }
    } catch {}
  }
  $db = Join-Path $root "config\db_config.json"
  if (Test-Path -LiteralPath $db) {
    try {
      $j = Get-Content -LiteralPath $db -Raw -Encoding UTF8 | ConvertFrom-Json
      if (-not $out.es -and $j.elasticsearch.home) { $out.es = [string]$j.elasticsearch.home }
      if (-not $out.kb -and $j.elasticsearch.kibana_home) { $out.kb = [string]$j.elasticsearch.kibana_home }
    } catch {}
  }
  return $out
}

$cfgPaths = Read-StackConfig
if (-not $EsHome) { $EsHome = $cfgPaths.es }
if (-not $KibanaHome) { $KibanaHome = $cfgPaths.kb }

function Write-Info([string]$msg) {
  if (-not $Quiet) { Write-Host $msg }
}

function Test-ListenPort([int]$Port) {
  try {
    $c = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
      Select-Object -First 1
    if ($c) { return $true }
  } catch {}
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
    $ok = $iar.AsyncWaitHandle.WaitOne(400)
    if ($ok -and $client.Connected) { $client.Close(); return $true }
    $client.Close()
  } catch {}
  return $false
}

function Find-Home([string]$Kind, [string]$Hint) {
  if ($Hint -and (Test-Path -LiteralPath $Hint)) {
    $bat = Join-Path $Hint ("bin\" + $(if ($Kind -eq "elasticsearch") { "elasticsearch.bat" } else { "kibana.bat" }))
    if (Test-Path -LiteralPath $bat) { return (Resolve-Path -LiteralPath $Hint).Path }
  }
  $envName = if ($Kind -eq "elasticsearch") { "FORENSIC_ES_HOME" } else { "FORENSIC_KIBANA_HOME" }
  $envVal = [Environment]::GetEnvironmentVariable($envName)
  if ($envVal -and (Test-Path -LiteralPath $envVal)) {
    $bat = Join-Path $envVal ("bin\" + $(if ($Kind -eq "elasticsearch") { "elasticsearch.bat" } else { "kibana.bat" }))
    if (Test-Path -LiteralPath $bat) { return (Resolve-Path -LiteralPath $envVal).Path }
  }
  $roots = @(
    "C:\elastic",
    "C:\Program Files\Elastic",
    (Split-Path -Parent $PSScriptRoot)
  )
  $batName = if ($Kind -eq "elasticsearch") { "elasticsearch.bat" } else { "kibana.bat" }
  $pattern = if ($Kind -eq "elasticsearch") { "*elasticsearch*" } else { "*kibana*" }
  foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $hits = Get-ChildItem -LiteralPath $root -Directory -Filter $pattern -ErrorAction SilentlyContinue
    foreach ($dir in $hits) {
      $cand = @(
        (Join-Path $dir.FullName "bin\$batName"),
        (Join-Path $dir.FullName "$($dir.Name -replace '-windows.*$','')\bin\$batName")
      )
      # nested unpack: elasticsearch-9.5.0-windows-x86_64\elasticsearch-9.5.0\bin\...
      $nested = Get-ChildItem -LiteralPath $dir.FullName -Directory -Filter $pattern -ErrorAction SilentlyContinue |
        Select-Object -First 3
      foreach ($n in $nested) {
        $cand += (Join-Path $n.FullName "bin\$batName")
      }
      foreach ($b in $cand) {
        if (Test-Path -LiteralPath $b) {
          return (Split-Path -Parent (Split-Path -Parent $b))
        }
      }
    }
  }
  return ""
}

function Start-StackApp([string]$AppDir, [string]$BatName, [string]$Title) {
  $bat = Join-Path $AppDir "bin\$BatName"
  if (-not (Test-Path -LiteralPath $bat)) {
    Write-Info "  missing: $bat"
    return $false
  }
  Write-Info "  start $Title : $bat"
  # Normal window so .bat startup logs are visible
  Start-Process -FilePath $bat -WorkingDirectory (Join-Path $AppDir "bin") -WindowStyle Normal | Out-Null
  return $true
}

function Wait-Port([int]$Port, [int]$Sec, [string]$Label) {
  $deadline = (Get-Date).AddSeconds($Sec)
  while ((Get-Date) -lt $deadline) {
    if (Test-ListenPort $Port) {
      Write-Info "  $Label ready on :$Port"
      return $true
    }
    Start-Sleep -Seconds 2
  }
  Write-Info "  $Label not ready on :$Port within ${Sec}s"
  return $false
}

$esHome = Find-Home "elasticsearch" $EsHome
$kbHome = Find-Home "kibana" $KibanaHome

Write-Info "[stack] Elasticsearch home: $(if ($esHome) { $esHome } else { '(not found)' })"
Write-Info "[stack] Kibana home: $(if ($kbHome) { $kbHome } else { '(not found)' })"

$result = @{
  es_home = $esHome
  kibana_home = $kbHome
  es_port = $EsPort
  kibana_port = $KibanaPort
  es_was_up = (Test-ListenPort $EsPort)
  kibana_was_up = (Test-ListenPort $KibanaPort)
  es_started = $false
  kibana_started = $false
  es_ready = $false
  kibana_ready = $false
}

if ($result.es_was_up) {
  Write-Info "[stack] ES already listening :$EsPort"
  $result.es_ready = $true
} elseif ($esHome) {
  $result.es_started = [bool](Start-StackApp $esHome "elasticsearch.bat" "Elasticsearch")
  $result.es_ready = Wait-Port $EsPort $EsWaitSec "ES"
} else {
  Write-Info "[stack] skip ES (home not found)"
}

if ($SkipKibana) {
  Write-Info "[stack] Kibana skipped (-SkipKibana)"
} elseif ($result.kibana_was_up) {
  Write-Info "[stack] Kibana already listening :$KibanaPort"
  $result.kibana_ready = $true
} elseif ($kbHome) {
  # Kibana 依赖 ES；未就绪也尝试启动，由 Kibana 自己重试
  $result.kibana_started = [bool](Start-StackApp $kbHome "kibana.bat" "Kibana")
  $result.kibana_ready = Wait-Port $KibanaPort ([Math]::Max(30, [int]($EsWaitSec / 2))) "Kibana"
} else {
  Write-Info "[stack] skip Kibana (home not found)"
}

# Emit machine-readable line for callers
Write-Output ("STACK_RESULT " + ($result | ConvertTo-Json -Compress))
exit 0
