# FaKmon 内核驱动：工具链检测 / 编译 / 测试签名 / 安装
# 用法（管理员 PowerShell）：
#   .\build-driver.ps1 -CheckOnly   # 只检查工具链与本机能否加载
#   .\build-driver.ps1              # 编译 + 测试签名 → out\fakmon.sys、out\FaKmonTest.cer
#   .\build-driver.ps1 -Install     # 在【测试机】上：导入测试证书、复制、sc create/start
#
# 加载条件：测试签名驱动只能在 bcdedit testsigning on 的机器上加载，
# 而开启 Secure Boot 的机器无法开启 testsigning（需先在 BIOS 关闭）。
# 生产终端必须走 EV 证书 + 微软 Attestation 签名。

param(
  [switch]$CheckOnly,
  [switch]$Install,
  [switch]$NoSign,
  [string]$OutDir = ""
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcCs = @(Get-ChildItem -Path $Root -Filter "*.c" | ForEach-Object { $_.FullName })
$SrcH = Join-Path $Root "fakmon.h"
if (-not $OutDir) { $OutDir = Join-Path $Root "out" }
$CertSubject = "CN=FaKmon Test Signing"

function Ok($m) { Write-Host "[OK]  $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!!]  $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "[NO]  $m" -ForegroundColor Red }
function Info($m) { Write-Host "[..]  $m" -ForegroundColor Cyan }

function Find-Kit {
  foreach ($base in @("${env:ProgramFiles(x86)}\Windows Kits\10", "${env:ProgramFiles}\Windows Kits\10")) {
    $inc = Join-Path $base "Include"
    if (-not (Test-Path $inc)) { continue }
    $vers = Get-ChildItem $inc -Directory | Where-Object { Test-Path (Join-Path $_.FullName "km\ntddk.h") } | Sort-Object Name -Descending
    foreach ($v in $vers) {
      $lib = Join-Path $base "Lib\$($v.Name)\km\x64"
      if (Test-Path (Join-Path $lib "ntoskrnl.lib")) {
        return [pscustomobject]@{ Base = $base; Ver = $v.Name; Inc = $v.FullName; Lib = $lib }
      }
    }
  }
  return $null
}

function Find-SignTool($kit) {
  $cands = @()
  if ($kit) { $cands += Join-Path $kit.Base "bin\$($kit.Ver)\x64\signtool.exe" }
  foreach ($base in @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "${env:ProgramFiles}\Windows Kits\10\bin")) {
    if (Test-Path $base) {
      $cands += Get-ChildItem $base -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "\\x64\\" } | Sort-Object FullName -Descending | ForEach-Object FullName
    }
  }
  return $cands | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}

Write-Host ""
Write-Host "=== FaKmon 驱动 ===" -ForegroundColor White
Write-Host "源码: $Root"
Write-Host ""

if ($SrcCs.Count -lt 1 -or -not (Test-Path $SrcH)) { Fail "缺少 *.c / fakmon.h"; exit 1 }
Ok "源码文件齐全"

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = $null
if (Test-Path $vswhere) {
  $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
}
if ($vsPath) { Ok "VS C++ 工具链: $vsPath" } else { Fail "未找到 VS C++ 工具链（Build Tools 2022 + VCTools）" }

$kit = Find-Kit
if ($kit) { Ok "WDK $($kit.Ver): $($kit.Inc)" } else { Fail "未找到 WDK（需含 km\ntddk.h 与 km\x64\ntoskrnl.lib）" }

# 本机加载条件
$sb = $null
try { $sb = Confirm-SecureBootUEFI } catch { $sb = $null }
$testSign = [bool](bcdedit /enum "{current}" 2>$null | Select-String "testsigning\s+Yes")
if ($sb) { Warn "本机 Secure Boot 已开启：无法开测试签名，本机只适合编译，不适合加载测试驱动" }
if ($testSign) { Ok "测试签名已开启" } else { Warn "测试签名未开启（测试机需 bcdedit /set testsigning on 并重启）" }

$svc = Get-Service -Name FaKmon -ErrorAction SilentlyContinue
if ($svc) { Ok "服务 FaKmon 已存在，状态=$($svc.Status)" } else { Info "服务 FaKmon 尚未安装" }

if ($CheckOnly) { exit 0 }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$sys = Join-Path $OutDir "fakmon.sys"
$cer = Join-Path $OutDir "FaKmonTest.cer"

# ---------- 编译 ----------
if (-not $Install -or -not (Test-Path $sys)) {
  if (-not $vsPath -or -not $kit) { Fail "工具链不齐，无法编译"; exit 2 }
  $vsDev = Join-Path $vsPath "Common7\Tools\VsDevCmd.bat"
  if (-not (Test-Path $vsDev)) { Fail "找不到 VsDevCmd.bat"; exit 2 }
  $objs = @()
  foreach ($c in $SrcCs) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($c)
    $objs += Join-Path $OutDir "$base.obj"
  }
  $objList = ($objs | ForEach-Object { "`"$_`"" }) -join " "
  $inc = $kit.Inc
  $compileLines = @()
  foreach ($c in $SrcCs) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($c)
    $o = Join-Path $OutDir "$base.obj"
    $compileLines += "cl /nologo /c /kernel /utf-8 /W4 /WX- /O2 /GS- /Gy /Zi /Zp8 /GR- /EHs-c- /D_AMD64_ /DAMD64 /D_WIN64 /DWIN64 /D_KERNEL_MODE /DNTDDI_VERSION=0x0A000008 /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DPOOL_NX_OPTIN=1 /I`"$Root`" /I`"$inc\km`" /I`"$inc\shared`" /I`"$inc\km\crt`" `"$c`" /Fo`"$o`" /Fd`"$OutDir\fakmon.pdb`""
  }
  $batLines = @(
    '@echo off'
    "call `"$vsDev`" -arch=amd64 -host_arch=amd64 >nul"
  )
  foreach ($line in $compileLines) {
    $batLines += $line
    $batLines += 'if errorlevel 1 exit /b 1'
  }
  $batLines += @(
    'if errorlevel 1 exit /b 1'
    "link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB /INTEGRITYCHECK /RELEASE /DEBUG /MERGE:_TEXT=.text /SECTION:INIT,d /OPT:REF /OPT:ICF /LIBPATH:`"$($kit.Lib)`" ntoskrnl.lib hal.lib wdmsec.lib bufferoverflowk.lib /OUT:`"$sys`" /PDB:`"$OutDir\fakmon_sys.pdb`" $objList"
    'if errorlevel 1 exit /b 1'
    'exit /b 0'
  )
  $bat = $batLines -join "`r`n"
  $tmpBat = Join-Path $env:TEMP "fa-build-fakmon.bat"
  Set-Content -Path $tmpBat -Value $bat -Encoding ASCII
  Info "编译 x64 Release …"
  & cmd /c $tmpBat
  $rc = $LASTEXITCODE
  Remove-Item $tmpBat -Force -ErrorAction SilentlyContinue
  if ($rc -ne 0 -or -not (Test-Path $sys)) { Fail "编译失败"; exit 3 }
  Ok "已生成: $sys ($([math]::Round((Get-Item $sys).Length/1KB,1)) KB)"

  # ---------- 测试签名 ----------
  if (-not $NoSign) {
    $signtool = Find-SignTool $kit
    if (-not $signtool) { Fail "找不到 signtool.exe（WDK/SDK 自带）"; exit 3 }
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Subject -eq $CertSubject | Select-Object -First 1
    if (-not $cert) {
      Info "创建测试代码签名证书 $CertSubject"
      $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CertSubject -CertStoreLocation Cert:\CurrentUser\My `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(5)
    }
    Export-Certificate -Cert $cert -FilePath $cer -Force | Out-Null
    & $signtool sign /fd sha256 /sha1 $cert.Thumbprint /s My "$sys"
    if ($LASTEXITCODE -ne 0) { Fail "签名失败"; exit 3 }
    Ok "已测试签名，证书: $cer"
  }
}

if (-not $Install) {
  Write-Host ""
  Info "部署到测试机：把 out\fakmon.sys、out\FaKmonTest.cer、本脚本拷过去，管理员运行 .\build-driver.ps1 -Install"
  exit 0
}

# ---------- 安装（测试机） ----------
if ($sb) { Fail "Secure Boot 已开启，测试签名驱动不会被加载。请在 BIOS 关闭 Secure Boot 或改用正式签名"; exit 4 }
if (-not $testSign) { Fail "请先执行 bcdedit /set testsigning on 并重启"; exit 4 }
if (-not (Test-Path $sys)) { Fail "缺少 $sys"; exit 4 }
if (Test-Path $cer) {
  Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
  Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
  Ok "已信任测试证书"
}

$destDir = "C:\ProgramData\ForensicAgent"
$dest = Join-Path $destDir "fakmon.sys"
New-Item -ItemType Directory -Force -Path $destDir | Out-Null
if ($svc) {
  sc.exe stop FaKmon | Out-Null
  Start-Sleep -Seconds 1
  sc.exe delete FaKmon | Out-Null
  Start-Sleep -Seconds 1
}
Copy-Item $sys $dest -Force
Ok "已复制到 $dest"

sc.exe create FaKmon type= kernel start= auto error= normal binPath= "$dest" DisplayName= "ForensicAgent Kernel Monitor" | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "sc create 失败"; exit 4 }
sc.exe start FaKmon
if ($LASTEXITCODE -ne 0) { Fail "sc start 失败（签名未被信任 / HVCI 拦截 / 驱动报错，可看系统事件日志）"; exit 4 }
Ok "FaKmon 已启动"

$agent = Get-Service ForensicAgent -ErrorAction SilentlyContinue
if ($agent) {
  Restart-Service ForensicAgent -Force
  Ok "已重启 ForensicAgent，将自动切换到内核通道"
} else {
  Warn "未发现 ForensicAgent 服务，安装 Agent 后会自动连接驱动"
}
exit 0
