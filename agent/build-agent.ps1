# 编译 Forensic Agent
# 默认：启发式 + rules.json 字符串规则（无需 libyara）
# -Yara：启用 github.com/hillu/go-yara（需安装 libyara 与 CGO，见 MEMORY_YARA.md）

param(
    [switch]$Yara,
    [string]$Out = "dist\forensic-agent.exe"
)

$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot

$tags = @()
if ($Yara) { $tags += "yara" }

$env:CGO_ENABLED = "1"
$tagArg = ""
if ($tags.Count -gt 0) { $tagArg = "-tags=" + ($tags -join ",") }

Write-Host "go build $tagArg ..."
if ($tagArg) {
    go build $tagArg -ldflags "-s -w" -o $Out .
} else {
    $env:CGO_ENABLED = "0"
    go build -ldflags "-s -w" -o $Out .
}

Pop-Location
Write-Host "OK -> $Out"
