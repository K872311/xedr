@echo off
cd /d "%~dp0"
python "%~dp0..\scripts\build_agent.py" %*
if errorlevel 1 (
  echo build FAILED
  exit /b 1
)
echo built forensic-agent.exe + build-manifest.json (windowsgui, no console/tray)
