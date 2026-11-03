# -*- coding: utf-8 -*-
"""ForensicAgent 静默安装包脚本（仅用户态 Agent，不含内核驱动）。"""
from __future__ import annotations

from typing import Any, Dict


def install_bat() -> str:
    return "\r\n".join([
        "@echo off",
        "setlocal EnableDelayedExpansion",
        "cd /d \"%~dp0\"",
        "set LOG=%~dp0install.log",
        "set RESULT=%~dp0install_result.txt",
        ">\"%LOG%\" echo === ForensicAgent install %DATE% %TIME% ===",
        "set AGENT_ST=fail",
        "net session >nul 2>&1",
        "if errorlevel 1 (",
        "  echo need_admin>>\"%LOG%\"",
        "  echo ForensicAgent 安装失败：需要管理员权限。>\"%RESULT%\"",
        "  exit /b 1",
        ")",
        "set DEST=%ProgramData%\\ForensicAgent",
        "if not exist \"%DEST%\" mkdir \"%DEST%\"",
        "copy /y \"%~dp0forensic-agent.exe\" \"%DEST%\\forensic-agent.exe\" >nul",
        "copy /y \"%~dp0agent.json\" \"%DEST%\\agent.json\" >nul",
        "findstr /i /c:\"server_url\" \"%DEST%\\agent.json\" >nul 2>&1",
        "if errorlevel 1 (",
        "  echo agent_json_missing_server_url>>\"%LOG%\"",
        "  echo ForensicAgent 安装失败：agent.json 缺少 server_url，请重新下载安装包。>\"%RESULT%\"",
        "  exit /b 1",
        ")",
        "\"%DEST%\\forensic-agent.exe\" uninstall >>\"%LOG%\" 2>&1",
        "\"%DEST%\\forensic-agent.exe\" install -config \"%DEST%\\agent.json\" >>\"%LOG%\" 2>&1",
        "if errorlevel 1 (",
        "  echo agent_install_failed>>\"%LOG%\"",
        "  goto :write_result",
        ")",
        "sc config ForensicAgent start= auto >>\"%LOG%\" 2>&1",
        "sc failure ForensicAgent reset= 86400 actions= restart/15000/restart/15000/restart/30000 >>\"%LOG%\" 2>&1",
        "sc start ForensicAgent >>\"%LOG%\" 2>&1",
        "set AGENT_ST=ok",
        "echo agent_ok>>\"%LOG%\"",
        ":write_result",
        "if \"%AGENT_ST%\"==\"ok\" (",
        "  echo Agent：安装成功，服务 ForensicAgent 已配置。>\"%RESULT%\"",
        "  echo.>>\"%RESULT%\"",
        "  echo 采集为用户态（ETW / 事件日志 / 进程与文件等），不含内核驱动。>>\"%RESULT%\"",
        ") else (",
        "  echo Agent：安装失败，请查看 install.log。>\"%RESULT%\"",
        ")",
        "exit /b 0",
        "",
    ])


def install_vbs() -> str:
    return "\r\n".join([
        "Set fso = CreateObject(\"Scripting.FileSystemObject\")",
        "Set wsh = CreateObject(\"WScript.Shell\")",
        "dir = fso.GetParentFolderName(WScript.ScriptFullName)",
        "bat = dir & \"\\install.bat\"",
        "If Not fso.FileExists(bat) Then",
        "  MsgBox \"缺少 install.bat\", vbCritical, \"ForensicAgent\"",
        "  WScript.Quit 1",
        "End If",
        "rc = wsh.Run(\"\"\"\" & bat & \"\"\"\", 0, True)",
        "resultPath = dir & \"\\install_result.txt\"",
        "msg = \"安装流程已结束。\"",
        "If fso.FileExists(resultPath) Then",
        "  msg = fso.OpenTextFile(resultPath, 1).ReadAll",
        "End If",
        "If rc <> 0 Then msg = msg & vbCrLf & vbCrLf & \"(install.bat 退出码 \" & rc & \")\"",
        "MsgBox msg, vbInformation, \"ForensicAgent 安装结果\"",
        "",
    ])


def uninstall_bat() -> str:
    return "\r\n".join([
        "@echo off",
        "setlocal",
        "net session >nul 2>&1 || exit /b 1",
        "set DEST=%ProgramData%\\ForensicAgent",
        "sc stop FaKmon >nul 2>&1",
        "sc delete FaKmon >nul 2>&1",
        "if exist \"%DEST%\\forensic-agent.exe\" (",
        "  \"%DEST%\\forensic-agent.exe\" uninstall > \"%~dp0uninstall.log\" 2>&1",
        ") else (",
        "  \"%~dp0forensic-agent.exe\" uninstall > \"%~dp0uninstall.log\" 2>&1",
        ")",
        "sc stop ForensicAgent >nul 2>&1",
        "sc delete ForensicAgent >nul 2>&1",
        "exit /b 0",
        "",
    ])


def readme_text(*, base: str, rel: Dict[str, Any]) -> str:
    return "\r\n".join([
        "ForensicAgent（静默，用户态采集）",
        "安装: 右键 install.vbs → 以管理员身份运行",
        "完成后会弹出安装结果摘要。",
        "安装目录: %ProgramData%\\ForensicAgent\\",
        "卸载: uninstall.bat（管理员）",
        f"平台: {base}",
        f"版本: {rel.get('version') or '未知'}  构建: {rel.get('build_id') or '未知'}  状态: {rel.get('status')}",
        f"EXE SHA256: {rel.get('exe_sha256') or ''}",
        "",
        "不含内核驱动 FaKmon（实验室驱动已停用下发，避免蓝屏风险）。",
        "",
        "【可选本机策略】Security/System 审核、PowerShell 日志、Sysmon 等。",
        "",
    ])
