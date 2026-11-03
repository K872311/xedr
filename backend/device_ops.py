# -*- coding: utf-8 -*-
"""设备级操作：重启 / 关机 / 恢复出厂（须管理员密码确认）。"""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from . import config

_lock = threading.RLock()
_fail: Dict[str, Any] = {"n": 0, "until": 0.0}
_FAIL_MAX = 5
_FAIL_LOCK = 60


def _root() -> Path:
    return Path(getattr(config, "ROOT", None) or Path(__file__).resolve().parent.parent).resolve()


def auth_locked() -> Optional[str]:
    with _lock:
        until = float(_fail.get("until") or 0)
        left = int(until - time.time())
        if left > 0:
            return f"密码错误次数过多，请 {left} 秒后再试"
    return None


def note_auth_fail() -> Optional[str]:
    with _lock:
        n = int(_fail.get("n") or 0) + 1
        _fail["n"] = n
        if n >= _FAIL_MAX:
            _fail["n"] = 0
            _fail["until"] = time.time() + _FAIL_LOCK
            return f"密码错误次数过多，请 {_FAIL_LOCK} 秒后再试"
    return None


def note_auth_ok() -> None:
    with _lock:
        _fail["n"] = 0
        _fail["until"] = 0.0


def issue_otp(*, user_id: str = "") -> Dict[str, Any]:
    """兼容旧接口：不再签发可回传的验证码。"""
    return {
        "ok": True,
        "ttl": 0,
        "expires_in": 0,
        "message": "请在执行设备操作时再次输入管理员密码",
    }


def verify_otp(code: str, *, user_id: str = "") -> Optional[str]:
    return "请改用管理员密码确认设备操作"


def reboot_host(*, user_id: str = "") -> Dict[str, Any]:
    return _run_shutdown(reboot=True, delay_sec=5)


def shutdown_host(*, user_id: str = "") -> Dict[str, Any]:
    return _run_shutdown(reboot=False, delay_sec=5)


def _win_shutdown_exe() -> str:
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return str(Path(root) / "System32" / "shutdown.exe")


def _run_shutdown(*, reboot: bool, delay_sec: int = 5) -> Dict[str, Any]:
    """对本机发起重启/关机。成功则约 delay_sec 秒后执行。"""
    delay_sec = max(0, min(120, int(delay_sec)))
    if os.name == "nt":
        exe = _win_shutdown_exe()
        if not Path(exe).is_file():
            return {"ok": False, "error": f"未找到 shutdown.exe：{exe}"}
        args = [exe, "/r" if reboot else "/s", "/t", str(delay_sec), "/f",
                "/c", "管理员通过系统运行状态发起设备" + ("重启" if reboot else "关机")]
        try:
            p = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=20,
                encoding="utf-8",
                errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as e:
            return {"ok": False, "error": f"无法执行关机命令: {e}"}
        out = ((p.stderr or "") + "\n" + (p.stdout or "")).strip()
        if p.returncode != 0:
            low = out.lower()
            if p.returncode in (5, 1314) or "privilege" in low or "access" in low or "拒绝" in out or "特权" in out:
                return {"ok": False, "error": "重启/关机失败：当前服务没有系统关机权限，请用管理员身份运行分析服务"}
            return {"ok": False, "error": out or f"shutdown 失败（exit {p.returncode}）"}
        action = "reboot" if reboot else "shutdown"
        return {
            "ok": True,
            "action": action,
            "message": f"已安排约 {delay_sec} 秒后{'重启' if reboot else '关闭'}本机",
        }
    cmd = ["shutdown", "-r" if reboot else "-h", f"+{max(0, delay_sec // 60)}"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except Exception as e:
        return {"ok": False, "error": f"无法执行关机命令: {e}"}
    if p.returncode != 0:
        return {"ok": False, "error": (p.stderr or p.stdout or f"exit {p.returncode}").strip()}
    return {
        "ok": True,
        "action": "reboot" if reboot else "shutdown",
        "message": f"已安排本机{'重启' if reboot else '关机'}",
    }


def _safe_clear_dir(path: Path) -> int:
    n = 0
    if not path.exists():
        return 0
    try:
        for child in path.iterdir():
            try:
                if child.is_file() or child.is_symlink():
                    child.unlink(missing_ok=True)
                    n += 1
                elif child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                    n += 1
            except Exception:
                continue
    except Exception:
        pass
    return n


def factory_reset(*, user_id: str = "") -> Dict[str, Any]:
    """清除分析报告与采集结果；保留规则库 / 黑白名单 / 用户配置 / 程序本体。"""
    root = _root()
    cleared: Dict[str, int] = {}
    for name in ("reports", "jg"):
        cleared[name] = _safe_clear_dir(root / name)
    try:
        p = root / "config" / "runtime_metrics.json"
        if p.is_file():
            p.unlink()
            cleared["runtime_metrics"] = 1
    except Exception:
        pass
    return {
        "ok": True,
        "message": "已清除分析数据（报告 / 采集结果），规则、黑白名单与账号配置保留",
        "action": "factory_reset",
        "cleared": cleared,
    }
