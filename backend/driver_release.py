# -*- coding: utf-8 -*-
"""FaKmon 内核驱动发布：与 Agent 安装包一并下发（测试签名）。"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from . import config

DRIVER_SYS = "fakmon.sys"
DRIVER_CER = "FaKmonTest.cer"


def driver_out_dir() -> Path:
    return Path(config.ROOT) / "agent" / "driver" / "out"


def _driver_find(name: str, *, min_size: int = 1) -> Optional[Path]:
    """查找驱动产物：优先 driver/out，其次 agent/ 根（构建脚本会复制便于下发）。"""
    root = Path(config.ROOT) / "agent"
    for p in (
        driver_out_dir() / name,
        root / name,
        root / "driver" / "bundle" / name,
    ):
        if p.is_file() and p.stat().st_size >= min_size:
            return p
    return None


def driver_sys_path() -> Optional[Path]:
    return _driver_find(DRIVER_SYS, min_size=4096)


def driver_cer_path() -> Optional[Path]:
    return _driver_find(DRIVER_CER, min_size=1)


def driver_bundle_ready() -> bool:
    return driver_sys_path() is not None and driver_cer_path() is not None


def driver_status() -> Dict[str, Any]:
    from .agent_release import file_sha256

    sys_p = driver_sys_path()
    cer_p = driver_cer_path()
    out: Dict[str, Any] = {
        "driver_in_package": bool(sys_p and cer_p),
        "driver_sys_path": str(sys_p) if sys_p else "",
        "driver_cer_path": str(cer_p) if cer_p else "",
        "driver_sys_size": sys_p.stat().st_size if sys_p else 0,
        "driver_sys_sha256": file_sha256(sys_p) if sys_p else "",
        "driver_note": "",
    }
    if not sys_p:
        out["driver_note"] = "安装包不含内核驱动（需在 Windows 服务器上构建 agent/driver）"
    elif not cer_p:
        out["driver_note"] = "缺少 FaKmonTest.cer，驱动无法在新机器上信任加载"
    else:
        out["driver_note"] = "静默安装包将尝试安装 FaKmon（需目标机 testsigning 或正式签名）"
    return out


def run_driver_build(timeout_sec: int = 300) -> Dict[str, Any]:
    """Windows 上调用 agent/driver/build-driver.ps1（不 -Install）。"""
    if os.name != "nt":
        return {"ok": False, "skipped": True, "error": "非 Windows，跳过驱动编译"}
    ps1 = Path(config.ROOT) / "agent" / "driver" / "build-driver.ps1"
    if not ps1.is_file():
        return {"ok": False, "error": "缺少 build-driver.ps1"}
    t0 = time.time()
    try:
        cp = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ps1),
            ],
            cwd=str(ps1.parent),
            capture_output=True,
            timeout=timeout_sec,
        )
        log = (cp.stdout or b"").decode("utf-8", "replace") + (cp.stderr or b"").decode("utf-8", "replace")
        ok = cp.returncode == 0 and driver_sys_path() is not None
        return {
            "ok": ok,
            "code": cp.returncode,
            "log": log[-3000:],
            "seconds": round(time.time() - t0, 1),
            "driver_ready": driver_bundle_ready(),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"驱动构建超时 {timeout_sec}s", "seconds": round(time.time() - t0, 1)}
    except Exception as e:
        return {"ok": False, "error": str(e), "seconds": round(time.time() - t0, 1)}


def publish_driver_bundle() -> bool:
    """把 out/ 下驱动复制到 agent/，方便打包与部署同步。"""
    import shutil

    src_sys = driver_out_dir() / DRIVER_SYS
    src_cer = driver_out_dir() / DRIVER_CER
    if not src_sys.is_file() or not src_cer.is_file():
        return False
    dest = Path(config.ROOT) / "agent"
    try:
        shutil.copy2(src_sys, dest / DRIVER_SYS)
        shutil.copy2(src_cer, dest / DRIVER_CER)
        return True
    except OSError:
        return False


def driver_cache_token() -> str:
    sys_p = driver_sys_path()
    if not sys_p:
        return "no-driver"
    from .agent_release import file_sha256

    return file_sha256(sys_p)[:16]
