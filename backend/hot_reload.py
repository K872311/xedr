"""分析相关代码/规则热加载：避免长驻进程里后台任务一直跑旧 matcher。

每次分析任务开始前调用 ensure_fresh_analysis()：
- 磁盘上 backend 分析链 / rules JSON 有变更 → importlib.reload + reload_store
- 并把 jobs 模块里缓存的 analyze_report / JobCancelled 指到新对象
"""
from __future__ import annotations

import importlib
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config

_lock = threading.RLock()
_last_stamp: Optional[Tuple[int, int, int]] = None  # (py_mtime_ns_max, py_count, rules_mtime_ns_max)
_primed = False  # 首次任务强制热加载一次，避免「启动后、首任务前」改过的代码仍钉在旧模块上

# 分析链依赖（按先依赖后被依赖；pipeline 最后）
_MATCHER_MODS = [
    "backend.matchers.util",
    "backend.matchers.rule_engine",
    "backend.matchers.file_meta",
    "backend.matchers.files",
    "backend.matchers.ioc",
    "backend.matchers.network",
    "backend.matchers.keywords",
    "backend.matchers.wininfosc",
    "backend.matchers.remote_tools",
    "backend.remote_tools",
    "backend.ir_analysis",
    "backend.matchers.lateral",
    "backend.matchers.cred_theft",
    "backend.matchers.beacon",
    "backend.matchers.defense_weaken",
    "backend.matchers.exfil",
    "backend.matchers.persistence",
    "backend.matchers.browsers",
    "backend.matchers.artifacts",
    "backend.matchers.aux_rules",
    "backend.matchers.ransom",
    "backend.matchers.eventlog",
    "backend.matchers.interesting",
]

_CORE_MODS = [
    "backend.models",
    "backend.ingest",
    "backend.aggregate",
    "backend.platform",
    "backend.rules_loader",
    "backend.pipeline",
]


def _py_roots() -> List[Path]:
    root = Path(__file__).resolve().parent
    return [root, root / "matchers"]


def _iter_py_files() -> List[Path]:
    out: List[Path] = []
    for d in _py_roots():
        if not d.is_dir():
            continue
        for p in d.glob("*.py"):
            # jobs/hot_reload 自身变更需重启进程，避免打乱队列状态
            if p.name in ("jobs.py", "hot_reload.py"):
                continue
            out.append(p)
    return out


def _iter_rule_files() -> List[Path]:
    rd = Path(config.RULES_DIR)
    if not rd.is_dir():
        return []
    out: List[Path] = []
    for p in rd.rglob("*.json"):
        # 备份/缓存目录跳过
        parts = {x.lower() for x in p.parts}
        if ".bak" in parts or "__pycache__" in parts:
            continue
        out.append(p)
    gen = rd / ".rules_gen"
    if gen.is_file():
        out.append(gen)
    return out


def _stamp() -> Tuple[int, int, int]:
    py_max = 0
    py_n = 0
    for p in _iter_py_files():
        try:
            st = p.stat()
            py_max = max(py_max, int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))))
            py_n += 1
        except OSError:
            continue
    rules_max = 0
    for p in _iter_rule_files():
        try:
            st = p.stat()
            rules_max = max(rules_max, int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))))
        except OSError:
            continue
    return (py_max, py_n, rules_max)


def fingerprint() -> Dict[str, Any]:
    py_max, py_n, rules_max = _stamp()
    return {
        "py_mtime_ns": py_max,
        "py_files": py_n,
        "rules_mtime_ns": rules_max,
        "stamp": f"{py_max}:{py_n}:{rules_max}",
    }


def _safe_reload(modname: str) -> bool:
    mod = sys.modules.get(modname)
    if mod is None:
        try:
            importlib.import_module(modname)
            mod = sys.modules.get(modname)
        except Exception as e:
            print(f"[hot_reload] import {modname}: {e}")
            return False
    if mod is None:
        return False
    try:
        importlib.reload(mod)
        return True
    except Exception as e:
        print(f"[hot_reload] reload {modname}: {e}")
        return False


def _rebind_jobs() -> None:
    """jobs / server 顶部 from-import 会钉死旧函数；每次热加载后改绑。"""
    try:
        import backend.pipeline as pipe
        if "backend.jobs" in sys.modules:
            jobs_mod = sys.modules["backend.jobs"]
            jobs_mod.analyze_report = pipe.analyze_report
            jobs_mod.JobCancelled = pipe.JobCancelled
        # server.py 顶层 from backend.pipeline import analyze_report
        for name in ("server", "__main__"):
            mod = sys.modules.get(name)
            if mod is not None and hasattr(mod, "analyze_report"):
                setattr(mod, "analyze_report", pipe.analyze_report)
    except Exception as e:
        print(f"[hot_reload] rebind: {e}")


def ensure_fresh_analysis(force: bool = False) -> Dict[str, Any]:
    """若分析代码或规则文件变更则热加载。可在任意分析任务开头调用。"""
    global _last_stamp, _primed
    cur = _stamp()
    with _lock:
        if not _primed:
            force = True
            _primed = True
        if not force and _last_stamp == cur:
            return {
                "reloaded_code": False,
                "reloaded_rules": False,
                "fingerprint": fingerprint(),
            }
        old = _last_stamp
        py_changed = force or old is None or old[0] != cur[0] or old[1] != cur[1]
        rules_changed = force or old is None or old[2] != cur[2]

        reloaded: List[str] = []
        if py_changed:
            for name in _MATCHER_MODS + _CORE_MODS:
                if _safe_reload(name):
                    reloaded.append(name)
            _rebind_jobs()

        rules_ok = False
        if rules_changed or py_changed:
            try:
                from .rules_loader import reload_store
                reload_store()
                rules_ok = True
            except Exception as e:
                print(f"[hot_reload] reload_store: {e}")

        _last_stamp = cur
        info = {
            "reloaded_code": bool(py_changed and reloaded),
            "reloaded_rules": bool(rules_ok and (rules_changed or force)),
            "modules": reloaded,
            "fingerprint": fingerprint(),
        }
        if info["reloaded_code"] or info["reloaded_rules"]:
            print(
                f"[hot_reload] code={info['reloaded_code']} rules={info['reloaded_rules']} "
                f"mods={len(reloaded)} stamp={info['fingerprint'].get('stamp')}"
            )
        return info
