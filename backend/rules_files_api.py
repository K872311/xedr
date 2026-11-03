"""规则 JSON 文件：白名单在线查看/编辑（落盘，带备份）。"""
from __future__ import annotations
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from . import config

# 允许编辑的文件（体积相对可控、结构常用）
EDITABLE: Set[str] = {
    "rules-simple.json",
    "rules-files.json",
    "rules-folders.json",
    "rules-keywords.json",
    "rules-ioc.json",
}

# 允许查看（含只读大文件 / partial）
VIEWABLE: Set[str] = EDITABLE | {
    "rules-interesting-files.json",
    "rules-wininfosc.json",
    "rules-windows-system.json",
    "rules-linux-system.json",
    "rules-linux-sigma.json",
    "rules-linux-signatures.json",
    "rules-linux-process.json",
    "rules-linux-network.json",
    "rules-linux-kernel.json",
    "rules-linux-persistence.json",
    "rules-tools_rules.json",
    "rules-high-risk.json",
    "rules-windows-process.json",
    "rules-browsers.json",
    "rules-file-types.json",
    "rules-encryption.json",
    "rules-email.json",
    "rules-timeline.json",
    "rules-yara-hash.json",
    "rules-central-repo.json",
    "rules-dftimewolf.json",
}

_MAX_EDIT_BYTES = 2 * 1024 * 1024  # 编辑上限 2MB
_MAX_VIEW_BYTES = 8 * 1024 * 1024  # 查看上限 8MB


def _safe_name(name: str) -> str:
    n = (name or "").strip().replace("\\", "/").split("/")[-1]
    if not n or not n.startswith("rules-") or not n.endswith(".json"):
        raise ValueError("非法规则文件名")
    if ".." in n or "/" in n:
        raise ValueError("非法规则文件名")
    return n


def resolve_rule_file(name: str) -> Path:
    n = _safe_name(name)
    # 与 RuleStore 相同搜索顺序（含 rules/linux/）
    for base in (Path(config.RULES_DIR), Path(config.ROOT)):
        for cand in (base / n, base / "linux" / n):
            if cand.is_file():
                return cand.resolve()
    # 默认落在 RULES_DIR（新建用）
    return (Path(config.RULES_DIR) / n).resolve()


def file_flags(name: str) -> Dict[str, bool]:
    try:
        n = _safe_name(name)
    except ValueError:
        return {"viewable": False, "editable": False}
    exists = resolve_rule_file(n).is_file()
    return {"viewable": exists, "editable": exists and n in EDITABLE}


def inventory_flags() -> Dict[str, Dict[str, bool]]:
    return {n: {"viewable": True, "editable": n in EDITABLE} for n in sorted(VIEWABLE)}


def read_rule_file(name: str) -> Dict[str, Any]:
    n = _safe_name(name)
    path = resolve_rule_file(n)
    if not path.is_file():
        raise ValueError("文件不存在")
    size = path.stat().st_size
    if size > _MAX_VIEW_BYTES:
        raise ValueError(f"文件过大（{size} 字节），请本地编辑")
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON 无效: {e}") from e
    return {
        "file": n,
        "path": str(path),
        "size": size,
        "editable": n in EDITABLE and size <= _MAX_EDIT_BYTES,
        "content": data,
        "raw": text,
    }


def _backup(path: Path) -> Optional[str]:
    bak_dir = path.parent / ".bak"
    bak_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    dest = bak_dir / f"{path.name}.{stamp}.bak"
    shutil.copy2(path, dest)
    # 只保留最近 20 个备份
    old = sorted(bak_dir.glob(f"{path.name}.*.bak"), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in old[20:]:
        try:
            p.unlink()
        except OSError:
            pass
    return str(dest)


def write_rule_file(name: str, payload: Any) -> Dict[str, Any]:
    n = _safe_name(name)
    if n not in EDITABLE:
        raise ValueError("该规则文件不允许在线编辑（仅支持白名单）")
    path = resolve_rule_file(n)
    path.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(payload, str):
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON 无效: {e}") from e
    elif isinstance(payload, dict):
        data = payload
    else:
        raise ValueError("内容须为 JSON 对象")

    if not isinstance(data, dict):
        raise ValueError("根节点必须是 JSON 对象 {}")

    raw = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if len(raw.encode("utf-8")) > _MAX_EDIT_BYTES:
        raise ValueError("保存后体积超过 2MB 上限")

    bak = None
    if path.is_file():
        bak = _backup(path)

    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass

    return {
        "ok": True,
        "file": n,
        "path": str(path),
        "backup": bak,
        "size": path.stat().st_size,
    }
