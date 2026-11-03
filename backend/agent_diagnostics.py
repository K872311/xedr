# -*- coding: utf-8 -*-
"""Agent 诊断包持久化与下载（collect_diagnostics 回执）。"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from . import config


def _root() -> Path:
    root = Path(getattr(config, "REPORTS_DIR", "") or Path(__file__).resolve().parent.parent / "data")
    d = root / "agent_diagnostics"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_name(name: str) -> str:
    name = str(name or "diagnostics.zip").strip()
    name = re.sub(r"[^\w.\-]+", "_", name)[:120]
    return name or "diagnostics.zip"


def persist_from_command_result(
    agent_id: str,
    command_id: str,
    result: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """将 result 中的 content_base64 落盘，返回可写入 DB 的精简 result（无 base64）。"""
    if not isinstance(result, dict):
        return result
    b64 = result.get("content_base64")
    if not b64 or not isinstance(b64, str):
        return result
    try:
        raw = base64.b64decode(b64, validate=False)
    except Exception:
        return result
    if len(raw) < 32:
        return result
    aid = str(agent_id or "unknown").strip()
    cid = str(command_id or "cmd").strip()
    fn = _safe_name(str(result.get("filename") or f"forensic-agent-diag-{cid}.zip"))
    dest_dir = _root() / aid
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / f"{cid}_{fn}"
    path.write_bytes(raw)
    slim = {k: v for k, v in result.items() if k != "content_base64"}
    slim.update({
        "stored": True,
        "size": len(raw),
        "filename": fn,
        "download_command_id": cid,
    })
    return slim


def resolve_download_path(agent_id: str, command_id: str) -> Optional[Path]:
    aid = str(agent_id or "").strip()
    cid = str(command_id or "").strip()
    if not aid or not cid:
        return None
    d = _root() / aid
    if not d.is_dir():
        return None
    for p in sorted(d.glob(f"{cid}_*"), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file() and p.stat().st_size > 0:
            return p
    return None


def get_command_result_meta(agent_id: str, command_id: str) -> Dict[str, Any]:
    from . import agent_edr

    agent_edr.ensure()
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            row = conn.execute(
                "SELECT id, agent_id, action, status, result_json, acked_at FROM agent_commands WHERE id=?",
                (command_id,),
            ).fetchone()
        finally:
            conn.close()
    if not row:
        return {"ok": False, "error": "指令不存在"}
    if str(row["agent_id"]) != str(agent_id):
        return {"ok": False, "error": "指令不属于该终端", "forbidden": True}
    try:
        result = json.loads(row["result_json"] or "{}")
    except Exception:
        result = {}
    path = resolve_download_path(agent_id, command_id)
    return {
        "ok": True,
        "command_id": command_id,
        "agent_id": agent_id,
        "action": row["action"],
        "status": row["status"],
        "acked_at": row["acked_at"],
        "result": result,
        "download_ready": path is not None and row["status"] == "done",
        "download_path": str(path) if path else "",
    }


def read_download_bytes(agent_id: str, command_id: str) -> Tuple[Optional[bytes], str, Optional[str]]:
    path = resolve_download_path(agent_id, command_id)
    if not path:
        return None, "", "诊断文件不存在或尚未回传"
    name = path.name
    if "_" in name:
        name = name.split("_", 1)[1]
    return path.read_bytes(), name, None


def list_diagnostics(agent_id: str = "", limit: int = 50) -> Dict[str, Any]:
    """诊断包历史（落盘文件 + collect_diagnostics 指令）。"""
    from . import agent_edr

    agent_edr.ensure()
    aid = str(agent_id or "").strip()
    limit = max(1, min(int(limit or 50), 200))
    items: list = []
    root = _root()
    dirs = [root / aid] if aid else [p for p in root.iterdir() if p.is_dir()]
    for d in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True):
            if not p.is_file() or p.stat().st_size < 32:
                continue
            name = p.name
            cid = name.split("_", 1)[0] if "_" in name else ""
            items.append({
                "agent_id": d.name,
                "command_id": cid,
                "filename": name.split("_", 1)[1] if "_" in name else name,
                "size": p.stat().st_size,
                "mtime": int(p.stat().st_mtime),
                "download_ready": True,
            })
            if len(items) >= limit:
                break
        if len(items) >= limit:
            break
    return {"ok": True, "items": items[:limit], "total": len(items)}
