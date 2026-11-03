"""采集报告金库：落盘时算 SHA256，读前可校验。原文仍在 reports/<stem>/report.json。"""
from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from . import config
from . import paths as P

_CHUNK = 1024 * 1024


def vault_root() -> Path:
    d = config.REPORTS_DIR / "_vault"
    d.mkdir(parents=True, exist_ok=True)
    return d


def manifest_path(report_file: str) -> Path:
    return P.report_dir(report_file, create=False) / "manifest.json"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _vault_blob(sha: str) -> Path:
    return vault_root() / sha[:2] / sha


def seal_report(report_file: str, source: str = "") -> Dict[str, Any]:
    """对已落盘的 report.json 计算哈希，写 manifest，并镜像一份到 _vault。"""
    rid = P.report_id(report_file)
    rp = P.resolve_report_json(rid)
    out: Dict[str, Any] = {"file": rid, "ok": False, "sha256": "", "source": source or ""}
    if not rp or not rp.is_file():
        out["error"] = "报告原文不存在"
        return out
    sha = _sha256_file(rp)
    size = rp.stat().st_size
    dest = _vault_blob(sha)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        try:
            shutil.copy2(rp, dest)
        except OSError as e:
            out["error"] = f"金库写入失败: {e}"
    man = {
        "file": rid,
        "sha256": sha,
        "size": size,
        "source": source or "",
        "sealed_at": datetime.now().isoformat(timespec="seconds"),
        "vault_rel": f"_vault/{sha[:2]}/{sha}",
    }
    mp = P.report_dir(rid, create=True) / "manifest.json"
    try:
        with open(mp, "w", encoding="utf-8") as f:
            json.dump(man, f, ensure_ascii=False, indent=2)
    except OSError as e:
        out["error"] = f"manifest 写入失败: {e}"
        return out
    out.update(man)
    out["ok"] = True
    return out


def load_manifest(report_file: str) -> Optional[Dict[str, Any]]:
    p = manifest_path(report_file)
    if not p.is_file():
        return None
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def verify_report(report_file: str) -> Dict[str, Any]:
    """读前校验：现算哈希 vs manifest。无 manifest 则只算哈希（不视为失败）。"""
    rid = P.report_id(report_file)
    rp = P.resolve_report_json(rid)
    out: Dict[str, Any] = {
        "file": rid,
        "ok": False,
        "sha256": "",
        "expected": "",
        "verified": False,
        "has_manifest": False,
    }
    if not rp or not rp.is_file():
        out["error"] = "报告原文不存在"
        return out
    sha = _sha256_file(rp)
    out["sha256"] = sha
    man = load_manifest(rid)
    if not man:
        out["ok"] = True
        out["note"] = "尚无入库清单，已计算当前哈希"
        return out
    out["has_manifest"] = True
    expected = str(man.get("sha256") or "")
    out["expected"] = expected
    out["sealed_at"] = man.get("sealed_at") or ""
    out["source"] = man.get("source") or ""
    if expected and expected != sha:
        out["error"] = "哈希与入库清单不一致，原文可能被改动"
        return out
    blob = _vault_blob(expected or sha)
    if blob.is_file():
        vsha = _sha256_file(blob)
        if vsha != sha:
            out["error"] = "金库副本与当前原文不一致"
            return out
        out["vault"] = True
    out["ok"] = True
    out["verified"] = bool(expected)
    return out
