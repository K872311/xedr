"""告警待审：命中默认 pending，人接受才算结论，排除不进默认列表。"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List

from . import paths as P

STATUSES = ("pending", "accepted", "rejected")


def finding_id(item: Dict[str, Any]) -> str:
    raw = str(item.get("id") or "").strip()
    if raw and len(raw) <= 200:
        return raw
    blob = "|".join(
        [
            str(item.get("category") or item.get("type") or ""),
            str(item.get("title") or item.get("name") or ""),
            str(item.get("rule_id") or ""),
            str(item.get("matcher") or ""),
        ]
    )
    if len(blob) <= 160:
        return blob or hashlib.sha1(repr(item).encode("utf-8", errors="replace")).hexdigest()[:16]
    return hashlib.sha1(blob.encode("utf-8", errors="replace")).hexdigest()[:20]


def _path(report_file: str):
    return P.report_dir(report_file, create=True) / "finding_review.json"


def load_review(report_file: str) -> Dict[str, Dict[str, Any]]:
    p = _path(report_file)
    if not p.is_file():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        items = (data or {}).get("items") if isinstance(data, dict) else None
        if not isinstance(items, dict):
            return {}
        out: Dict[str, Dict[str, Any]] = {}
        for k, v in items.items():
            if isinstance(v, dict):
                out[str(k)] = v
        return out
    except Exception:
        return {}


def save_review(report_file: str, items: Dict[str, Dict[str, Any]]) -> None:
    p = _path(report_file)
    payload = {"updated_at": datetime.now().isoformat(timespec="seconds"), "items": items}
    with open(p, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def set_review(
    report_file: str,
    fid: str,
    status: str,
    note: str = "",
    user: str = "",
) -> Dict[str, Any]:
    st = (status or "pending").strip().lower()
    if st not in STATUSES:
        raise ValueError("状态须为 pending / accepted / rejected")
    fid = str(fid or "").strip()
    if not fid:
        raise ValueError("缺少告警 id")
    items = load_review(report_file)
    row = {
        "status": st,
        "note": (note or "")[:300],
        "by": (user or "")[:64],
        "at": datetime.now().isoformat(timespec="seconds"),
    }
    items[fid] = row
    save_review(report_file, items)
    return row


def review_of(item: Dict[str, Any], items: Dict[str, Dict[str, Any]]) -> str:
    fid = finding_id(item)
    row = items.get(fid) or {}
    st = str(row.get("status") or "pending").lower()
    return st if st in STATUSES else "pending"


def attach_review(findings: List[Dict[str, Any]], report_file: str = "") -> List[Dict[str, Any]]:
    items = load_review(report_file) if report_file else {}
    out: List[Dict[str, Any]] = []
    try:
        from .text_fix import fix_finding_dict
    except Exception:
        fix_finding_dict = lambda x: x  # type: ignore
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        row = fix_finding_dict(dict(f))
        fid = finding_id(row)
        row["id"] = fid
        rv = items.get(fid) or {}
        row["review_status"] = str(rv.get("status") or "pending")
        row["review_note"] = rv.get("note") or ""
        out.append(row)
    try:
        from . import bw_list
        out = bw_list.apply_to_finding_dicts(out)
    except Exception:
        pass
    return out


def findings_for_ai(analysis: Dict[str, Any], report_file: str = "") -> List[Dict[str, Any]]:
    """AI 只吃未排除的命中：已确认优先，否则待审。无命中则空列表（不盲扫原文）。"""
    raw = analysis.get("findings_aggregated") or analysis.get("findings") or []
    if not isinstance(raw, list):
        raw = []
    attached = attach_review([x for x in raw if isinstance(x, dict)], report_file)
    kept = [f for f in attached if (f.get("review_status") or "pending") != "rejected"]
    accepted = [f for f in kept if f.get("review_status") == "accepted"]
    return accepted or kept
