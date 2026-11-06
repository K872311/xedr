# -*- coding: utf-8 -*-
"""扫描 agent_events 详情丰富度，模拟 UI 可读字段。"""
import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "reports" / "agents.db"

USEFUL_KEYS = frozenset({
    "path", "command_line", "matched", "chain", "rule_id", "rule_title",
    "key", "reg_key", "value", "value_name", "remote", "domain", "summary",
    "source_summary", "evidence", "ioc_value", "script_block", "name", "image",
    "failed", "checks", "items",
})


def detail_score(raw: str) -> int:
    if not raw:
        return 0
    try:
        o = json.loads(raw) if str(raw).lstrip().startswith("{") else None
    except ValueError:
        return max(1, len(str(raw)) // 10)
    if not isinstance(o, dict):
        return 1
    n = 0
    for k, v in o.items():
        if v in (None, "", [], {}):
            continue
        n += 2
        if isinstance(v, dict):
            n += sum(1 for x in v.values() if x not in (None, "", [], {}))
        elif isinstance(v, list) and v:
            n += min(len(v), 5) * 2
        elif isinstance(v, str) and len(v) > 20:
            n += 1
    return n


def ui_thin(d: dict) -> bool:
    if not isinstance(d, dict) or not d:
        return True
    et = str(d.get("etype") or "")
    if d.get("matched") or d.get("command_line") or d.get("chain"):
        return False
    if d.get("path") or d.get("reg_key") or d.get("key") or d.get("remote") or d.get("ioc_value"):
        return False
    if d.get("evidence") and isinstance(d["evidence"], dict):
        ev = d["evidence"]
        if any(ev.get(k) for k in USEFUL_KEYS):
            return False
    # only rule_id / etype
    keys = {k for k, v in d.items() if v not in (None, "", [], {})}
    if keys <= {"etype", "rule_id", "rule_title", "title", "rule_source", "building_block", "count", "failed", "steps", "window_sec", "first"}:
        return True
    if et in ("ptm_hit", "evm_hit") and not d.get("matched") and not d.get("chain"):
        return True
    return False


def title_bucket(t: str) -> str:
    t = str(t or "")
    m = re.match(r"^(PTM|EVM|LOLBin|规则命中|IOC|Elastic|Protections|SCA|FIM|注册表)[：:]", t)
    if m:
        return m.group(1) + "：…"
    return (t[:36] + "…") if len(t) > 36 else t


def main():
    if not DB.is_file():
        print("no db", DB)
        return 1
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM agent_events ORDER BY id DESC").fetchall()
    thin_ui = []
    by_bucket = Counter()
    for r in rows:
        raw = r["detail"] or ""
        try:
            d = json.loads(raw) if raw.lstrip().startswith("{") else {}
        except ValueError:
            d = {}
        if ui_thin(d):
            b = title_bucket(r["title"])
            by_bucket[b] += 1
            thin_ui.append({
                "id": r["id"], "title": r["title"], "module": r["module"],
                "score": detail_score(raw), "keys": list(d.keys()), "etype": d.get("etype"),
            })
    print(f"total={len(rows)} ui_thin={len(thin_ui)}")
    print("\n--- UI 认为缺详情 (by bucket) ---")
    for b, c in by_bucket.most_common():
        print(f"  {c:3d}  {b}")
    print("\n--- 全部缺详情条目 ---")
    for x in thin_ui:
        print(json.dumps(x, ensure_ascii=False))
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
