#!/usr/bin/env python3
"""校验 rules/*.json 与 config/correlation_rules.json（schema / 严重级别 / MITRE）。"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
CORR = ROOT / "config" / "correlation_rules.json"

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RISK_BANDS = {
    "low": (0, 21),
    "medium": (22, 47),
    "high": (48, 73),
    "critical": (74, 100),
}
MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)


def err(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)


def load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        err(f"{p}: {e}")
        return None


def check_risk_score(severity: str, risk: int, ctx: str) -> bool:
    sev = str(severity or "medium").lower()
    lo, hi = RISK_BANDS.get(sev, (0, 100))
    if not (lo <= int(risk) <= hi):
        err(f"{ctx}: risk_score {risk} 与 severity {sev} 不匹配（期望 {lo}-{hi}）")
        return False
    return True


def walk_agent_live(data, path: Path) -> int:
    n = 0
    rules = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(rules, list):
        return 0
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            continue
        rid = r.get("id") or f"#{i}"
        sev = r.get("severity") or "medium"
        if sev not in SEV_RANK:
            err(f"{path} rule {rid}: 非法 severity {sev}")
            n += 1
        rs = r.get("risk_score")
        if rs is not None and not check_risk_score(sev, int(rs), f"{path} {rid}"):
            n += 1
        for t in r.get("mitre") or []:
            if t and not MITRE_RE.match(str(t)):
                err(f"{path} rule {rid}: 非法 MITRE {t}")
                n += 1
    return n


def walk_task_rules(data, path: Path) -> int:
    n = 0
    for key in ("taskRules", "serviceRules", "startupRules", "registryRules", "fileRules"):
        arr = data.get(key) if isinstance(data, dict) else None
        if not isinstance(arr, list):
            continue
        for r in arr:
            if not isinstance(r, dict):
                continue
            rid = r.get("id") or "?"
            sev = r.get("severity") or "medium"
            if sev not in SEV_RANK:
                err(f"{path} {rid}: 非法 severity")
                n += 1
            for t in r.get("mitre") or []:
                if t and not MITRE_RE.match(str(t)):
                    err(f"{path} {rid}: 非法 MITRE {t}")
                    n += 1
    return n


def validate_correlation() -> int:
    n = 0
    data = load_json(CORR)
    if not isinstance(data, dict):
        return 1
    for r in data.get("rules") or []:
        if not isinstance(r, dict):
            continue
        rid = r.get("id")
        if not rid:
            err("correlation_rules: 缺少 id")
            n += 1
            continue
        rtype = str(r.get("type") or "frequency")
        if rtype not in ("frequency", "sequence", "first_seen"):
            err(f"correlation {rid}: 未知 type {rtype}")
            n += 1
        if rtype == "sequence" and len(r.get("steps") or []) < 2:
            err(f"correlation {rid}: sequence 至少 2 步")
            n += 1
    return n


def main() -> int:
    errors = validate_correlation()
    for p in sorted(RULES_DIR.glob("*.json")):
        if p.name.startswith("."):
            continue
        data = load_json(p)
        if data is None:
            errors += 1
            continue
        if "taskRules" in data or "serviceRules" in data:
            errors += walk_task_rules(data, p)
        elif isinstance(data, dict) and "rules" in data:
            errors += walk_agent_live(data, p)
    if errors:
        print(f"校验失败：{errors} 个问题", file=sys.stderr)
        return 1
    print("规则校验通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
