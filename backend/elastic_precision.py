# -*- coding: utf-8 -*-
"""Elastic 规则 → Agent EVM：高精准子集筛选（剔除高误报转换）。"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config
from . import elastic_detection_import as edi

_RULES = Path(config.RULES_DIR)
_CONFIG = Path(config.ROOT) / "config"
_ALLOWLIST = _CONFIG / "elastic_precision_allowlist.json"

_GENERIC_EXE = frozenset(
    """
    powershell.exe cmd.exe rundll32.exe mshta.exe wscript.exe cscript.exe
    chrome.exe msedge.exe brave.exe python.exe node.exe curl.exe java.exe javaw.exe
    bitsadmin.exe regsvr32.exe dllhost.exe msiexec.exe pwsh.exe explorer.exe
    svchost.exe conhost.exe winrar.exe 7z.exe
    """.split()
)

_SPECIFIC_HINTS = (
    "mimikatz", "procdump", "certutil", "vssadmin", "bcdedit", "wevtutil", "nltest",
    "psexec", "cobalt", "empire", "bloodhound", "rubeus", "sharphound", "lsass",
    "-ma", "-decode", "-nop", "-w hidden", "-enc", "bypass", "sam.hiv", "ntds.dit",
    "autoruns", "nanodump", "dcomlaunch", "wmic", "msbuild", "installutil",
)


def _noise_level(tags: Any) -> str:
    for t in tags or []:
        s = str(t or "").strip().lower()
        if s.startswith("noise:"):
            return s.split(":", 1)[-1].strip()
    return ""


def _tag_blob(tags: Any) -> str:
    return " ".join(str(t or "").lower() for t in (tags or []))


def score_elastic_rule(rule: Dict[str, Any], *, rel_path: str = "") -> Tuple[int, List[str]]:
    """分数越高越适合 Agent 子串 EVM；返回 (score, reasons)。"""
    reasons: List[str] = []
    q = str(rule.get("query") or "")
    tags = rule.get("tags")
    tb = _tag_blob(tags)
    n = _noise_level(tags)

    if n == "high":
        return 0, ["noise:high"]
    if "profile: aggressive" in tb:
        return 0, ["profile:aggressive"]
    if edi._query_needs_telemetry_only(q):
        return 0, ["telemetry_only"]

    cr = edi.convert_elastic_rule(rule, rel_path=rel_path)
    if cr.status != "convertible" or not cr.evm_rule:
        return 0, ["not_convertible_evm"]

    evm = cr.evm_rule
    et = str(evm.get("etype") or "")
    if et == "fim_add":
        return 0, ["wrong_channel_fim"]

    pats = [str(p).strip() for p in (evm.get("patterns") or []) if str(p).strip()]
    if not pats:
        return 0, ["no_patterns"]

    head = pats[: min(8, len(pats))]
    if all(
        pl.lower().replace("*", "") in _GENERIC_EXE or len(pl) <= 5
        for pl in head
    ):
        return 0, ["generic_lolbin_only"]

    score = 0
    if n == "low":
        score += 35
        reasons.append("noise:low")
    elif n == "medium":
        score += 12
        reasons.append("noise:medium")
    if "profile: recommended" in tb:
        score += 15
        reasons.append("profile:recommended")
    if et in ("process_create", "registry_set", "dns_query", "win_logon_fail"):
        score += 22
        reasons.append(f"etype:{et}")
    elif et == "network_connect":
        score += 5
        reasons.append("etype:network_connect")
    if evm.get("building_block"):
        score -= 10
        reasons.append("building_block:-10")

    for pl in pats:
        low = pl.lower()
        if any(h in low for h in _SPECIFIC_HINTS):
            score += 28
            reasons.append(f"specific:{pl[:40]}")
            break
        if low.endswith(".exe") and low not in _GENERIC_EXE:
            score += 8

    return score, reasons


def pick_precision_rule_ids(
    *,
    platform: str = "windows",
    min_score: int = 100,
    max_rules: int = 20,
    extra_ids: Optional[List[str]] = None,
) -> List[str]:
    cat = edi.load_catalog()
    items = [
        x for x in (cat.get("items") or [])
        if str(x.get("status") or "") == "convertible"
        and (not platform or str(x.get("platform") or "").lower() == platform.lower())
    ]
    scored: List[Tuple[int, str, str]] = []
    for it in items:
        rel = str(it.get("rel_path") or "")
        p = _RULES / rel.replace("/", "\\")
        if not p.is_file():
            continue
        doc = edi._parse_toml(p)
        if not doc or not isinstance(doc.get("rule"), dict):
            continue
        rule = doc["rule"]
        sc, _ = score_elastic_rule(rule, rel_path=rel)
        rid = str(it.get("id") or edi._elastic_id(rule, rel)).strip()
        if sc >= min_score and rid:
            scored.append((sc, rid, str(rule.get("name") or "")[:80]))

    scored.sort(key=lambda x: (-x[0], x[1]))
    out: List[str] = []
    seen = set()
    for eid in extra_ids or []:
        s = str(eid or "").strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    for _, rid, _ in scored:
        if rid in seen:
            continue
        seen.add(rid)
        out.append(rid)
        if len(out) >= max_rules:
            break
    return out[:max_rules]


def build_precision_evm_document(
    *,
    rule_ids: Optional[List[str]] = None,
    enabled: bool = True,
    min_score: int = 100,
    max_rules: int = 20,
) -> Dict[str, Any]:
    allow = {}
    if _ALLOWLIST.is_file():
        try:
            allow = json.loads(_ALLOWLIST.read_text(encoding="utf-8"))
        except Exception:
            allow = {}
    extra = list(allow.get("always_include") or [])
    exclude = {str(x).strip() for x in (allow.get("exclude") or []) if str(x).strip()}

    min_sc = int(allow.get("min_score") or min_score)
    force = {str(x).strip() for x in extra if str(x).strip()}
    ids = rule_ids or pick_precision_rule_ids(
        min_score=min_sc,
        max_rules=int(allow.get("max_rules") or max_rules),
        extra_ids=extra,
    )
    ids = [i for i in ids if i not in exclude]

    rules: List[Dict[str, Any]] = []
    for rid in ids:
        found = edi._find_toml_by_elastic_id(rid)
        if not found:
            continue
        path, rule = found
        try:
            rel = str(path.relative_to(_RULES)).replace("\\", "/")
        except ValueError:
            rel = path.name
        sc, _ = score_elastic_rule(rule, rel_path=rel)
        if sc < min_sc and rid not in force:
            continue
        cr = edi.convert_elastic_rule(rule, rel_path=rel)
        if not cr.evm_rule:
            continue
        evm = dict(cr.evm_rule)
        evm["enabled"] = bool(enabled)
        evm["precision_score"] = sc
        evm["building_block"] = False
        rules.append(evm)

    return {
        "version": 2,
        "profile": "precision",
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "min_score": int(allow.get("min_score") or min_score),
        "rule_ids": ids,
        "rules": rules,
    }


def apply_precision_evm(*, enabled: bool = True, write: bool = True) -> Dict[str, Any]:
    doc = build_precision_evm_document(enabled=enabled)
    path = _CONFIG / "elastic_evm_import.json"
    if write:
        _CONFIG.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            from . import agent_sync
            agent_sync.bump_sync("evm")
        except Exception:
            pass
    return {"ok": True, "path": str(path), "count": len(doc.get("rules") or []), "ids": doc.get("rule_ids")}


def prune_agent_live_elastic(*, write: bool = True) -> Dict[str, Any]:
    """从 agent-live-rules 移除 Elastic 快照近似规则（保留自定义与内置）。"""
    from . import agent_rules as ar

    p = ar._path()
    if not p.is_file():
        return {"ok": True, "removed": 0}
    doc = json.loads(p.read_text(encoding="utf-8"))
    rules = doc.get("rules") or []
    kept = []
    removed = 0
    for r in rules:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id") or "")
        if rid.startswith("elastic-") or ar.is_elastic_rule(r):
            removed += 1
            continue
        kept.append(r)
    if write and removed:
        doc["rules"] = kept
        p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            from . import agent_protocol, agent_sync
            agent_protocol.bump_live("rules")
            agent_sync.bump_sync("rules")
        except Exception:
            pass
    return {"ok": True, "removed": removed, "kept": len(kept)}
