# -*- coding: utf-8 -*-
"""Wazuh ruleset（rules/ruleset）：SCA YAML 目录 + Agent 可执行检查包。

- sca/**/*.yml：CIS 等合规检查（Wazuh SCA 语法子集）
- mitre/enterprise-attack.json：ATT&CK 语料（与 backend/mitre 互补）
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from . import config

RULESET_ROOT = Path(config.RULES_DIR) / "ruleset"
SCA_ROOT = RULESET_ROOT / "sca"
MITRE_JSON = RULESET_ROOT / "mitre" / "enterprise-attack.json"
_PUBLISHED = Path(config.RULES_DIR) / "published"
_CATALOG_NAME = "wazuh-sca-catalog.json"
_BUNDLE_CONFIG = Path(config.ROOT) / "config" / "agent_sca_bundle.json"

_RE_RULE_PREFIX = re.compile(r"^\s*(not\s+)?([rcfdp]:)", re.I)


def iter_sca_yml(*, platform: str = "") -> Iterable[Path]:
    if not SCA_ROOT.is_dir():
        return
    plat = str(platform or "").strip().lower()
    if plat:
        root = SCA_ROOT / plat
        if root.is_dir():
            yield from sorted(root.rglob("*.yml"))
        return
    yield from sorted(SCA_ROOT.rglob("*.yml"))


def _platform_from_path(path: Path) -> str:
    try:
        rel = path.relative_to(SCA_ROOT)
        return rel.parts[0] if rel.parts else "unknown"
    except ValueError:
        return "unknown"


def classify_rule_expr(expr: str) -> str:
    s = str(expr or "").strip().strip("'\"")
    m = _RE_RULE_PREFIX.match(s)
    if not m:
        return "other"
    kind = m.group(2).lower()
    if kind == "r:":
        return "registry"
    if kind == "c:":
        if len(s) > 900:
            return "heavy_command"
        return "command"
    if kind in ("f:", "d:", "p:"):
        return "unsupported"
    return "other"


def _normalize_rules(raw: Any) -> List[str]:
    if not isinstance(raw, list):
        return []
    out: List[str] = []
    for x in raw:
        s = str(x or "").strip()
        if s:
            out.append(s)
    return out


def _mitre_summary(block: Any) -> List[str]:
    if not isinstance(block, dict):
        return []
    out: List[str] = []
    for key in ("technique", "subtechnique"):
        sub = block.get(key)
        if isinstance(sub, dict):
            for tid in sub.get("id") or []:
                out.append(str(tid))
    return out[:6]


def parse_sca_file(path: Path) -> Optional[Dict[str, Any]]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    pol = doc.get("policy") if isinstance(doc.get("policy"), dict) else {}
    reqs = doc.get("requirements") if isinstance(doc.get("requirements"), dict) else {}
    checks_raw = doc.get("checks") if isinstance(doc.get("checks"), list) else []
    stats = {"registry": 0, "command": 0, "heavy_command": 0, "unsupported": 0, "other": 0, "agent_capable": 0}
    checks_out: List[Dict[str, Any]] = []
    for ch in checks_raw:
        if not isinstance(ch, dict):
            continue
        rules = _normalize_rules(ch.get("rules"))
        kinds = [classify_rule_expr(r) for r in rules]
        for k in kinds:
            stats[k] = stats.get(k, 0) + 1
        capable = all(k in ("registry", "command") for k in kinds) and bool(rules)
        if capable:
            stats["agent_capable"] += 1
        checks_out.append({
            "id": ch.get("id"),
            "name": str(ch.get("name") or "")[:240],
            "condition": str(ch.get("condition") or "all").lower(),
            "rule_kinds": kinds,
            "agent_capable": capable,
            "mitre": _mitre_summary(ch.get("mitre")),
        })
    req_rules = _normalize_rules(reqs.get("rules"))
    return {
        "policy_id": str(pol.get("id") or path.stem),
        "name": str(pol.get("name") or path.stem)[:200],
        "file": str(path.relative_to(RULESET_ROOT)).replace("\\", "/"),
        "platform": _platform_from_path(path),
        "check_count": len(checks_out),
        "agent_capable_checks": sum(1 for c in checks_out if c.get("agent_capable")),
        "requirement_rules": len(req_rules),
        "stats": stats,
        "checks_preview": checks_out[:8],
    }


def scan_catalog(*, platform: str = "", max_files: int = 0) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    for i, path in enumerate(iter_sca_yml(platform=platform)):
        if max_files and i >= max_files:
            break
        row = parse_sca_file(path)
        if row:
            items.append(row)
    return {
        "ok": True,
        "version": 1,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ruleset_root": str(RULESET_ROOT),
        "mitre_enterprise_json": str(MITRE_JSON) if MITRE_JSON.is_file() else "",
        "stats": {
            "policies": len(items),
            "agent_capable_checks": sum(int(x.get("agent_capable_checks") or 0) for x in items),
        },
        "items": items,
    }


def save_catalog(catalog: Optional[Dict[str, Any]] = None) -> Path:
    cat = catalog or scan_catalog()
    _PUBLISHED.mkdir(parents=True, exist_ok=True)
    p = _PUBLISHED / _CATALOG_NAME
    p.write_text(json.dumps(cat, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return p


def load_catalog() -> Dict[str, Any]:
    p = _PUBLISHED / _CATALOG_NAME
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return scan_catalog()


def _load_sca_doc(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _find_policy_yaml(policy_id: str) -> Optional[Path]:
    pid = str(policy_id or "").strip()
    if not pid:
        return None
    for path in iter_sca_yml():
        doc = _load_sca_doc(path)
        if not doc or not isinstance(doc.get("policy"), dict):
            continue
        if str(doc["policy"].get("id") or path.stem) == pid:
            return path
    return None


def _extract_agent_check(ch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rules = _normalize_rules(ch.get("rules"))
    if not rules:
        return None
    kinds = [classify_rule_expr(r) for r in rules]
    if not all(k in ("registry", "command") for k in kinds):
        return None
    return {
        "id": ch.get("id"),
        "title": str(ch.get("name") or "")[:240],
        "condition": str(ch.get("condition") or "all").lower(),
        "rules": [{"kind": classify_rule_expr(r), "expr": r} for r in rules],
        "mitre": _mitre_summary(ch.get("mitre")),
    }


def build_agent_bundle(
    policy_ids: Optional[List[str]] = None,
    *,
    platform: str = "windows",
    max_checks_per_policy: int = 0,
    agent_capable_only: bool = True,
) -> Dict[str, Any]:
    """生成下发 Agent 的 SCA JSON（注册表 + 轻量命令）。"""
    want = [str(x).strip() for x in (policy_ids or []) if str(x).strip()]
    if not want:
        want = [
            "cis_win10_enterprise",
            "cis_win11_enterprise",
        ]
    policies_out: List[Dict[str, Any]] = []
    for pid in want:
        path = _find_policy_yaml(pid)
        if not path:
            continue
        doc = _load_sca_doc(path)
        if not doc:
            continue
        pol = doc.get("policy") if isinstance(doc.get("policy"), dict) else {}
        reqs = doc.get("requirements") if isinstance(doc.get("requirements"), dict) else {}
        req_rules = _normalize_rules(reqs.get("rules"))
        req_out = []
        for r in req_rules:
            k = classify_rule_expr(r)
            if k in ("registry", "command"):
                req_out.append({"kind": k, "expr": r})
        checks: List[Dict[str, Any]] = []
        for ch in doc.get("checks") or []:
            if not isinstance(ch, dict):
                continue
            row = _extract_agent_check(ch)
            if not row and agent_capable_only:
                continue
            if row:
                checks.append(row)
        if max_checks_per_policy > 0 and len(checks) > max_checks_per_policy:
            checks = checks[:max_checks_per_policy]
        if not checks and not req_out:
            continue
        policies_out.append({
            "id": str(pol.get("id") or pid),
            "name": str(pol.get("name") or pid)[:200],
            "platform": _platform_from_path(path),
            "requirements": req_out,
            "checks": checks,
        })
    plat = str(platform or "").strip().lower()
    if plat:
        policies_out = [p for p in policies_out if str(p.get("platform") or "").lower() == plat]
    return {
        "version": 1,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": "wazuh_ruleset",
        "max_checks_per_run": 48,
        "policies": policies_out,
    }


def _sca_policy_prefs() -> Tuple[List[str], int, int]:
    policy_ids: List[str] = []
    max_per = 0
    max_run = 48
    try:
        from . import agent_edr

        pol = agent_edr.get_policy("global").get("policy") or {}
        sca = pol.get("sca") if isinstance(pol.get("sca"), dict) else {}
        raw = sca.get("policies")
        if isinstance(raw, list):
            policy_ids = [str(x).strip() for x in raw if str(x).strip()]
        max_per = int(sca.get("max_checks_per_policy") or 0)
        max_run = int(sca.get("max_checks_per_run") or 48)
    except Exception:
        pass
    return policy_ids, max_per, max_run


def export_agent_bundle_document() -> Dict[str, Any]:
    policy_ids, max_per, max_run = _sca_policy_prefs()
    if _BUNDLE_CONFIG.is_file() and not policy_ids:
        try:
            doc = json.loads(_BUNDLE_CONFIG.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and doc.get("policies"):
                if max_run and int(doc.get("max_checks_per_run") or 0) != max_run:
                    doc["max_checks_per_run"] = max_run
                return doc
        except Exception:
            pass
    doc = build_agent_bundle(
        policy_ids=policy_ids or None,
        max_checks_per_policy=max_per,
    )
    doc["max_checks_per_run"] = max_run
    return doc


def save_agent_bundle(doc: Optional[Dict[str, Any]] = None) -> Path:
    body = doc or build_agent_bundle(max_checks_per_policy=0)
    _BUNDLE_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    _BUNDLE_CONFIG.write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return _BUNDLE_CONFIG


def mitre_enterprise_path() -> str:
    return str(MITRE_JSON) if MITRE_JSON.is_file() else ""
