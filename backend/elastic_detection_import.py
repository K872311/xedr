# -*- coding: utf-8 -*-
"""Elastic detection-rules（rules/**/*.toml）→ 本平台的可执行规则。

策略（务实）：
- 全量 TOML 编入 catalog（检索 / MITRE / 说明），供控制台与狩猎参考；
- 对 EQL/KQL 中可抽取 IOC/路径/进程名的规则，生成 Agent 快照规则 + EVM 时间线规则；
- esql / new_terms / ML 等标记为 reference，不强行转换。
"""
from __future__ import annotations

import json
import re
import time
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from . import config

_SKIP_DIRS = frozenset({"_deprecated", "promotions", "ml", "apm", "integrations", "network", "macos"})
_PLATFORM_DIRS = ("windows", "linux", "cross-platform")
_CATALOG_NAME = "elastic-detection-catalog.json"
_EVM_CONFIG = "elastic_evm_import.json"
_PUBLISHED = Path(config.RULES_DIR) / "published"
_CONFIG = Path(config.ROOT) / "config"

_RE_PROCESS_WHERE = re.compile(r"^\s*process\s+where\b", re.I | re.M)
_RE_FILE_WHERE = re.compile(r"^\s*file\s+where\b", re.I | re.M)
_RE_REGISTRY_WHERE = re.compile(r"^\s*registry\s+where\b", re.I | re.M)
_RE_NETWORK_WHERE = re.compile(r"^\s*network\s+where\b", re.I | re.M)
_RE_DNS_WHERE = re.compile(r"^\s*dns\s+where\b", re.I | re.M)
_RE_AUTH_WHERE = re.compile(r"^\s*authentication\s+where\b", re.I | re.M)

_RE_LITERALS = re.compile(r'"([^"\\]{2,512})"')
_RE_WILDCARD_PATH = re.compile(
    r"(?:process|file|registry)\.(?:path|executable|name|target_path)\s*:\s*\(?\s*([^)\n]{3,400})",
    re.I,
)
_RE_LIKE = re.compile(r"(?:process|file|registry)\.\w+\s+like\s+\"([^\"]+)\"", re.I)
_RE_CONTAINS = re.compile(
    r"(?:process\.command_line|process\.args|registry\.data\.strings)\s+:\s*\(?\s*([^)\n]{3,400})",
    re.I,
)

# 从 EQL/KQL 抽出的过泛字面量，单独 substring 命中会造成大量误报
_GENERIC_LITERALS = frozenset({
    "recording", "start", "end", "info", "low", "medium", "high", "windows", "linux",
    "true", "false", "null", "none", "and", "or", "not", "process", "file", "registry",
    "network", "dns", "user", "host", "event", "category", "type", "name", "path",
    "s-1-5-18", "system", "local", "remote", "administrator", "users", "program files",
    "microsoft", "windows", "powershell", "cmd.exe", "exe", "dll",
})


@dataclass
class ConvertResult:
    status: str  # convertible | reference | unsupported
    reason: str = ""
    agent_rule: Optional[Dict[str, Any]] = None
    evm_rule: Optional[Dict[str, Any]] = None
    mitre: List[str] = field(default_factory=list)


def _rules_roots() -> List[Path]:
    root = Path(config.RULES_DIR)
    out = [root]
    for sub in _PLATFORM_DIRS:
        p = root / sub
        if p.is_dir():
            out.append(p)
    return out


def iter_toml_files(*, platform: str = "") -> Iterable[Path]:
    plat = str(platform or "").strip().lower()
    roots: List[Path] = []
    base = Path(config.RULES_DIR)
    if plat in _PLATFORM_DIRS:
        roots = [base / plat]
    elif plat:
        roots = [base]
    else:
        roots = [base / p for p in _PLATFORM_DIRS if (base / p).is_dir()]
        roots.insert(0, base)
    seen: Set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*.toml")):
            parts = set(p.relative_to(base).parts)
            if parts & _SKIP_DIRS:
                continue
            key = str(p.resolve()).lower()
            if key in seen:
                continue
            seen.add(key)
            yield p


def _parse_toml(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return None


def _mitre_from_tags(tags: Any) -> Tuple[List[str], str, str]:
    tactics: List[str] = []
    technique = ""
    tactic = ""
    if not isinstance(tags, list):
        return tactics, tactic, technique
    for t in tags:
        s = str(t or "")
        if s.startswith("Tactic:"):
            tactic = s.split(":", 1)[-1].strip().lower().replace(" ", "_")
        if re.match(r"^T\d", s):
            technique = s.split(".")[0].strip()
        if "Tactic:" in s or re.match(r"^T\d", s):
            tactics.append(s)
    return tactics, tactic, technique


def _severity(rule: Dict[str, Any]) -> str:
    sev = str(rule.get("severity") or "").strip().lower()
    if sev in ("critical", "high", "medium", "low"):
        return sev
    rs = int(rule.get("risk_score") or 0)
    if rs >= 73:
        return "high"
    if rs >= 47:
        return "medium"
    if rs >= 21:
        return "low"
    return "medium"


def _elastic_id(rule: Dict[str, Any], rel: str) -> str:
    rid = str(rule.get("rule_id") or "").strip()
    if rid:
        return f"elastic-{rid.split('-')[0]}"
    stem = Path(rel).stem[:48]
    return f"elastic-{stem}"


def _extract_literals(query: str) -> List[str]:
    out: List[str] = []
    for m in _RE_LITERALS.finditer(query or ""):
        s = m.group(1).strip()
        if len(s) < 2 or s.startswith("?"):
            continue
        if s in ("windows", "start", "end", "info", "low", "medium", "high"):
            continue
        out.append(s)
    for m in _RE_LIKE.finditer(query or ""):
        out.append(m.group(1).strip())
    # wildcard paths in grouped lists
    for m in _RE_WILDCARD_PATH.finditer(query or ""):
        chunk = m.group(1)
        for part in re.split(r",\s*", chunk):
            part = part.strip().strip('"').strip("'")
            if part and not part.startswith("?"):
                out.append(part)
    for m in _RE_CONTAINS.finditer(query or ""):
        chunk = m.group(1)
        for part in re.split(r",\s*", chunk):
            part = part.strip().strip('"').strip("'")
            if part:
                out.append(part)
    # dedupe preserve order
    seen: Set[str] = set()
    uniq: List[str] = []
    for x in out:
        k = x.lower()
        if k in seen:
            continue
        seen.add(k)
        uniq.append(x)
    return uniq[:24]


def _filter_literals(literals: List[str]) -> List[str]:
    out: List[str] = []
    for x in literals:
        s = str(x or "").strip()
        if len(s) < 3:
            continue
        k = s.lower()
        if k in _GENERIC_LITERALS:
            continue
        if k.isdigit():
            continue
        out.append(s)
    return out[:20]


def _query_needs_telemetry_only(query: str) -> bool:
    q = (query or "").lower()
    if "script_block" in q or "powershell.file" in q:
        return True
    if "event.category" in q or "event.module" in q or "winlogbeat" in q:
        return True
    if "index =" in q or "logs-" in q:
        return True
    return False


def get_official_rule_detail(rule_id: str) -> Dict[str, Any]:
    """按控制台规则 ID（elastic-xxx / .evm / .fim）返回官方 TOML 中的 query 等。"""
    rid = str(rule_id or "").strip()
    if not rid:
        return {"ok": False, "error": "缺少 rule_id"}
    base = rid.replace(".evm", "").replace(".fim", "")
    found = _find_toml_by_elastic_id(base)
    if not found:
        return {"ok": False, "error": "未找到对应 Elastic TOML"}
    path, rule = found
    try:
        rel = str(path.relative_to(Path(config.RULES_DIR))).replace("\\", "/")
    except ValueError:
        rel = path.name
    cr = convert_elastic_rule(rule, rel_path=rel)
    return {
        "ok": True,
        "id": base,
        "elastic_rule_id": str(rule.get("rule_id") or ""),
        "name": str(rule.get("name") or "")[:200],
        "rel_path": rel,
        "type": str(rule.get("type") or ""),
        "language": str(rule.get("language") or ""),
        "severity": _severity(rule),
        "query": str(rule.get("query") or ""),
        "description": str(rule.get("description") or "")[:2000],
        "conversion_status": cr.status,
        "conversion_reason": cr.reason,
        "mitre": cr.mitre[:8],
        "official_note": "Agent 侧为从 query 抽取的子串近似，语义与 Elastic Stack 上运行的 EQL/KQL 不完全一致。",
    }


def _domain_from_query(query: str) -> str:
    q = query or ""
    if _RE_PROCESS_WHERE.search(q):
        return "process"
    if _RE_FILE_WHERE.search(q):
        return "file"
    if _RE_REGISTRY_WHERE.search(q):
        return "registry"
    if _RE_NETWORK_WHERE.search(q):
        return "network"
    if _RE_DNS_WHERE.search(q):
        return "dns"
    if _RE_AUTH_WHERE.search(q):
        return "auth"
    if "process." in q.lower():
        return "process"
    if "file." in q.lower():
        return "file"
    if "registry." in q.lower():
        return "registry"
    return ""


def _etype_for_domain(domain: str) -> str:
    return {
        "process": "process_create",
        "file": "file_create",
        "registry": "registry_set",
        "network": "network_connect",
        "dns": "dns_query",
        "auth": "win_logon_fail",
    }.get(domain, "")


def convert_elastic_rule(rule: Dict[str, Any], *, rel_path: str = "") -> ConvertResult:
    rtype = str(rule.get("type") or "").strip().lower()
    language = str(rule.get("language") or "").strip().lower()
    query = str(rule.get("query") or "")
    name = str(rule.get("name") or Path(rel_path).stem or "Elastic rule")[:120]
    tags = rule.get("tags")
    mitre_list, tactic, technique = _mitre_from_tags(tags)

    if rtype in ("esql", "new_terms", "machine_learning", "threat_match", "threshold"):
        return ConvertResult("reference", f"类型 {rtype} 需 Elastic Stack 完整引擎")
    if rtype not in ("eql", "query", "eql", "") and language not in ("eql", "kuery", "kql", "lucene"):
        if not query:
            return ConvertResult("unsupported", f"未知类型 {rtype or '?'} 且无 query")

    domain = _domain_from_query(query)
    literals = _filter_literals(_extract_literals(query))
    # 过滤纯注释/过泛
    literals = [x for x in literals if x != "*" and not x.startswith("/*")]
    if not literals and not domain:
        return ConvertResult("reference", "无可用字面量，保留为狩猎语料")

    sev = _severity(rule)
    eid = _elastic_id(rule, rel_path)
    note = f"Elastic: {rel_path}"[:280]
    mitre_note = ", ".join(mitre_list[:4])

    agent_rule: Optional[Dict[str, Any]] = None
    evm_rule: Optional[Dict[str, Any]] = None

    telemetry_only = _query_needs_telemetry_only(query)
    if domain in ("process", "file") and not telemetry_only:
        mods = ["process", "file"] if domain == "process" else ["file", "process"]
        fields = ["command_line", "path", "name"] if domain == "process" else ["path", "name"]
        pats = literals[:20]
        if not pats:
            return ConvertResult("reference", "进程/文件规则但无抽取特征")
        # 过长路径改 substring 匹配文件名
        pats = [p if len(p) <= 120 else p[-80:] for p in pats]
        agent_rule = {
            "id": eid,
            "title": name,
            "severity": sev,
            "modules": mods,
            "fields": fields,
            "patterns": pats,
            "match": "substring",
            "enabled": False,
            "note": note,
            "source": "elastic",
            "elastic_rule_id": str(rule.get("rule_id") or ""),
            "building_block": True,
        }
        if technique:
            agent_rule["technique"] = technique
        if tactic:
            agent_rule["tactic"] = tactic
    elif domain in ("process", "file") and telemetry_only:
        agent_rule = None

    et = _etype_for_domain(domain)
    if et and literals and not telemetry_only:
        evm_rule = {
            "id": eid + ".evm",
            "title": name,
            "severity": sev,
            "etype": et,
            "summary_contains": "",
            "patterns": literals[:16],
            "match": "substring",
            "building_block": True,
            "enabled": False,
            "elastic_rule_id": str(rule.get("rule_id") or ""),
        }
        # 文件域仅在非遥测索引规则时用 FIM；PowerShell/Winlog 类误映射 fim_add 误报极高
        if domain == "file" and not _query_needs_telemetry_only(query):
            evm_rule["etype"] = "fim_add"
            evm_rule["id"] = eid + ".fim"

    if agent_rule or evm_rule:
        reason = "已抽取特征"
        if not agent_rule:
            reason = "仅时间线 EVM（注册表/网络类）"
        return ConvertResult("convertible", reason, agent_rule, evm_rule, mitre_list)

    return ConvertResult("reference", "无法映射到 Agent 模块", mitre=mitre_list)


def scan_catalog(*, platform: str = "", max_files: int = 0) -> Dict[str, Any]:
    base = Path(config.RULES_DIR)
    items: List[Dict[str, Any]] = []
    stats = {"total": 0, "convertible": 0, "reference": 0, "unsupported": 0}
    for i, path in enumerate(iter_toml_files(platform=platform)):
        if max_files and i >= max_files:
            break
        doc = _parse_toml(path)
        if not doc or not isinstance(doc.get("rule"), dict):
            continue
        rule = doc["rule"]
        try:
            rel = str(path.relative_to(base)).replace("\\", "/")
        except ValueError:
            rel = path.name
        cr = convert_elastic_rule(rule, rel_path=rel)
        stats["total"] += 1
        stats[cr.status] = int(stats.get(cr.status, 0)) + 1
        items.append({
            "id": _elastic_id(rule, rel),
            "elastic_rule_id": str(rule.get("rule_id") or ""),
            "name": str(rule.get("name") or "")[:200],
            "rel_path": rel,
            "type": str(rule.get("type") or ""),
            "language": str(rule.get("language") or ""),
            "severity": _severity(rule),
            "status": cr.status,
            "reason": cr.reason,
            "mitre": cr.mitre[:6],
            "platform": rel.split("/")[0] if "/" in rel else "windows",
            "has_agent": bool(cr.agent_rule),
            "has_evm": bool(cr.evm_rule),
        })
    out = {
        "ok": True,
        "version": 1,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "rules_dir": str(base),
        "stats": stats,
        "items": items,
    }
    return out


def save_catalog(catalog: Optional[Dict[str, Any]] = None) -> Path:
    cat = catalog or scan_catalog()
    _PUBLISHED.mkdir(parents=True, exist_ok=True)
    p = _PUBLISHED / _CATALOG_NAME
    p.write_text(json.dumps(cat, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return p


def load_catalog() -> Dict[str, Any]:
    p = _PUBLISHED / _CATALOG_NAME
    if not p.is_file():
        return scan_catalog()
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"ok": False, "items": [], "stats": {}}


def _find_toml_by_elastic_id(elastic_id: str) -> Optional[Tuple[Path, Dict[str, Any]]]:
    eid = str(elastic_id or "").strip()
    base = Path(config.RULES_DIR)
    for path in iter_toml_files():
        doc = _parse_toml(path)
        if not doc or not isinstance(doc.get("rule"), dict):
            continue
        rule = doc["rule"]
        try:
            rel = str(path.relative_to(base)).replace("\\", "/")
        except ValueError:
            rel = path.name
        if _elastic_id(rule, rel) == eid:
            return path, rule
    return None


def import_rules(
    rule_ids: List[str],
    *,
    enable: bool = False,
    enable_agent: Optional[bool] = None,
    enable_evm: Optional[bool] = None,
    mode: str = "both",
    dry_run: bool = True,
) -> Dict[str, Any]:
    """导入到 agent-live-rules.json（快照）与 config/elastic_evm_import.json（EVM）。"""
    from . import agent_rules as ar

    mode = str(mode or "both").lower()
    en_agent = bool(enable) if enable_agent is None else bool(enable_agent)
    en_evm = bool(enable) if enable_evm is None else bool(enable_evm)
    want_agent = mode in ("both", "agent", "snapshot")
    want_evm = mode in ("both", "evm", "timeline")
    created: List[str] = []
    updated: List[str] = []
    skipped: List[Dict[str, str]] = []
    evm_rules: List[Dict[str, Any]] = []

    existing_evm: List[Dict[str, Any]] = []
    evm_path = _CONFIG / _EVM_CONFIG
    if evm_path.is_file():
        try:
            doc = json.loads(evm_path.read_text(encoding="utf-8"))
            existing_evm = list(doc.get("rules") or [])
        except Exception:
            existing_evm = []

    evm_by_id = {str(r.get("id")): r for r in existing_evm if isinstance(r, dict)}

    for rid in rule_ids:
        found = _find_toml_by_elastic_id(rid)
        if not found:
            skipped.append({"id": rid, "reason": "未找到 TOML"})
            continue
        path, rule = found
        try:
            rel = str(path.relative_to(Path(config.RULES_DIR))).replace("\\", "/")
        except ValueError:
            rel = path.name
        cr = convert_elastic_rule(rule, rel_path=rel)
        if cr.status != "convertible":
            skipped.append({"id": rid, "reason": cr.reason or cr.status})
            continue
        if want_agent and cr.agent_rule:
            payload = dict(cr.agent_rule)
            payload["enabled"] = en_agent
            if dry_run:
                created.append(payload["id"])
                continue
            try:
                out = ar.upsert_imported_rule(payload)
                if out.get("created"):
                    created.append(payload["id"])
                else:
                    updated.append(payload["id"])
            except ValueError as e:
                skipped.append({"id": rid, "reason": str(e)})
        if want_evm and cr.evm_rule:
            evm = dict(cr.evm_rule)
            evm["enabled"] = en_evm
            evm_by_id[str(evm["id"])] = evm
            if dry_run:
                continue

    if want_evm and not dry_run:
        _CONFIG.mkdir(parents=True, exist_ok=True)
        merged = list(evm_by_id.values())
        evm_doc = {
            "version": 1,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "rules": merged[:2000],
        }
        evm_path.write_text(json.dumps(evm_doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            from . import agent_sync
            agent_sync.bump_sync("evm")
        except Exception:
            pass

    if not dry_run and (created or updated):
        try:
            from . import agent_protocol, agent_sync
            agent_protocol.bump_live("rules")
            agent_sync.bump_sync("rules")
        except Exception:
            pass

    return {
        "ok": True,
        "dry_run": dry_run,
        "enable": enable,
        "enable_agent": en_agent,
        "enable_evm": en_evm,
        "mode": mode,
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "evm_count": len(evm_by_id),
    }


def bulk_set_evm_enabled(
    enabled: bool,
    *,
    rule_ids: Optional[List[str]] = None,
    all_rules: bool = False,
) -> Dict[str, Any]:
    p = _CONFIG / _EVM_CONFIG
    if not p.is_file():
        return {"ok": False, "error": "无 elastic_evm_import.json"}
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        return {"ok": False, "error": str(e)}
    rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
    want = {str(x).strip() for x in (rule_ids or []) if str(x).strip()}
    n = 0
    for r in rules:
        rid = str(r.get("id") or "")
        base = rid.split(".")[0]
        if all_rules or rid in want or base in want:
            r["enabled"] = bool(enabled)
            n += 1
    doc["rules"] = rules
    doc["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        from . import agent_sync
        agent_sync.bump_sync("evm")
    except Exception:
        pass
    return {"ok": True, "enabled": bool(enabled), "changed": n}


def load_evm_import_rules(*, enabled_only: bool = True) -> List[Dict[str, Any]]:
    p = _CONFIG / _EVM_CONFIG
    if not p.is_file():
        return []
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []
    rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
    if enabled_only:
        rules = [r for r in rules if r.get("enabled", True)]
    return rules[:1500]


def match_timeline_event(ev: Dict[str, Any]) -> List[Dict[str, Any]]:
    """对已入库前的时间线事件做 Elastic EVM 轻量匹配（可选）。"""
    rules = list(load_evm_import_rules(enabled_only=True))
    try:
        from . import protections_import as _pi

        rules.extend(_pi.load_evm_import_rules(enabled_only=True))
    except Exception:
        pass
    if not rules:
        return []
    et = str(ev.get("etype") or "").lower()
    summary = str(ev.get("summary") or "").lower()
    detail = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
    path = str(detail.get("path") or detail.get("image") or "").lower()
    blob = summary + "\n" + path + "\n" + str(detail.get("command_line") or "").lower()
    hits: List[Dict[str, Any]] = []
    for r in rules:
        if r.get("enabled") is False:
            continue
        want_et = str(r.get("etype") or "").lower()
        if want_et and want_et != et and not (want_et == "fim_add" and et == "file_create"):
            continue
        sc = str(r.get("summary_contains") or "").lower()
        if sc and sc not in summary:
            continue
        pats = [str(p).strip() for p in (r.get("patterns") or []) if str(p).strip() and str(p).strip() != "*"]
        if not pats:
            continue
        matched = [p for p in pats if str(p).lower() in blob]
        bb = bool(r.get("building_block"))
        # 积木规则在官方需与其它条件组合；近似匹配时至少命中 2 条特征以降低误报
        need = 2 if bb and len(pats) >= 3 else 1
        if len(matched) >= need:
            hits.append(r)
    return hits[:5]
