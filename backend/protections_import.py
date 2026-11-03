# -*- coding: utf-8 -*-
"""Elastic protections-artifacts → Agent 可执行包（YARA + 高精准 EVM + PTM 补充）。

行为 TOML 为 Endpoint EQL，不能整库字面量导入；本模块按策略精选并打分。
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from . import config
from . import elastic_detection_import as edi
from . import elastic_precision as ep

_ROOT = Path(config.ROOT)
_RULES = Path(config.RULES_DIR)
_CONFIG = _ROOT / "config"
_POLICY = _CONFIG / "protections_bundle_policy.json"
_EVM_OUT = _CONFIG / "protections_evm_import.json"
_AMSI_OUT = _CONFIG / "protections_amsi_rules.json"
_API_OUT = _CONFIG / "protections_api_rules.json"

_WIN32K_APIS = frozenset({
    "GetAsyncKeyState", "SetWindowsHookEx", "RegisterRawInputDevices", "SetWinEventHook",
})
_TI_APIS = frozenset({
    "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory", "VirtualAlloc", "VirtualAllocEx",
    "VirtualFreeEx", "OpenProcess", "OpenThread", "SetThreadContext", "QueueUserAPC", "NtQueueApcThread",
    "MapViewOfFile", "SuspendThread", "DeviceIoControl", "connect",
})
_WMI_APIS = frozenset({"IWbemServices::ExecMethod", "IWbemServices::ExecQuery"})
_LDAP_APIS = frozenset({"ldap_search"})
_CATALOG_OUT = _RULES / "published" / "protections-behavior-catalog.json"
_PACK_DIR = _ROOT / "agent" / "memory-yara"
_MANIFEST = _PACK_DIR / "manifest.json"
_PTM = _CONFIG / "agent_ptm_rules.json"

_RE_PROCESS_HEAD = re.compile(r"^\s*process\s+where\b", re.I | re.M)
_RE_REGISTRY_HEAD = re.compile(r"^\s*registry\s+where\b", re.I | re.M)
_RE_FILE_WHERE = re.compile(r"^\s*file\s+where\b", re.I | re.M)
_RE_CMD_PATS = re.compile(
    r"process\.(?:command_line|args)\s*:\s*\(?\s*([^)\n]{4,1200})",
    re.I,
)
_RE_WC = re.compile(r'"(\*[^"]{4,200}\*|\*[^"]{4,200})"')
_RE_NAME = re.compile(r'process\.name\s*:\s*"?([a-zA-Z0-9_.-]+\.exe)"?', re.I)

_BLOCK_SUBSTR = (
    "api where",
    "library where",
    "sequence by",
    "process.ext",
    "file.ext",
    "dll.ext",
    "malware_classification",
    "code_signature",
    "credential_access where",
)


def _read_json(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def protections_root() -> Path:
    pol = load_policy()
    rel = str(pol.get("source_root") or "rules/protections-artifacts-main").strip()
    p = (_ROOT / rel).resolve()
    if p.is_dir():
        return p
    alt = _RULES / "protections-artifacts-main"
    return alt if alt.is_dir() else p


def load_policy() -> Dict[str, Any]:
    return _read_json(_POLICY)


def _parse_rule_toml(path: Path) -> Optional[Dict[str, Any]]:
    doc = edi._parse_toml(path)
    if not doc or not isinstance(doc.get("rule"), dict):
        return None
    rule = dict(doc["rule"])
    if "rule_id" not in rule and rule.get("id"):
        rule["rule_id"] = rule["id"]
    return rule


def _query_blocked(q: str) -> bool:
    low = (q or "").lower()
    if "process.ext" in low:
        return True
    for x in _BLOCK_SUBSTR:
        if x in ("code_signature", "process.ext"):
            continue
        if x in low:
            return True
    return False


def _query_blocked_file_evm(q: str) -> bool:
    low = (q or "").lower()
    if "sequence by" in low or "file.ext" in low or "process.ext" in low:
        return True
    return False


def extract_evm_patterns(query: str) -> List[str]:
    """从 process/registry 行为 query 抽取适合子串匹配的片段。"""
    q = query or ""
    out: List[str] = []
    for m in _RE_CMD_PATS.finditer(q):
        chunk = m.group(1)
        for wm in _RE_WC.finditer(chunk):
            s = wm.group(1).strip().strip("*")
            if len(s) >= 4:
                out.append(s)
        for part in re.split(r",\s*", chunk):
            part = part.strip().strip('"').strip("'")
            if part.startswith("*") and part.endswith("*") and len(part) > 8:
                out.append(part.strip("*"))
    for m in _RE_NAME.finditer(q):
        nm = m.group(1).lower()
        if nm not in ep._GENERIC_EXE:
            out.append(nm)
    if _RE_REGISTRY_HEAD.search(q):
        for m in re.finditer(r'registry\.path\s*:\s*"([^"]{6,200})"', q, re.I):
            out.append(m.group(1).replace("?", "").replace("*", ""))
    seen: Set[str] = set()
    uniq: List[str] = []
    for x in out:
        k = x.lower()
        if k in seen or len(k) < 5:
            continue
        if k in edi._GENERIC_LITERALS:
            continue
        seen.add(k)
        uniq.append(x[:160])
    return uniq[:16]


def score_protections_rule(rule: Dict[str, Any], *, rel_path: str = "") -> Tuple[int, List[str], Optional[Dict[str, Any]]]:
    reasons: List[str] = []
    q = str(rule.get("query") or "")
    if not q or _query_blocked(q):
        return 0, ["blocked_telemetry"], None
    if _RE_PROCESS_HEAD.search(q):
        domain = "process"
    elif _RE_REGISTRY_HEAD.search(q):
        domain = "registry"
    else:
        return 0, ["not_process_or_registry"], None

    pats = extract_evm_patterns(q)
    if not pats:
        cr = edi.convert_elastic_rule(rule, rel_path=rel_path)
        if cr.evm_rule:
            pats = [str(p) for p in (cr.evm_rule.get("patterns") or []) if str(p).strip()][:12]
    pats = edi._filter_literals(pats)
    if not pats:
        return 0, ["no_patterns"], None

    head = pats[: min(6, len(pats))]
    if all(pl.lower().replace("*", "") in ep._GENERIC_EXE or len(pl) <= 5 for pl in head):
        return 0, ["generic_only"], None

    score = 40
    reasons.append("protections_behavior")
    et = "process_create" if domain == "process" else "registry_set"
    score += 22
    reasons.append(f"etype:{et}")

    for pl in pats:
        low = pl.lower()
        if any(h in low for h in ep._SPECIFIC_HINTS):
            score += 30
            reasons.append(f"specific:{pl[:36]}")
            break
        if low.endswith(".exe") and low not in ep._GENERIC_EXE:
            score += 10

    if len(q) > 8000:
        score -= 15
        reasons.append("query_huge:-15")
    elif len(q) < 2500:
        score += 8
        reasons.append("query_compact:+8")

    name = str(rule.get("name") or "")
    if any(x in name.lower() for x in ("potential", "suspicious")):
        score += 5

    sev = edi._severity(rule)
    if sev == "critical":
        score += 12
    elif sev == "high":
        score += 8

    eid = edi._elastic_id(rule, rel_path)
    evm = {
        "id": eid + ".prot.evm",
        "title": (name or Path(rel_path).stem)[:120],
        "severity": sev if sev in ("critical", "high", "medium", "low") else "medium",
        "etype": et,
        "summary_contains": "",
        "patterns": pats[:14],
        "match": "substring",
        "building_block": False,
        "enabled": True,
        "protections_rule_id": str(rule.get("rule_id") or rule.get("id") or ""),
        "source": "protections-artifacts",
    }
    if domain == "process":
        evm["summary_contains"] = ""
    if re.search(r"code_signature\.trusted\s*==\s*false", q, re.I):
        evm["signed_filter"] = "unsigned"
    elif "unsigned" in q.lower() and "code_signature" in q.lower():
        evm["signed_filter"] = "unsigned"
    return score, reasons, evm


def build_signed_process_evm_rules(*, max_rules: int = 36) -> List[Dict[str, Any]]:
    """`process where` + 签名条件、无 process.Ext → EVM + signed_filter。"""
    rules: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for path in iter_behavior_tomls():
        rule = _parse_rule_toml(path)
        if not rule:
            continue
        q = str(rule.get("query") or "")
        if not _RE_PROCESS_HEAD.search(q):
            continue
        low = q.lower()
        if "sequence" in low or "process.ext" in low or "api where" in low or "library where" in low:
            continue
        if "code_signature" not in low:
            continue
        if not (
            re.search(r"code_signature\.trusted\s*==\s*false", q, re.I)
            or "unsigned" in low
        ):
            continue
        rel = f"protections-artifacts/{path.name}"
        sc, _, evm = score_protections_rule(rule, rel_path=rel)
        if not evm or sc < 55:
            continue
        rid = str(rule.get("rule_id") or rule.get("id") or path.stem)
        key = rid.split("-")[0]
        if key in seen:
            continue
        seen.add(key)
        evm = dict(evm)
        evm["signed_filter"] = "unsigned"
        evm["source"] = "protections-artifacts-signed"
        rules.append(evm)
        if len(rules) >= max_rules:
            break
    return rules


def _extract_file_path_patterns(query: str) -> List[str]:
    q = query or ""
    out: List[str] = []
    for m in re.finditer(r"file\.(?:path|name|target_path)\s*(?:::|:|like)\s*", q, re.I):
        rest = q[m.end() : m.end() + 1500]
        chunk = rest.split("\n", 1)[0]
        if chunk.lstrip().startswith("("):
            depth = 0
            end = 0
            for i, ch in enumerate(rest[:2000]):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            chunk = rest[:end] if end else rest[:800]
        for wm in re.finditer(r'"([^"]{5,160})"', chunk):
            raw = wm.group(1).strip().strip("*")
            if "?" in raw or len(raw) < 5:
                continue
            if raw.lower().endswith((".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs", ".js")):
                out.append(raw.replace("?", "").lower())
            elif "\\" in raw or "/" in raw:
                out.append(raw.replace("?", "").lower())
    seen: Set[str] = set()
    uniq: List[str] = []
    for x in out:
        k = x.lower()
        if k in seen or k in edi._GENERIC_LITERALS:
            continue
        seen.add(k)
        uniq.append(x)
    return uniq[:10]


def build_file_evm_rules(*, max_rules: int = 28) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for path in iter_behavior_tomls():
        rule = _parse_rule_toml(path)
        if not rule:
            continue
        q = str(rule.get("query") or "")
        if not _RE_FILE_WHERE.search(q):
            continue
        if _query_blocked_file_evm(q):
            continue
        pats = _extract_file_path_patterns(q)
        if not pats:
            continue
        rid = str(rule.get("rule_id") or rule.get("id") or path.stem)
        key = rid.split("-")[0]
        if key in seen:
            continue
        seen.add(key)
        rel = f"protections-artifacts/{path.name}"
        eid = edi._elastic_id(rule, rel)
        sev = edi._severity(rule)
        rules.append({
            "id": eid + ".prot.file.evm",
            "title": str(rule.get("name") or path.stem)[:120],
            "severity": sev if sev in ("critical", "high", "medium", "low") else "medium",
            "etype": "file_create",
            "patterns": pats[:8],
            "match": "substring",
            "building_block": False,
            "enabled": True,
            "protections_rule_id": rid,
            "source": "protections-artifacts-file",
        })
        if len(rules) >= max_rules:
            break
    return rules


def _extract_dll_name_literals(query: str) -> List[str]:
    q = query or ""
    out: List[str] = []
    for m in re.finditer(r"dll\.name\s*(?:::|:|in|like)\s*", q, re.I):
        rest = q[m.end() : m.end() + 2000]
        chunk = rest
        if chunk.lstrip().startswith("("):
            depth = 0
            end = 0
            for i, ch in enumerate(chunk):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            chunk = chunk[:end] if end else chunk[:800]
        else:
            chunk = chunk.split("\n", 1)[0]
        for wm in re.finditer(r'"([^"]+\.dll[^"]*)"', chunk, re.I):
            raw = wm.group(1).strip().strip("*")
            if len(raw) >= 6 and "?" not in raw and "*" not in raw:
                out.append(raw.lower())
        for wm in re.finditer(r'"([^"]+)"', chunk):
            raw = wm.group(1).strip().strip("*")
            if ".dll" in raw.lower() and len(raw) >= 6 and "?" not in raw and "*" not in raw:
                out.append(raw.lower())
    for m in re.finditer(r"dll\.pe\.original_file_name\s+in\s*\(([^)]+)\)", q, re.I | re.S):
        for wm in re.finditer(r'"([^"]+\.dll)"', m.group(1), re.I):
            out.append(wm.group(1).lower())
    seen: Set[str] = set()
    uniq: List[str] = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq[:8]


def _extract_library_host_processes(query: str) -> List[str]:
    q = query or ""
    out: List[str] = []
    for m in re.finditer(r"process\.name\s*(?:::|:|in)\s*", q, re.I):
        rest = q[m.end() : m.end() + 1200]
        chunk = rest.split("\n", 1)[0]
        if chunk.lstrip().startswith("("):
            depth = 0
            end = 0
            for i, ch in enumerate(chunk):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            chunk = chunk[:end] if end else chunk[:600]
        for wm in re.finditer(r'"([^"]+\.exe)"', chunk, re.I):
            nm = wm.group(1).lower()
            if nm not in ep._GENERIC_EXE:
                out.append(nm)
    seen: Set[str] = set()
    uniq: List[str] = []
    for x in out:
        if x in seen:
            continue
        seen.add(x)
        uniq.append(x)
    return uniq[:6]


def _library_query_importable(query: str) -> bool:
    q = query or ""
    if not re.match(r"^\s*library\s+where\b", q, re.I | re.M):
        return False
    low = q.lower()
    if "sequence by" in low or "malware_classification" in low:
        return False
    return len(_extract_dll_name_literals(q)) > 0


def build_library_evm_rules(*, max_rules: int = 48) -> List[Dict[str, Any]]:
    """独立 `library where` → Agent image_load_etw EVM（不含 call_stack 等 Defend 专有字段）。"""
    rules: List[Dict[str, Any]] = []
    seen_id: Set[str] = set()
    for path in iter_behavior_tomls():
        rule = _parse_rule_toml(path)
        if not rule:
            continue
        q = str(rule.get("query") or "")
        if not _library_query_importable(q):
            continue
        dlls = _extract_dll_name_literals(q)
        if not dlls:
            continue
        rid = str(rule.get("rule_id") or rule.get("id") or path.stem)
        key = rid.split("-")[0]
        if key in seen_id:
            continue
        seen_id.add(key)
        hosts = _extract_library_host_processes(q)
        pats = list(dlls)
        pats.extend(hosts)
        pats = edi._filter_literals(pats) or pats[:6]
        rel = f"protections-artifacts/{path.name}"
        eid = edi._elastic_id(rule, rel)
        sev = edi._severity(rule)
        item: Dict[str, Any] = {
            "id": eid + ".prot.lib.evm",
            "title": str(rule.get("name") or path.stem)[:120],
            "severity": sev if sev in ("critical", "high", "medium", "low") else "medium",
            "etype": "image_load_etw",
            "summary_contains": "",
            "patterns": pats[:10],
            "match": "substring",
            "building_block": False,
            "enabled": True,
            "protections_rule_id": str(rule.get("rule_id") or rule.get("id") or ""),
            "source": "protections-artifacts-library",
        }
        if "code_signature.trusted == false" in q.replace(" ", "").lower() or "unsigned" in q.lower():
            item["signed_filter"] = "unsigned"
        rules.append(item)
        if len(rules) >= max_rules:
            break
    return rules


def iter_behavior_tomls(*, platform: str = "windows") -> List[Path]:
    root = protections_root() / "behavior" / "rules" / platform
    if not root.is_dir():
        return []
    return sorted(root.glob("*.toml"))


def pick_yara_files(pol: Optional[Dict[str, Any]] = None) -> List[Path]:
    pol = pol or load_policy()
    ycfg = pol.get("yara") if isinstance(pol.get("yara"), dict) else {}
    ydir = protections_root() / "yara" / "rules"
    if not ydir.is_dir():
        return []
    include = [str(x) for x in (ycfg.get("include_prefixes") or [])]
    exclude_p = [str(x) for x in (ycfg.get("exclude_prefixes") or [])]
    exclude_f = {str(x).lower() for x in (ycfg.get("exclude_files") or [])}
    max_files = int(ycfg.get("max_files") or 60)
    max_bytes = int(ycfg.get("max_total_bytes") or 4_500_000)

    candidates: List[Tuple[int, Path]] = []
    for p in sorted(ydir.glob("Windows_*.yar")):
        if p.name.lower() in exclude_f:
            continue
        if any(p.name.startswith(x) for x in exclude_p):
            continue
        if include and not any(p.name.startswith(x) for x in include):
            continue
        pri = 0
        if p.name.startswith("Windows_Hacktool_"):
            pri += 100
        elif "Ransomware" in p.name:
            pri += 70
        elif "Trojan" in p.name or "Infostealer" in p.name:
            pri += 60
        elif "Shellcode" in p.name:
            pri += 50
        try:
            pri -= min(40, p.stat().st_size // 50000)
        except OSError:
            pass
        candidates.append((pri, p))

    candidates.sort(key=lambda x: (-x[0], x[1].name))
    out: List[Path] = []
    total = 0
    for _, p in candidates:
        try:
            sz = p.stat().st_size
        except OSError:
            continue
        if total + sz > max_bytes:
            continue
        out.append(p)
        total += sz
        if len(out) >= max_files:
            break
    return out


def build_evm_document(*, min_score: Optional[int] = None, max_rules: Optional[int] = None) -> Dict[str, Any]:
    pol = load_policy()
    ecfg = pol.get("evm") if isinstance(pol.get("evm"), dict) else {}
    min_sc = int(min_score if min_score is not None else ecfg.get("min_score") or 78)
    max_n = int(max_rules if max_rules is not None else ecfg.get("max_rules") or 48)
    sev_allow = {str(x).lower() for x in (ecfg.get("severity_allow") or ["high", "critical", "medium"])}
    prefix_allow = [str(x).lower() for x in (ecfg.get("name_prefix_allow") or [])]

    scored: List[Tuple[int, Dict[str, Any], str]] = []
    for path in iter_behavior_tomls():
        stem = path.stem.lower()
        if prefix_allow and not any(stem.startswith(p) for p in prefix_allow):
            continue
        rule = _parse_rule_toml(path)
        if not rule:
            continue
        rel = f"protections-artifacts/{path.name}"
        sc, _, evm = score_protections_rule(rule, rel_path=rel)
        if not evm or sc < min_sc:
            continue
        if edi._severity(rule) not in sev_allow and sc < min_sc + 15:
            continue
        scored.append((sc, evm, path.name))

    scored.sort(key=lambda x: (-x[0], x[1]["id"]))
    rules: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for sc, evm, _ in scored:
        rid = str(evm.get("id") or "")
        if rid in seen:
            continue
        seen.add(rid)
        evm["precision_score"] = sc
        rules.append(evm)
        if len(rules) >= max_n:
            break

    lcfg = ecfg.get("library") if isinstance(ecfg.get("library"), dict) else {}
    max_lib = int(lcfg.get("max_rules") or 40)
    lib_rules = build_library_evm_rules(max_rules=max_lib)
    scfg = ecfg.get("signed_process") if isinstance(ecfg.get("signed_process"), dict) else {}
    max_sig = int(scfg.get("max_rules") or 36)
    signed_rules = build_signed_process_evm_rules(max_rules=max_sig)
    fcfg = ecfg.get("file") if isinstance(ecfg.get("file"), dict) else {}
    max_file = int(fcfg.get("max_rules") or 28)
    file_rules = build_file_evm_rules(max_rules=max_file)
    by_id = {str(r.get("id") or ""): r for r in rules}
    for extra in lib_rules + signed_rules + file_rules:
        by_id[str(extra.get("id") or "")] = extra
    rules = list(by_id.values())

    ids = [
        str(r.get("id") or "")
        .replace(".prot.evm", "")
        .replace(".prot.lib.evm", "")
        .replace(".prot.file.evm", "")
        for r in rules
    ]
    return {
        "version": 1,
        "profile": "protections-curated",
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "min_score": min_sc,
        "library_rules": len(lib_rules),
        "signed_process_rules": len(signed_rules),
        "file_rules": len(file_rules),
        "rule_ids": ids,
        "rules": rules,
    }


def scan_behavior_catalog() -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    stats = {"total": 0, "scored_ok": 0, "reference": 0}
    for path in iter_behavior_tomls():
        rule = _parse_rule_toml(path)
        if not rule:
            continue
        rel = f"protections-artifacts/behavior/windows/{path.name}"
        stats["total"] += 1
        sc, reasons, evm = score_protections_rule(rule, rel_path=rel)
        st = "evm_candidate" if evm and sc >= 50 else "reference"
        if st == "evm_candidate":
            stats["scored_ok"] += 1
        else:
            stats["reference"] += 1
        items.append({
            "id": edi._elastic_id(rule, rel),
            "name": str(rule.get("name") or "")[:200],
            "rel_path": rel,
            "score": sc,
            "reasons": reasons[:6],
            "status": st,
            "has_evm": bool(evm),
        })
    return {
        "ok": True,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "stats": stats,
        "items": items,
    }


def load_evm_import_rules(*, enabled_only: bool = True) -> List[Dict[str, Any]]:
    if not _EVM_OUT.is_file():
        return []
    try:
        doc = json.loads(_EVM_OUT.read_text(encoding="utf-8"))
    except Exception:
        return []
    rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
    if enabled_only:
        rules = [r for r in rules if r.get("enabled", True)]
    return rules[:800]


def _sync_yara_files(yar_paths: List[Path], *, prefix: str = "ep_") -> Tuple[List[str], int]:
    """复制 YARA 到 agent/memory-yara，返回 manifest 文件名列表与总字节。"""
    _PACK_DIR.mkdir(parents=True, exist_ok=True)
    existing_ep = {p.name for p in _PACK_DIR.glob(f"{prefix}*.yar")}
    for name in existing_ep:
        try:
            (_PACK_DIR / name).unlink()
        except OSError:
            pass

    manifest_names: List[str] = []
    total = 0
    for src in yar_paths:
        dst_name = prefix + src.name
        dst = _PACK_DIR / dst_name
        shutil.copy2(src, dst)
        manifest_names.append(dst_name)
        try:
            total += dst.stat().st_size
        except OSError:
            pass
    return manifest_names, total


def _update_manifest(yar_names: List[str]) -> None:
    base_files = ["rules.json", "reflective_loader.yar", "cobalt_strike.yar", "mimikatz.yar", "amsi_bypass.yar"]
    man = _read_json(_MANIFEST)
    if not man:
        man = {
            "id": "forensic-agent-memory-yara",
            "name": "Agent 内存扫描轻量包",
            "version": "2026.10.31.1",
            "description": "rules.json + 内置 .yar + Elastic protections 精选",
        }
    files = list(base_files)
    for n in sorted(yar_names):
        if n not in files:
            files.append(n)
    rev = time.strftime("%Y.%m.%d.prot")
    man["files"] = files
    man["version"] = rev
    man["updated_at"] = time.strftime("%Y-%m-%d")
    man["protections_yara_count"] = len(yar_names)
    _MANIFEST.write_text(json.dumps(man, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # bump rules.json rev for agents without yara tag (string rules unchanged)
    rules_p = _PACK_DIR / "rules.json"
    if rules_p.is_file():
        try:
            doc = json.loads(rules_p.read_text(encoding="utf-8"))
            doc["rev"] = rev
            rules_p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except Exception:
            pass


def _extract_amsi_patterns(query: str) -> Tuple[List[str], List[str], List[str]]:
    q = query or ""
    proc_names: List[str] = []
    app_names: List[str] = []
    buffers: List[str] = []
    for m in re.finditer(r'process\.name\s*:\s*"?([a-zA-Z0-9_.-]+\.exe)"?', q, re.I):
        proc_names.append(m.group(1).lower())
    for m in re.finditer(r'app_name\s*==\s*"([^"]+)"', q, re.I):
        app_names.append(m.group(1))
    for line in q.splitlines():
        if "buffer" not in line.lower():
            continue
        for wm in re.finditer(r'"(\*[^"]{4,200}\*)"', line):
            s = wm.group(1).strip().strip("*")
            if len(s) >= 4:
                buffers.append(s)
    return proc_names[:6], app_names[:4], buffers[:14]


def build_amsi_document(*, max_rules: int = 96) -> Dict[str, Any]:
    rules: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for path in iter_behavior_tomls():
        rule = _parse_rule_toml(path)
        if not rule:
            continue
        q = str(rule.get("query") or "")
        if "amsiscanbuffer" not in q.lower():
            continue
        proc_names, app_names, buffers = _extract_amsi_patterns(q)
        if len(buffers) < 2:
            continue
        rid = str(rule.get("rule_id") or rule.get("id") or path.stem)
        key = rid.lower()
        if key in seen:
            continue
        seen.add(key)
        sev = edi._severity(rule)
        rules.append({
            "id": "amsi." + rid.split("-")[0][:24],
            "kind": "amsi_buffer",
            "title": str(rule.get("name") or path.stem)[:120],
            "severity": sev if sev in ("critical", "high", "medium") else "high",
            "process_names": proc_names,
            "app_names": app_names,
            "buffer_all": buffers,
            "protections_rule_id": rid,
            "enabled": True,
        })
        if len(rules) >= max_rules:
            break
    rev = hashlib.sha256(json.dumps(rules, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:12]
    return {
        "version": 1,
        "profile": "protections-amsi",
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "rev": rev,
        "rules": rules,
    }


def _ldap_filter_token(raw: str) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    # 匹配用：去掉通配占位，保留 LDAP 特征子串
    norm = s.replace("?", "").strip("*").strip()
    low = norm.lower()
    if len(norm) < 4 and "=" not in s:
        return ""
    if s.endswith("*") and s.count("=") == 0 and len(s) < 10:
        return ""
    needles = (
        "samaccounttype", "samaccountname", "objectclass", "objectcategory", "objectguid",
        "serviceprincipalname", "useraccountcontrol", "memberof", "msds-", "homedirectory",
        "scriptpath", "profilepath", "krbtgt", "rid manager", "proxyaddresses", "mail=",
        "directreports", "manager=", "lastlogon", "primarygroupid", "trustpartner",
    )
    for nd in needles:
        if nd in low:
            i = low.find(nd)
            return norm[i : min(len(norm), i + 72)]
    if s.startswith("(") or "=" in norm:
        return norm[:120] if len(norm) >= 4 else s.replace("?", "")[:120]
    return norm[:120] if len(norm) >= 6 else ""


def _looks_like_ldap_filter_literal(raw: str) -> bool:
    tok = _ldap_filter_token(raw)
    if not tok:
        return False
    low = tok.lower()
    if any(c in raw for c in ("(", "&", "|")) and "=" in raw:
        return True
    return any(
        x in low
        for x in (
            "object", "samaccount", "useraccount", "serviceprincipal", "msds",
            "memberof", "cn=", "guid", "krbtgt", "mail", "proxyaddress",
        )
    )


def _extract_ldap_filters(query: str) -> List[str]:
    """从 EQL 抽取 search_filter 字面量（支持嵌套括号、多行列表、in/like）。"""
    q = query or ""
    if "search_filter" not in q.lower():
        return []
    out: List[str] = []
    for m in re.finditer(r"(?:parameters\.)?search_filter\s*(?:::|:|in|like)\s*", q, re.I):
        rest = q[m.end() :]
        chunk = rest[:5000]
        for stop in ("\n [", "\n[", "'''", "\n]"):
            if stop in chunk:
                chunk = chunk.split(stop, 1)[0]
        for wm in re.finditer(r'"([^"]*)"', chunk):
            raw = wm.group(1)
            if not _looks_like_ldap_filter_literal(raw):
                continue
            tok = _ldap_filter_token(raw)
            if tok:
                out.append(tok)
    # 单行括号列表：search_filter : ("a", "b") 未被上面覆盖时
    for m in re.finditer(
        r"(?:parameters\.)?search_filter\s*:\s*\(\s*([^;]+?)\s*\)\s*(?:and|$|\n)",
        q,
        re.I | re.S,
    ):
        for wm in re.finditer(r'"([^"]*)"', m.group(1)):
            raw = wm.group(1)
            if _looks_like_ldap_filter_literal(raw):
                tok = _ldap_filter_token(raw)
                if tok:
                    out.append(tok)
    seen: Set[str] = set()
    uniq: List[str] = []
    for x in out:
        k = x.lower()
        if k in seen:
            continue
        seen.add(k)
        uniq.append(x)
    return uniq[:16]


def _ldap_fallback_tokens(query: str, *, title: str = "") -> List[str]:
    """无 search_filter 子句的 ldap_search（如纯 sequence 第一步）用标题/描述启发式。"""
    q = (query or "").lower()
    t = (title or "").lower()
    hints: List[str] = []
    if "kerberos" in t or "port == 88" in q:
        hints.append("objectcategory")
    if "password policy" in t or "maxpwdage" in q or "minpwdage" in q:
        hints.append("maxpwdage")
    if "certificate" in t or "adcs" in t:
        hints.append("pki")
    if "trust" in t and "schema" in t:
        hints.append("trustpartner")
    if "dfs" in t or "distributed file" in t:
        hints.append("remoteServerName")
    if "password spraying" in t:
        hints.append("badpasswordtime")
    if "privileged" in t and "group" in t:
        hints.append("admincount")
    if "sensitive attribute" in t:
        hints.append("serviceprincipalname")
    if "computer" in t and "enumeration" in t:
        hints.append("objectcategory=computer")
    if "domain accounts" in t or "account discovery" in t:
        hints.append("samaccounttype=805306368")
    if "kerberos enumeration" in t:
        hints.append("serviceprincipalname")
    if "suspicious enumeration" in t:
        hints.append("samaccounttype=805306368")
    if "active directory data collection" in t:
        hints.append("objectguid")
    seen: Set[str] = set()
    out: List[str] = []
    for h in hints:
        k = h.lower()
        if k not in seen:
            seen.add(k)
            out.append(h)
    return out[:4]


def _wmi_token_from_literal(raw: str) -> List[str]:
    s = (raw or "").strip().strip("*").strip()
    if len(s) < 3:
        return []
    out: List[str] = []
    if "::" in s:
        out.append(s)
        out.append(s.split("::", 1)[-1])
    elif re.search(r"execquery\s*\(", s, re.I):
        for cls in re.findall(r"(?:from|FROM)\s+(Win32_[A-Za-z0-9_]+)", s):
            out.append(cls)
        if not out:
            out.append("ExecQuery")
    else:
        out.append(s)
    for cls in re.findall(r"(Win32_[A-Za-z0-9_]+|MSFT_MpPreference|StdRegProv|FilterToConsumerBinding)", s):
        out.append(cls)
    return out


def _extract_wmi_operations(query: str) -> List[str]:
    """从 operation / summary 子句抽取 WMI 匹配片段（供 operation_contains）。"""
    return _extract_wmi_operation_tokens(query, title="")


def _extract_wmi_operation_tokens(query: str, *, title: str = "") -> List[str]:
    q = query or ""
    out: List[str] = []
    for m in re.finditer(
        r"(?:process\.Ext\.api\.)?(?:parameters\.)?operation\s*(?:::|:|==|like|in)\s*",
        q,
        re.I,
    ):
        rest = q[m.end() :]
        chunk = rest[:4000]
        for stop in ("\n and ", "\n or ", "\n not ", "\n]"):
            if stop in chunk:
                chunk = chunk.split(stop, 1)[0]
        if chunk.lstrip().startswith("("):
            depth = 0
            end = 0
            for i, ch in enumerate(chunk):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            chunk = chunk[:end] if end else chunk[:800]
        for wm in re.finditer(r'"([^"]{3,240})"', chunk):
            for tok in _wmi_token_from_literal(wm.group(1)):
                out.append(tok)
    for m in re.finditer(r'(?:process\.Ext\.api\.)?summary\s+like\s+"([^"]+)"', q, re.I):
        for tok in _wmi_token_from_literal(m.group(1)):
            out.append(tok)
    for m in re.finditer(
        r"(?:process\.Ext\.api\.)?summary\s*(?:::|:|like|==|in)\s*",
        q,
        re.I,
    ):
        rest = q[m.end() :]
        chunk = rest[:4000]
        for stop in ("\n and ", "\n or ", "\n not ", "\n]"):
            if stop in chunk:
                chunk = chunk.split(stop, 1)[0]
        if chunk.lstrip().startswith("("):
            depth = 0
            end = 0
            for i, ch in enumerate(chunk):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            chunk = chunk[:end] if end else chunk[:1200]
        for wm in re.finditer(r'"([^"]{8,240})"', chunk):
            for tok in _wmi_token_from_literal(wm.group(1)):
                out.append(tok)
    if not out and "api where" in q.lower():
        for cls in re.findall(r"\b(Win32_[A-Za-z0-9_]+)\b", q):
            out.append(cls)
    out.extend(_wmi_fallback_tokens(q, title=title))
    seen: Set[str] = set()
    uniq: List[str] = []
    for x in out:
        k = x.lower()
        if k in seen or len(k) < 3:
            continue
        seen.add(k)
        uniq.append(x)
    return uniq[:12]


def _wmi_fallback_tokens(query: str, *, title: str = "") -> List[str]:
    t = (title or "").lower()
    ql = (query or "").lower()
    hints: List[str] = []
    if "defender exclusion" in t or "mppreference" in ql:
        hints.append("MSFT_MpPreference")
        hints.append("Add")
    if "stdregprov" in t or "stdregprov" in ql:
        hints.append("StdRegProv")
        hints.append("SetStringValue")
    if "shadow copy" in t or "win32_shadowcopy" in ql:
        hints.append("Win32_ShadowCopy")
    if "process creation" in t and "wmi" in t:
        hints.append("Win32_Process")
        hints.append("Create")
    if "event consumer" in t or "filtertoconsumerbinding" in ql:
        hints.append("FilterToConsumerBinding")
        hints.append("PutInstance")
    if "enumeration" in t and "wmi" in t:
        hints.append("Win32_ComputerSystemProduct")
        hints.append("Win32_Process")
    seen: Set[str] = set()
    out: List[str] = []
    for h in hints:
        k = h.lower()
        if k not in seen:
            seen.add(k)
            out.append(h)
    return out


def _extract_exclude_user_ids(query: str) -> List[str]:
    q = query or ""
    out: List[str] = []
    m = re.search(r"not user\.id in\s*\(([^)]+)\)", q, re.I)
    if m:
        for part in m.group(1).split(","):
            s = part.strip().strip('"').strip("'")
            if s.upper().startswith("S-1-"):
                out.append(s.upper())
    for m2 in re.finditer(r'user\.id\s*!=\s*"([^"]+)"', q, re.I):
        out.append(m2.group(1).upper())
    return out[:8]


def _extract_api_name(query: str) -> str:
    q = query or ""
    m = re.search(r'process\.Ext\.api\.name\s*==\s*"([^"]+)"', q, re.I)
    if m:
        return m.group(1)
    m_like = re.search(r'process\.Ext\.api\.name\s+like\s+"(IWbemServices::[^"]+)"', q, re.I)
    if m_like:
        raw = m_like.group(1).replace("*", "")
        if "DeleteInstance" in raw:
            return "IWbemServices::ExecMethod"
        return raw
    m2 = re.search(r'api\.name\s*:\s*"([^"]+)"', q, re.I)
    if m2:
        return m2.group(1)
    ql = q.lower()
    if "api where" not in ql:
        return ""
    if re.search(r'process\.Ext\.api\.name\s*==\s*"ldap_search"', q, re.I):
        return "ldap_search"
    if "execquery" in ql or re.search(r"select\s+\*\s+from\s+win32_", ql):
        return "IWbemServices::ExecQuery"
    if any(x in ql for x in ("putinstance", "filtertoconumerbinding", "execmethod", "parameters.operation")):
        return "IWbemServices::ExecMethod"
    if "process.ext.api.summary" in ql and ("putinstance" in ql or "execquery" in ql):
        return "IWbemServices::ExecMethod" if "putinstance" in ql else "IWbemServices::ExecQuery"
    return ""


def build_api_call_rules(
    *, max_rules: int = 160, max_ldap: int = 20, max_wmi: int = 16,
) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    ldap_n = 0
    wmi_n = 0
    for path in iter_behavior_tomls():
        rule = _parse_rule_toml(path)
        if not rule:
            continue
        q = str(rule.get("query") or "")
        if "api where" not in q.lower():
            continue
        if "amsiscanbuffer" in q.lower():
            continue
        api = _extract_api_name(q)
        if not api:
            continue
        if api not in _WIN32K_APIS and api not in _TI_APIS and api not in _WMI_APIS and api not in _LDAP_APIS:
            continue
        rid = str(rule.get("rule_id") or rule.get("id") or path.stem)
        key = api.lower() + "|" + rid.split("-")[0]
        if key in seen:
            continue
        proc_names, _, _ = _extract_amsi_patterns(q)
        sev = edi._severity(rule)
        ldap_filters: Optional[List[str]] = None
        wmi_ops: Optional[List[str]] = None
        title = str(rule.get("name") or path.stem)
        if api in _LDAP_APIS:
            if ldap_n >= max_ldap:
                continue
            ldap_filters = _extract_ldap_filters(q)
            if not ldap_filters:
                ldap_filters = _ldap_fallback_tokens(q, title=title)
            if not ldap_filters:
                continue
        elif api in _WMI_APIS:
            if wmi_n >= max_wmi:
                continue
            wmi_ops = _extract_wmi_operation_tokens(q, title=title)
            if not wmi_ops:
                continue
        seen.add(key)
        item: Dict[str, Any] = {
            "id": "api." + rid.split("-")[0][:24],
            "kind": "api_call",
            "title": str(rule.get("name") or path.stem)[:120],
            "severity": sev if sev in ("critical", "high", "medium") else "high",
            "api_names": [api],
            "process_names": proc_names[:8],
            "exclude_user_ids": _extract_exclude_user_ids(q),
            "protections_rule_id": rid,
            "enabled": True,
        }
        if api in _LDAP_APIS and ldap_filters:
            if len(ldap_filters) == 1:
                item["search_filter_all"] = ldap_filters
            else:
                item["search_filter_any"] = ldap_filters
        elif api in _WMI_APIS and wmi_ops:
            item["operation_contains"] = wmi_ops
        elif api == "GetAsyncKeyState":
            item["min_background_call_count"] = 400
            item["min_ms_since_last_key"] = 100
        elif api == "SetWindowsHookEx":
            item["hook_filter_types"] = [13, 14]
        if api in _LDAP_APIS:
            ldap_n += 1
        if api in _WMI_APIS:
            wmi_n += 1
        rules.append(item)
        if len(rules) >= max_rules:
            break
    return rules


def build_api_rules_document(
    *, max_amsi: int = 96, max_api: int = 160, max_ldap: int = 20, max_wmi: int = 16,
) -> Dict[str, Any]:
    amsi_doc = build_amsi_document(max_rules=max_amsi)
    rules = list(amsi_doc.get("rules") or [])
    rules.extend(build_api_call_rules(max_rules=max_api, max_ldap=max_ldap, max_wmi=max_wmi))
    rev = hashlib.sha256(json.dumps(rules, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:12]
    return {
        "version": 2,
        "profile": "protections-api-unified",
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "rev": rev,
        "rules": rules,
    }


def _map_sequence_step(kind: str, body: str) -> Optional[Dict[str, Any]]:
    k = kind.lower()
    body_l = body.lower()
    if k == "process":
        step: Dict[str, Any] = {"etype": "process_create"}
        m = re.search(r'parent\.name\s*:\s*"([^"]+)"', body, re.I)
        if m:
            step["parent_name_contains"] = m.group(1).replace(".exe", "")
        m2 = re.search(r'process\.name\s*:\s*"([^"]+)"', body, re.I)
        if m2:
            step["summary_contains"] = m2.group(1).replace(".exe", "")
        m2b = re.search(r'process\.name\s*:\s*\(\s*"([^"]+)"', body, re.I)
        if m2b and not step.get("summary_contains"):
            step["summary_contains"] = m2b.group(1).replace(".exe", "")
        if "unsigned" in body_l and "code_signature" in body_l:
            step["reputation_not"] = "trusted"
        return step
    if k == "network":
        step: Dict[str, Any] = {"etype": "network_connect_etw"}
        mport = re.search(r"destination\.port\s*==\s*(\d+)", body, re.I)
        if mport:
            step["destination_port"] = int(mport.group(1))
        return step
    if k == "file":
        return {"etype": "file_create"}
    if k == "registry":
        return {"etype": "registry_set"}
    if k == "api":
        if "amsiscanbuffer" in body_l:
            step = {"etype": "api_amsi"}
            if "buffer" in body_l:
                m = re.search(r'"(\*[^"]{4,80}\*)"', body)
                if m:
                    step["buffer_contains"] = m.group(1).strip("*")
            return step
        step = {"etype": "api_call"}
        m = re.search(r'api\.name\s*==\s*"([^"]+)"', body, re.I)
        if not m:
            m = re.search(r'process\.Ext\.api\.name\s*==\s*"([^"]+)"', body, re.I)
        if m:
            step["api_name"] = m.group(1)
        elif "ldap_search" in body_l:
            step["api_name"] = "ldap_search"
        elif "execquery" in body_l:
            step["api_name"] = "IWbemServices::ExecQuery"
        elif "execmethod" in body_l or "putinstance" in body_l:
            step["api_name"] = "IWbemServices::ExecMethod"
        if step.get("api_name") == "ldap_search":
            lf = _extract_ldap_filters(body)
            if not lf:
                lf = _ldap_fallback_tokens(body, title="")
            if len(lf) == 1:
                step["search_filter_contains"] = lf[0]
        wops = _extract_wmi_operation_tokens(body, title="")
        if wops and step.get("api_name", "").startswith("IWbemServices"):
            step["operation_contains"] = wops[0]
        return step
    if k == "library":
        dlls = _extract_dll_name_literals(body)
        if not dlls:
            return None
        return {"etype": "image_load_etw", "image_contains": dlls[0]}
    return None


def _ptm_process_step_weak(step: Dict[str, Any]) -> bool:
    if step.get("etype") != "process_create":
        return False
    return not (
        step.get("summary_contains")
        or step.get("parent_name_contains")
        or step.get("reputation_not")
        or step.get("path_regex")
    )


_PTM_SEQUENCE_PRIORITY = (
    "credential_access_ldap_search_followed_by_kerberos_connection.toml",
    "credential_access_suspicious_vault_client_image_load.toml",
    "execution_execution_via_wmi_followed_by_network_connection.toml",
)


def _iter_ptm_sequence_paths() -> List[Path]:
    allp = iter_behavior_tomls()
    pri_names = set(_PTM_SEQUENCE_PRIORITY)
    pri = [p for p in allp if p.name in pri_names]
    rest = [p for p in allp if p.name not in pri_names]
    return pri + rest


def _sequence_query_too_heavy(query: str) -> bool:
    q = (query or "").lower()
    if "effective_parent" in q:
        return True
    if "descendant of" in q:
        return True
    if "cidrmatch" in q:
        return True
    if "process.ext.token" in q:
        return True
    return False


def build_ptm_from_sequences(*, max_rules: int = 120) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for path in _iter_ptm_sequence_paths():
        rule = _parse_rule_toml(path)
        if not rule:
            continue
        q = str(rule.get("query") or "")
        if "sequence" not in q.lower():
            continue
        if _sequence_query_too_heavy(q):
            continue
        steps_raw = re.findall(
            r"\[(process|network|file|registry|api|library)\s+where([^\]]+)\]",
            q,
            re.I | re.S,
        )
        if len(steps_raw) < 2 or len(steps_raw) > 4:
            continue
        steps: List[Dict[str, Any]] = []
        ok = True
        for kind, body in steps_raw[:4]:
            st = _map_sequence_step(kind, body)
            if not st:
                ok = False
                break
            steps.append(st)
        if not ok or len(steps) < 2:
            continue
        if all(_ptm_process_step_weak(s) for s in steps):
            continue
        win = 300
        m = re.search(r"maxspan\s*=\s*(\d+)m", q, re.I)
        if m:
            win = int(m.group(1)) * 60
        else:
            ms = re.search(r"maxspan\s*=\s*(\d+)s", q, re.I)
            if ms:
                win = int(ms.group(1))
        rid = str(rule.get("rule_id") or rule.get("id") or path.stem)
        out.append({
            "id": "ptm.prot." + rid.split("-")[0][:20],
            "type": "entity_sequence" if "entity_id" in q.lower() else "sequence",
            "same_entity_id": "entity_id" in q.lower(),
            "title": str(rule.get("name") or path.stem)[:120],
            "severity": edi._severity(rule) if edi._severity(rule) in ("critical", "high", "medium") else "high",
            "window_sec": win,
            "steps": steps,
            "source": "protections-artifacts",
            "protections_rule_id": rid,
        })
        if len(out) >= max_rules:
            break
    return out


def _merge_ptm_generated(extra: List[Dict[str, Any]]) -> int:
    if not extra:
        return 0
    doc = _read_json(_PTM)
    if not doc:
        doc = {"version": "1", "rules": []}
    by_id = {str(r.get("id") or ""): r for r in (doc.get("rules") or []) if isinstance(r, dict)}
    n = 0
    for r in extra:
        rid = str(r.get("id") or "").strip()
        if not rid:
            continue
        if rid not in by_id:
            n += 1
        by_id[rid] = r
    doc["rules"] = list(by_id.values())
    doc["updated_at"] = time.strftime("%Y-%m-%d")
    _PTM.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return n


def load_amsi_rules(*, enabled_only: bool = True) -> List[Dict[str, Any]]:
    if not _AMSI_OUT.is_file():
        return []
    try:
        doc = json.loads(_AMSI_OUT.read_text(encoding="utf-8"))
    except Exception:
        return []
    rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
    if enabled_only:
        rules = [r for r in rules if r.get("enabled", True)]
    return rules[:500]


def export_amsi_document() -> Dict[str, Any]:
    doc = export_api_rules_document()
    rules = [r for r in (doc.get("rules") or []) if str(r.get("kind") or "amsi_buffer") == "amsi_buffer"]
    out = dict(doc)
    out["rules"] = rules
    return out


def export_api_rules_document() -> Dict[str, Any]:
    if _API_OUT.is_file():
        try:
            doc = json.loads(_API_OUT.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and doc.get("rules") is not None:
                return doc
        except Exception:
            pass
    return build_api_rules_document()


def _merge_ptm_extras(pol: Dict[str, Any]) -> int:
    extra = pol.get("ptm_extra_rules")
    if not isinstance(extra, list) or not extra:
        return 0
    doc = _read_json(_PTM)
    if not doc:
        doc = {"version": "1", "rules": []}
    by_id = {str(r.get("id") or ""): r for r in (doc.get("rules") or []) if isinstance(r, dict)}
    n = 0
    for r in extra:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id") or "").strip()
        if not rid:
            continue
        if rid not in by_id:
            n += 1
        by_id[rid] = r
    doc["rules"] = list(by_id.values())
    doc["updated_at"] = time.strftime("%Y-%m-%d")
    _PTM.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return n


def apply_bundle(*, write: bool = True, dry_run: bool = False) -> Dict[str, Any]:
    pol = load_policy()
    root = protections_root()
    if not root.is_dir():
        return {"ok": False, "error": f"未找到 protections 目录: {root}"}

    yar_src = pick_yara_files(pol)
    ycfg = pol.get("yara") if isinstance(pol.get("yara"), dict) else {}
    prefix = str(ycfg.get("filename_prefix") or "ep_")
    evm_doc = build_evm_document()
    api_doc = build_api_rules_document()
    amsi_doc = {"rules": [r for r in (api_doc.get("rules") or []) if r.get("kind") == "amsi_buffer"]}
    ptm_seq = build_ptm_from_sequences()
    cat = scan_behavior_catalog()

    out: Dict[str, Any] = {
        "ok": True,
        "dry_run": dry_run,
        "protections_root": str(root),
        "yara_selected": len(yar_src),
        "yara_files": [p.name for p in yar_src[:20]],
        "evm_rules": len(evm_doc.get("rules") or []),
        "evm_library_rules": int(evm_doc.get("library_rules") or 0),
        "amsi_rules": len(amsi_doc.get("rules") or []),
        "api_call_rules": len([r for r in (api_doc.get("rules") or []) if r.get("kind") == "api_call"]),
        "api_rules_total": len(api_doc.get("rules") or []),
        "ptm_sequence_rules": len(ptm_seq),
        "catalog_stats": cat.get("stats"),
    }

    if dry_run:
        return out

    yar_names, yar_bytes = _sync_yara_files(yar_src, prefix=prefix)
    _update_manifest(yar_names)
    _CATALOG_OUT.parent.mkdir(parents=True, exist_ok=True)
    _CATALOG_OUT.write_text(json.dumps(cat, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _EVM_OUT.write_text(json.dumps(evm_doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _API_OUT.write_text(json.dumps(api_doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _AMSI_OUT.write_text(json.dumps(export_amsi_document(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ptm_n = _merge_ptm_extras(pol)
    ptm_n += _merge_ptm_generated(ptm_seq)

    out["yara_deployed"] = len(yar_names)
    out["yara_bytes"] = yar_bytes
    out["evm_path"] = str(_EVM_OUT)
    out["catalog_path"] = str(_CATALOG_OUT)
    out["ptm_merged"] = ptm_n
    out["amsi_path"] = str(_AMSI_OUT)
    out["api_rules_path"] = str(_API_OUT)

    if write:
        try:
            from . import agent_sync

            agent_sync.bump_sync("memory_yara")
            agent_sync.bump_sync("evm")
            agent_sync.bump_sync("ptm")
            agent_sync.bump_sync("amsi")
            agent_sync.bump_sync("api_rules")
        except Exception:
            pass
    return out


def bundle_summary_hash() -> str:
    evm = _read_json(_EVM_OUT)
    blob = json.dumps({"evm": evm.get("rules", [])}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()[:12]
