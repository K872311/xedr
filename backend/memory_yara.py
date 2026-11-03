"""Agent 内存 YARA：轻量包 rules/memory-yara/ + 主库 yara/valhalla-rules.yar。"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from . import config

_ROOT = Path(config.ROOT)
_CONTROLS_PATH = _ROOT / "config" / "memory_yara_controls.json"
_AGENT_PACK_DIRS = (
    _ROOT / "rules" / "memory-yara",
    _ROOT / "agent" / "memory-yara",
)
_EMBEDDED_RULES = _ROOT / "agent" / "data" / "memory_yara_rules.json"
_YARA_DIR = _ROOT / "yara"
_VALHALLA_YAR = _YARA_DIR / "valhalla-rules.yar"
_MAX_VALHALLA_BYTES = 8 * 1024 * 1024


def _agent_pack_dir() -> Path:
    for d in _AGENT_PACK_DIRS:
        if (d / "rules.json").is_file():
            return d
    for d in _AGENT_PACK_DIRS:
        if d.is_dir():
            return d
    return _AGENT_PACK_DIRS[0]


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _valhalla_meta() -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "path": "yara/valhalla-rules.yar",
        "present": False,
        "size": 0,
        "rule_count": 0,
        "retrieved": "",
        "note": "PE 向 YARA（import pe），需 Agent 启用 go-yara；默认构建仍以 rules.json 字符串匹配为主。",
    }
    if not _VALHALLA_YAR.is_file():
        return out
    st = _VALHALLA_YAR.stat()
    out["present"] = True
    out["size"] = st.st_size
    try:
        head = _VALHALLA_YAR.read_text(encoding="utf-8", errors="replace")[:4096]
        m = re.search(r"Number of Rules:\s*(\d+)", head)
        if m:
            out["rule_count"] = int(m.group(1))
        m2 = re.search(r"Retrieved:\s*(.+)", head)
        if m2:
            out["retrieved"] = m2.group(1).strip()
    except OSError:
        pass
    return out


def _load_agent_pack_files() -> Tuple[Dict[str, str], Dict[str, Any], List[str]]:
    """读取 Agent 包内文件 + 可选附加 Valhalla。"""
    pack = _agent_pack_dir()
    manifest_path = pack / "manifest.json"
    missing: List[str] = []
    if manifest_path.is_file():
        manifest = json.loads(_read_text(manifest_path))
        file_names = [str(x) for x in (manifest.get("files") or []) if str(x).strip()]
    else:
        file_names = sorted(
            p.name for p in pack.iterdir()
            if p.is_file() and p.suffix.lower() in (".json", ".yar") and p.name != "manifest.json"
        ) if pack.is_dir() else []
        rev = "1"
        rules_p = pack / "rules.json"
        if rules_p.is_file():
            try:
                rev = str(json.loads(_read_text(rules_p)).get("rev") or rev)
            except Exception:
                pass
        manifest = {
            "id": "agent-memory-yara",
            "name": "Agent 内存扫描轻量包",
            "version": rev,
            "updated_at": "",
            "description": "rules.json 字符串规则 + 可选 .yar（目录：rules/memory-yara 或 agent/memory-yara）",
            "files": file_names,
        }
        if not file_names and _EMBEDDED_RULES.is_file():
            file_names = ["rules.json"]
            manifest["files"] = file_names
    files: Dict[str, str] = {}
    if not file_names and _EMBEDDED_RULES.is_file():
        files["rules.json"] = _read_text(_EMBEDDED_RULES)
    for name in file_names:
        fp = pack / str(name)
        if name == "rules.json" and not fp.is_file() and _EMBEDDED_RULES.is_file():
            files[str(name)] = _read_text(_EMBEDDED_RULES)
            continue
        if fp.is_file():
            files[str(name)] = _read_text(fp)
        else:
            missing.append(str(name))
    if _VALHALLA_YAR.is_file() and _VALHALLA_YAR.stat().st_size <= _MAX_VALHALLA_BYTES:
        files["valhalla-rules.yar"] = _read_text(_VALHALLA_YAR)
    elif _VALHALLA_YAR.is_file():
        missing.append("valhalla-rules.yar(过大，未编入 Agent 包)")
    return files, manifest, missing


_DEFAULT_CONTROLS: Dict[str, Any] = {
    "version": 1,
    "groups": {
        "protections_yara": True,
        "builtin_yara": True,
        "valhalla_yara": False,
        "string_rules": True,
    },
    "disabled_string_rule_ids": [],
}


def load_controls() -> Dict[str, Any]:
    if not _CONTROLS_PATH.is_file():
        return dict(_DEFAULT_CONTROLS)
    try:
        raw = json.loads(_CONTROLS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return dict(_DEFAULT_CONTROLS)
    if not isinstance(raw, dict):
        return dict(_DEFAULT_CONTROLS)
    out = dict(_DEFAULT_CONTROLS)
    grp = raw.get("groups")
    if isinstance(grp, dict):
        g = dict(out["groups"])
        for k in g:
            if k in grp and isinstance(grp[k], bool):
                g[k] = grp[k]
        out["groups"] = g
    ids = raw.get("disabled_string_rule_ids")
    if isinstance(ids, list):
        out["disabled_string_rule_ids"] = [str(x).strip() for x in ids if str(x).strip()]
    out["updated_at"] = str(raw.get("updated_at") or "")
    return out


def save_controls(doc: Dict[str, Any]) -> Dict[str, Any]:
    cur = load_controls()
    grp_in = doc.get("groups")
    if isinstance(grp_in, dict):
        g = dict(cur["groups"])
        for k in g:
            if k in grp_in and isinstance(grp_in[k], bool):
                g[k] = grp_in[k]
        cur["groups"] = g
    if "disabled_string_rule_ids" in doc:
        ids = doc.get("disabled_string_rule_ids")
        if isinstance(ids, list):
            cur["disabled_string_rule_ids"] = [str(x).strip() for x in ids if str(x).strip()]
    cur["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    _CONTROLS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONTROLS_PATH.write_text(json.dumps(cur, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        from . import agent_sync

        agent_sync.bump_sync("memory_yara")
    except Exception:
        pass
    return cur


def _yar_group(name: str) -> str:
    low = str(name or "").lower()
    if low == "valhalla-rules.yar":
        return "valhalla_yara"
    if low.startswith("ep_") or low.startswith("windows_"):
        return "protections_yara"
    return "builtin_yara"


def _controls_digest(controls: Dict[str, Any]) -> str:
    blob = json.dumps(controls, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:10]


def _string_rule_enabled(rule: Dict[str, Any], controls: Dict[str, Any]) -> bool:
    groups = controls.get("groups") or {}
    if not groups.get("string_rules", True):
        return False
    rid = str(rule.get("id") or "").strip()
    disabled: Set[str] = set(str(x) for x in (controls.get("disabled_string_rule_ids") or []))
    return rid not in disabled


def _yar_file_enabled(name: str, controls: Dict[str, Any]) -> bool:
    gname = _yar_group(name)
    groups = controls.get("groups") or {}
    return bool(groups.get(gname, True))


def apply_controls(
    files: Dict[str, str],
    manifest: Dict[str, Any],
    controls: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """按控制台开关过滤 Agent 实际下发的 rules.json / .yar。"""
    controls = controls or load_controls()
    out_files: Dict[str, str] = {}
    for name, content in files.items():
        low = name.lower()
        if low.endswith(".yar"):
            if _yar_file_enabled(name, controls):
                out_files[name] = content
            continue
        if name == "rules.json":
            try:
                doc = json.loads(content)
            except Exception:
                out_files[name] = content
                continue
            rules = doc.get("rules") or []
            if not isinstance(rules, list):
                out_files[name] = content
                continue
            kept = [r for r in rules if isinstance(r, dict) and _string_rule_enabled(r, controls)]
            doc = dict(doc)
            doc["rules"] = kept
            out_files[name] = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
            continue
        out_files[name] = content
    man = dict(manifest or {})
    man["files"] = [n for n in (man.get("files") or []) if n in out_files]
    man["controls_rev"] = _controls_digest(controls)
    return out_files, man


def bundle(rev: str = "") -> Dict[str, Any]:
    files, manifest, missing = _load_agent_pack_files()
    controls = load_controls()
    files, manifest = apply_controls(files, manifest, controls)
    if not files.get("rules.json"):
        tried = ", ".join(str(d) for d in _AGENT_PACK_DIRS)
        return {
            "ok": False,
            "error": f"memory-yara 规则包不完整（缺少 rules.json）。已查找：{tried}",
            "missing": missing,
            "pack_dir": str(_agent_pack_dir()),
        }
    rules_doc = json.loads(files.get("rules.json") or "{}")
    base_rev = str(rules_doc.get("rev") or manifest.get("version") or "").strip()
    vh = hashlib.sha256(files.get("valhalla-rules.yar", "").encode("utf-8")).hexdigest()[:8]
    ctag = _controls_digest(controls)
    pack_rev = base_rev
    if vh and files.get("valhalla-rules.yar"):
        pack_rev += f"+vh{vh}"
    pack_rev += f"+c{ctag}"
    blob = json.dumps({"manifest": manifest, "files": files, "controls": controls}, ensure_ascii=False, sort_keys=True)
    sha = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    return {
        "ok": True,
        "rev": pack_rev,
        "manifest": manifest,
        "files": files,
        "sha256": sha,
        "rule_count": len(rules_doc.get("rules") or []),
        "missing": missing,
        "valhalla_included": "valhalla-rules.yar" in files,
        "controls": controls,
    }


def list_rules() -> Dict[str, Any]:
    raw_files, manifest, missing = _load_agent_pack_files()
    if not raw_files.get("rules.json"):
        tried = ", ".join(str(d) for d in _AGENT_PACK_DIRS)
        return {
            "ok": False,
            "error": f"memory-yara 规则包不完整（缺少 rules.json）。已查找：{tried}",
            "missing": missing,
        }
    controls = load_controls()
    rules_all = json.loads(raw_files.get("rules.json") or "{}").get("rules") or []
    items: List[Dict[str, Any]] = []
    for r in rules_all:
        if not isinstance(r, dict):
            continue
        row = dict(r)
        row["enabled"] = _string_rule_enabled(r, controls)
        items.append(row)
    yar_all = sorted(k for k in raw_files if str(k).lower().endswith(".yar"))
    yar_meta = [
        {"name": n, "group": _yar_group(n), "enabled": _yar_file_enabled(n, controls)}
        for n in yar_all
    ]
    b = bundle()
    if not b.get("ok"):
        return b
    vh = _valhalla_meta()
    groups = controls.get("groups") or {}
    return {
        "ok": True,
        "rev": b["rev"],
        "sha256": b["sha256"],
        "rule_count": len([x for x in items if x.get("enabled")]),
        "rule_count_total": len(items),
        "yar_active": len([x for x in yar_meta if x.get("enabled")]),
        "yar_total": len(yar_meta),
        "controls": controls,
        "group_labels": {
            "protections_yara": "Elastic Protections YARA（ep_*.yar）",
            "builtin_yara": "内置/其它 .yar",
            "valhalla_yara": "Valhalla 主库 .yar",
            "string_rules": "rules.json 字符串规则",
        },
        "manifest": {
            "id": manifest.get("id"),
            "name": manifest.get("name"),
            "version": manifest.get("version"),
            "updated_at": manifest.get("updated_at"),
            "description": manifest.get("description"),
        },
        "yar_files": [x["name"] for x in yar_meta if x.get("enabled")],
        "yar_files_all": yar_meta,
        "valhalla": vh,
        "valhalla_included_in_agent_bundle": bool(b.get("valhalla_included")),
        "repo_paths": {
            "yara_corpus": "yara/",
            "agent_memory_pack": "rules/memory-yara/",
        },
        "sigma_note": "yara/valhalla-sigma-rules/ 为 Sigma 规则（日志侧），不是 Agent 内存 YARA。",
        "items": items,
    }
