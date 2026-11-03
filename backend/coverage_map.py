"""采集覆盖度：对照 wininfosc/linuxsc 映射，写出 reports/<rid>/coverage.json。"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config
from . import paths as P

_MAP_CACHE: Dict[str, Any] = {}


def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        # 无 PyYAML 时做极简解析（仅本仓库 map 格式）
        return _minimal_yaml_modules(text)


def _minimal_yaml_modules(text: str) -> Dict[str, Any]:
    """无 PyYAML 时的兜底：抽出 modules 列表的 id/label/pack/paths。"""
    modules: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    list_key = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith("collector:"):
            continue
        if line.startswith("schema:"):
            continue
        if line.startswith("modules:"):
            continue
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if stripped.startswith("- id:"):
            if cur:
                modules.append(cur)
            cur = {"id": stripped.split(":", 1)[1].strip(), "forensic_paths": [], "linuxsc_paths": [], "report_keys": []}
            list_key = ""
            continue
        if cur is None:
            continue
        if indent >= 4 and ":" in stripped and not stripped.startswith("- "):
            k, _, v = stripped.partition(":")
            k, v = k.strip(), v.strip()
            if k in ("label", "pack"):
                cur[k] = v
                list_key = ""
            elif k in ("forensic_paths", "linuxsc_paths", "report_keys"):
                list_key = k
                cur.setdefault(k, [])
            continue
        if list_key and stripped.startswith("- "):
            cur.setdefault(list_key, []).append(stripped[2:].strip())
    if cur:
        modules.append(cur)
    return {"modules": modules}


def load_collector_map(os_family: str = "windows") -> Dict[str, Any]:
    fam = "linux" if str(os_family or "").lower() == "linux" else "windows"
    if fam in _MAP_CACHE:
        return _MAP_CACHE[fam]
    name = "linuxsc-map.yaml" if fam == "linux" else "wininfosc-map.yaml"
    path = config.CONFIG_DIR / name
    data = _load_yaml(path)
    data["_path"] = str(path)
    data["_os_family"] = fam
    _MAP_CACHE[fam] = data
    return data


def reload_maps() -> None:
    _MAP_CACHE.clear()


def _pack_dir(rid: str) -> Path:
    from .collect_pack import pack_dir_for_rid
    return pack_dir_for_rid(rid, create=False)


def _list_present(root: Path) -> List[str]:
    if not root.is_dir():
        return []
    out = []
    for p in root.iterdir():
        out.append(p.name)
    return sorted(out)


def _module_mapped(
    mod: Dict[str, Any],
    *,
    pack_names: set,
    source_names: set,
    report: Optional[Dict[str, Any]],
    manifest_mods: Dict[str, Any],
) -> Tuple[bool, List[str], str]:
    """返回 (mapped, hits, reason)。"""
    hits: List[str] = []
    pack = str(mod.get("pack") or "").strip()
    mid = str(mod.get("id") or "")
    if pack and pack in pack_names:
        hits.append(f"pack/{pack}")
    man = manifest_mods.get(mid) if isinstance(manifest_mods, dict) else None
    if isinstance(man, dict) and str(man.get("status") or "").lower() in ("ok", "empty", "dirsnap"):
        hits.append(f"manifest:{mid}")
    for key in ("forensic_paths", "linuxsc_paths"):
        for name in mod.get(key) or []:
            n = str(name).strip()
            if not n:
                continue
            if n in source_names or any(s == n or s.startswith(n + "/") for s in source_names):
                hits.append(n)
    if report:
        for rk in mod.get("report_keys") or []:
            v = report.get(rk)
            if isinstance(v, list) and v:
                hits.append(f"report:{rk}")
            elif isinstance(v, dict) and v:
                hits.append(f"report:{rk}")
            elif isinstance(v, str) and v.strip():
                hits.append(f"report:{rk}")
            elif v not in (None, "", [], {}):
                hits.append(f"report:{rk}")
    if hits:
        return True, hits, "present"
    return False, [], "missing"


def compute_coverage(
    rid: str,
    report: Optional[Dict[str, Any]] = None,
    *,
    source_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """对照映射表，统计已映射 / 未映射路径。"""
    from .os_detect import detect_os_family
    from .collect_pack import load_pack_manifest

    fam = detect_os_family(report) if report else "windows"
    if report and str(report.get("os_family") or "").lower() == "linux":
        fam = "linux"
    cmap = load_collector_map(fam)
    modules = list(cmap.get("modules") or [])

    pack = _pack_dir(rid)
    pack_names = set(_list_present(pack)) if pack.is_dir() else set()
    man = load_pack_manifest(rid) or {}
    manifest_mods = man.get("modules") if isinstance(man.get("modules"), dict) else {}

    src_root = Path(source_root) if source_root else None
    source_names: set = set()
    if src_root and src_root.is_dir():
        source_names = set(_list_present(src_root))
    # 也扫报告目录下可能残留的原始采集根
    rdir = P.report_dir(rid, create=False)
    for cand in ("source", "collect", "linuxsc", "wininfosc", "raw"):
        d = rdir / cand
        if d.is_dir():
            source_names |= set(_list_present(d))

    mapped: List[Dict[str, Any]] = []
    unmapped_expected: List[Dict[str, Any]] = []
    for mod in modules:
        if not isinstance(mod, dict):
            continue
        ok, hits, reason = _module_mapped(
            mod,
            pack_names=pack_names,
            source_names=source_names,
            report=report,
            manifest_mods=manifest_mods,
        )
        row = {
            "id": mod.get("id"),
            "label": mod.get("label") or mod.get("id"),
            "pack": mod.get("pack") or "",
            "hits": hits,
            "status": reason,
        }
        if ok:
            mapped.append(row)
        else:
            unmapped_expected.append(row)

    # 包内 / 源目录出现但不在映射表中的路径
    known_pack = {str(m.get("pack") or "") for m in modules}
    known_pack |= {"manifest.json"}
    known_src: set = set()
    for m in modules:
        for key in ("forensic_paths", "linuxsc_paths"):
            for n in m.get(key) or []:
                known_src.add(str(n).strip())

    unmapped_paths: List[str] = []
    for name in sorted(pack_names):
        if name not in known_pack:
            unmapped_paths.append(f"pack/{name}")
    for name in sorted(source_names):
        if name not in known_src and not name.startswith("."):
            unmapped_paths.append(name)

    return {
        "rid": rid,
        "os_family": fam,
        "collector": cmap.get("collector") or fam,
        "map_file": cmap.get("_path") or "",
        "generated_at": time.time(),
        "summary": {
            "mapped": len(mapped),
            "unmapped_expected": len(unmapped_expected),
            "unmapped_extra": len(unmapped_paths),
            "pack_files": len(pack_names),
        },
        "mapped": mapped,
        "unmapped_expected": unmapped_expected,
        "unmapped_paths": unmapped_paths,
    }


def coverage_path(rid: str) -> Path:
    return P.report_dir(rid, create=False) / "coverage.json"


def write_coverage(
    rid: str,
    report: Optional[Dict[str, Any]] = None,
    *,
    source_root: Optional[Path] = None,
) -> Dict[str, Any]:
    cov = compute_coverage(rid, report, source_root=source_root)
    out = P.report_dir(rid, create=True) / "coverage.json"
    out.write_text(json.dumps(cov, ensure_ascii=False, indent=2), encoding="utf-8")
    return cov


def load_coverage(rid: str) -> Optional[Dict[str, Any]]:
    p = coverage_path(rid)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None
