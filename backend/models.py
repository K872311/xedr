from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    evidence: str = ""
    source: str = ""
    rule_id: str = ""
    matcher: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    # 证据锚点（渐进）：pack 模块 / 路径 / 哈希等，供详情页定位
    anchor: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # 兼容旧前端字段
        d["type"] = self.category
        d["name"] = self.title
        d["reason"] = self.evidence or self.title
        if not d.get("anchor"):
            d.pop("anchor", None)
        return d


def build_anchor(
    *,
    host: str = "",
    source: str = "",
    line: Any = None,
    sha256: str = "",
    md5: str = "",
    pack_file: str = "",
    path: str = "",
    module: str = "",
    kind: str = "",
    **extra: Any,
) -> Optional[Dict[str, Any]]:
    """统一锚点形状：优先 {host, source, line, sha256, pack_file}。"""
    path = str(path or "").strip()
    sha = str(sha256 or "").strip().lower()
    md5v = str(md5 or "").strip().lower()
    pack = str(pack_file or "").strip()
    host = str(host or "").strip()
    source = str(source or "").strip()
    module = str(module or "").strip()
    if line is None:
        line_s = ""
    else:
        line_s = str(line).strip()
    if not (path or sha or md5v or pack or line_s):
        return None
    out: Dict[str, Any] = {}
    if host:
        out["host"] = host
    if source:
        out["source"] = source
    if line_s:
        out["line"] = line_s
    if sha:
        out["sha256"] = sha
    if md5v:
        out["md5"] = md5v
    if pack:
        out["pack_file"] = pack
        out["pack"] = pack  # 兼容旧字段
    if path:
        out["path"] = path
    if module:
        out["module"] = module
    for k, v in extra.items():
        if v is None or v == "" or k in out:
            continue
        out[k] = v
    if not out.get("kind"):
        out["kind"] = kind or ("file" if path else ("hash" if (sha or md5v) else "pack"))
    return out


def infer_anchor_from_extra(
    extra: Optional[Dict[str, Any]] = None,
    *,
    evidence: str = "",
    source: str = "",
    host: str = "",
    line: Any = None,
) -> Optional[Dict[str, Any]]:
    """从 extra/证据里尽量抽出锚点（不强制）。"""
    ex = extra if isinstance(extra, dict) else {}
    path = str(
        ex.get("path") or ex.get("full_path") or ex.get("file") or ex.get("process_path") or ""
    ).strip()
    if isinstance(ex.get("file"), dict):
        path = path or str(ex["file"].get("full_path") or ex["file"].get("path") or "").strip()
    sha = str(ex.get("sha256") or "").strip().lower()
    md5 = str(ex.get("md5") or "").strip().lower()
    pack = str(
        ex.get("pack_file") or ex.get("pack") or ex.get("pack_name") or ""
    ).strip()
    module = str(ex.get("module") or "").strip()
    host = str(host or ex.get("host") or ex.get("hostname") or "").strip()
    src = str(source or ex.get("source") or "").strip()
    line_v = line if line is not None else ex.get("line")
    if line_v is None and ex.get("event_id") is not None:
        line_v = ex.get("event_id")
    if not path and evidence:
        # 证据首行若像路径
        first = str(evidence).split("\n", 1)[0].strip()
        if ("\\" in first or first.startswith("/")) and len(first) < 400:
            path = first.split(" — ")[0].split(" | ")[0].strip()
        # 证据中 SHA256=
        if not sha:
            m = __import__("re").search(r"\b([a-fA-F0-9]{64})\b", str(evidence))
            if m:
                sha = m.group(1).lower()
    if not pack and path:
        # 粗分模块
        low = path.replace("/", "\\").lower()
        if "\\windows\\system32\\drivers\\" in low or low.endswith(".sys"):
            pack = "persistence.json"
            module = module or "persistence"
        elif any(x in low for x in ("\\prefetch\\", "\\temp\\", "\\users\\")):
            pack = "files.jsonl"
            module = module or "files"
        else:
            pack = "files.jsonl"
            module = module or "files"
    elif pack and not module:
        lowp = pack.lower()
        if "file" in lowp:
            module = "files"
        elif "persist" in lowp:
            module = "persistence"
        elif "usn" in lowp or "disk" in lowp:
            module = "disk"
        elif "process" in lowp:
            module = "process"
    return build_anchor(
        host=host,
        source=src,
        line=line_v,
        sha256=sha,
        md5=md5,
        pack_file=pack,
        path=path,
        module=module,
    )


def empty_analysis() -> Dict[str, Any]:
    return {
        "matched_rmm": [],
        "matched_suspicious": [],
        "matched_encryption": [],
        "matched_ransom": [],
        "matched_files": [],
        "matched_keywords": [],
        "matched_persistence": [],
        "ioc_hits": {"md5": [], "sha1": [], "sha256": [], "domain": [], "ip": [], "url": []},
        "findings": [],
        "ai": None,
        "pipeline": {"matchers": [], "rules_used": []},
        "summary": {"total": 0, "high": 0, "medium": 0, "low": 0, "ioc_total": 0},
    }


def summarize(findings: List[Finding], ioc_hits: Optional[Dict] = None) -> Dict[str, int]:
    sev_map = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"}
    s = {"total": len(findings), "high": 0, "medium": 0, "low": 0, "ioc_total": 0}
    for f in findings:
        bucket = sev_map.get((f.severity or "medium").lower(), "medium")
        s[bucket] = s.get(bucket, 0) + 1
    if ioc_hits:
        for v in ioc_hits.values():
            s["ioc_total"] += len(v or [])
    return s
