"""管线 operators：匹配器之后的跨报告关联规则。"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import Finding
from .. import config

OPS_DIR = config.RULES_DIR / "operators"


def _load_yaml(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        out: Dict[str, Any] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            k, _, v = line.partition(":")
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if v.lower() in ("true", "yes"):
                out[k] = True
            elif v.lower() in ("false", "no"):
                out[k] = False
            else:
                try:
                    out[k] = int(v)
                except ValueError:
                    out[k] = v
        return out


def list_operator_defs() -> List[Dict[str, Any]]:
    if not OPS_DIR.is_dir():
        return []
    out = []
    for p in sorted(OPS_DIR.glob("*.yaml")) + sorted(OPS_DIR.glob("*.yml")):
        try:
            d = _load_yaml(p)
            if d:
                d["_file"] = p.name
                out.append(d)
        except Exception as e:
            print(f"[operators] load {p.name}: {e}")
    return out


def _system_path(path: str) -> bool:
    low = (path or "").replace("/", "\\").lower()
    needles = (
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\windows\\winsxs\\",
        "\\program files\\windows",
        "/usr/lib/",
        "/lib/",
        "/lib64/",
        "/usr/bin/",
        "/bin/",
        "/sbin/",
    )
    return any(n in low for n in needles)


def _scan_sha256_across_reports(
    *,
    exclude_system: bool = True,
    limit_reports: int = 80,
    per_report_limit: int = 8000,
) -> Dict[str, List[Dict[str, Any]]]:
    """sha256 -> [{hostname, rid, path}, ...]"""
    from ..db_store import list_index, _connect
    from .. import paths as P

    by_hash: Dict[str, List[Dict[str, Any]]] = {}
    rows = list_index(limit=limit_reports) or []
    for meta in rows:
        rid = str(meta.get("file") or "").strip()
        if not rid:
            continue
        host = str(meta.get("hostname") or "").strip() or "unknown"
        dbp = P.resolve_analysis_db(rid)
        if not dbp or not Path(dbp).is_file():
            continue
        conn = _connect(Path(dbp))
        try:
            try:
                files = conn.execute(
                    "SELECT full_path, sha256 FROM files "
                    "WHERE IFNULL(sha256,'')!='' LIMIT ?",
                    (per_report_limit,),
                ).fetchall()
            except Exception:
                continue
            for r in files:
                h = (r["sha256"] or "").strip().lower()
                if len(h) != 64:
                    continue
                path = r["full_path"] or ""
                if exclude_system and _system_path(path):
                    continue
                by_hash.setdefault(h, []).append({
                    "hostname": host,
                    "rid": rid,
                    "path": path,
                })
        finally:
            conn.close()
    return by_hash


def run_cross_host_shared_hash(
    report: Dict[str, Any],
    cfg: Dict[str, Any],
) -> List[Finding]:
    if not cfg.get("enabled", True):
        return []
    min_hosts = max(2, int(cfg.get("min_hosts") or 2))
    match_by = str(cfg.get("match_by") or "host").lower()
    exclude_system = bool(cfg.get("exclude_system", True))
    max_findings = max(1, min(int(cfg.get("max_findings") or 50), 200))
    severity = str(cfg.get("severity") or "high")
    category = str(cfg.get("category") or "横向关联")
    current_rid = str(report.get("_rid") or report.get("_report_file") or "").strip()
    current_host = str(report.get("hostname") or "").strip()

    t0 = time.perf_counter()
    by_hash = _scan_sha256_across_reports(exclude_system=exclude_system)
    findings: List[Finding] = []

    for sha, occs in by_hash.items():
        if len(findings) >= max_findings:
            break
        hosts = sorted({o["hostname"] for o in occs if o.get("hostname")})
        rids = sorted({o["rid"] for o in occs if o.get("rid")})
        if match_by == "report":
            if len(rids) < min_hosts:
                continue
        else:
            if len(hosts) < min_hosts:
                continue
        # 仅当当前报告也命中该哈希时才挂到本报告告警（避免每台机重复全量刷屏）
        if current_rid and not any(o.get("rid") == current_rid for o in occs):
            # 若当前报告无 files 表命中，但主机名匹配且哈希在其它报告——仍跳过
            if current_host and not any(o.get("hostname") == current_host for o in occs):
                continue
            if not current_host:
                continue
            if not any(o.get("hostname") == current_host for o in occs):
                continue

        host_n = len(hosts)
        sample = occs[:8]
        lines = [f"{o['hostname']}: {o['path']}" for o in sample]
        evidence = (
            f"SHA256={sha} · 主机数={host_n} · 报告数={len(rids)}\n"
            + "\n".join(lines)
        )
        local_path = ""
        for o in occs:
            if current_rid and o.get("rid") == current_rid:
                local_path = o.get("path") or ""
                break
        if not local_path and sample:
            local_path = sample[0].get("path") or ""

        findings.append(Finding(
            category=category,
            severity=severity,
            title=f"跨主机共享文件哈希候选（{host_n} 台主机）",
            evidence=evidence[:2000],
            source="operator",
            rule_id=str(cfg.get("id") or "cross-host-shared-hash"),
            matcher="operator",
            extra={
                "sha256": sha,
                "host_count": host_n,
                "hosts": hosts[:20],
                "rids": rids[:20],
                "path": local_path,
                "operator": "cross-host-shared-hash",
                "candidate": True,
                "pack_file": "files.jsonl",
            },
            anchor={
                "kind": "file_hash",
                "host": current_host,
                "source": "operator",
                "sha256": sha,
                "pack_file": "files.jsonl",
                "pack": "files.jsonl",
                "module": "files",
                "path": local_path,
                "hosts": hosts[:10],
            } if local_path or sha else None,
        ))

    ms = int((time.perf_counter() - t0) * 1000)
    print(f"[operators] cross-host-shared-hash findings={len(findings)} ms={ms}")
    return findings


def run_host_usn_time_cluster(
    report: Dict[str, Any],
    cfg: Dict[str, Any],
) -> List[Finding]:
    from .usn_cluster import run_host_usn_time_cluster as _run
    return _run(report, cfg)


_HANDLERS = {
    "cross-host-shared-hash": run_cross_host_shared_hash,
    "host-usn-time-cluster": run_host_usn_time_cluster,
}


def run_operators(
    report: Dict[str, Any],
    *,
    only: Optional[List[str]] = None,
) -> Tuple[List[Finding], Dict[str, Any]]:
    """执行全部（或指定）operators，返回 findings + meta。"""
    defs = list_operator_defs()
    want = {str(x).strip() for x in (only or []) if str(x).strip()} or None
    all_findings: List[Finding] = []
    ran: List[Dict[str, Any]] = []
    for cfg in defs:
        oid = str(cfg.get("id") or cfg.get("_file") or "").strip()
        if want is not None and oid not in want:
            continue
        if not cfg.get("enabled", True):
            ran.append({"operator": oid, "ok": True, "skipped": True, "findings": 0})
            continue
        fn = _HANDLERS.get(oid)
        if not fn:
            ran.append({"operator": oid, "ok": False, "error": "no handler"})
            continue
        t0 = time.perf_counter()
        try:
            found = fn(report, cfg) or []
            ms = int((time.perf_counter() - t0) * 1000)
            all_findings.extend(found)
            ran.append({"operator": oid, "ok": True, "findings": len(found), "ms": ms})
        except Exception as e:
            ms = int((time.perf_counter() - t0) * 1000)
            print(f"[operators] {oid} failed: {e}")
            ran.append({"operator": oid, "ok": False, "error": str(e), "ms": ms})
    return all_findings, {"operators": ran}
