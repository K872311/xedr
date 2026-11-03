"""网络外联分析：仅告警「云厂商」与「非境内」目标。"""
from __future__ import annotations
from typing import Dict, List, Set, Tuple

from .. import ip_catalog
from ..models import Finding
from ..net_process import conn_pid, conn_proc_label, enrich_report_connections
from ..rules_loader import RuleStore
from .util import conn_local, conn_remote, conn_remote_ip, is_private_ip


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    _ = store
    findings: List[Finding] = []
    matched = []
    counts = {"private": 0, "domestic": 0, "cloud": 0, "overseas": 0, "invalid": 0, "alerted": 0}
    try:
        ip_catalog.ensure_loaded()
    except Exception as e:
        print("[network] ip_catalog load:", e)

    enrich_report_connections(report)
    by_ip: Dict[str, list] = {}
    for c in report.get("established_connections") or []:
        if not isinstance(c, dict):
            continue
        ip = conn_remote_ip(c)
        if not ip:
            continue
        by_ip.setdefault(ip, []).append(c)

    for ip, rows in by_ip.items():
        c0 = rows[0]
        rm = conn_remote(c0)
        if is_private_ip(ip):
            counts["private"] += 1
            continue
        info = ip_catalog.classify_ip(ip)
        cls = str(info.get("class") or "overseas")
        counts[cls] = counts.get(cls, 0) + 1
        if not info.get("alert"):
            continue
        counts["alerted"] += 1
        provider = str(info.get("provider") or "")
        proc_labels = []
        seen_lab = set()
        for c in rows:
            lab = conn_proc_label(c)
            if lab and lab not in seen_lab:
                seen_lab.add(lab)
                proc_labels.append(lab)
            if len(proc_labels) >= 6:
                break
        proc_s = "、".join(proc_labels)
        if cls == "cloud":
            title = f"云外联 {ip}" + (f" ({provider})" if provider else "")
            if proc_labels:
                title += f" · {proc_labels[0].split(' (PID')[0]}"
            sev = "medium"
            rid = f"egress-cloud|{provider or 'cloud'}"
            tag = "cloud"
        else:
            title = f"境外外联 {ip}"
            if proc_labels:
                title += f" · {proc_labels[0].split(' (PID')[0]}"
            sev = "medium"
            rid = "egress-overseas"
            tag = "overseas"
        local = conn_local(c0)
        proc_bit = f"{proc_s}  " if proc_s else (f"(PID {c0.get('pid', '')}) " if c0.get("pid") else "")
        evidence = f"{proc_bit}{local} → {rm or ip} · {provider or cls}".strip()
        key = f"网络外联|{title}|{evidence}|网络连接"
        if key in seen:
            continue
        seen.add(key)
        matched.append({
            "category": "外联", "type": tag, "name": rm or ip,
            "class": cls, "provider": provider, "process": proc_s,
        })
        findings.append(Finding(
            "网络外联", sev, title, evidence, "网络连接", rid, "network",
            extra={
                "ip_class": cls,
                "provider": provider,
                "remote": rm or ip,
                "local": local,
                "pid": conn_pid(c0) or None,
                "process_name": str(c0.get("process_name") or "").strip(),
                "process_path": str(c0.get("process_path") or "").strip(),
                "processes": proc_labels,
            },
        ))
    return findings, {
        "matched_suspicious": matched,
        "egress_stats": counts,
        "ip_catalog": ip_catalog.stats(),
    }
