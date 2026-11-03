"""远控软件告警：基于 rules/remote_tools.json 与报告内服务/进程/文件痕迹。"""
from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from ..models import Finding, build_anchor


def run(report: Dict, store, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    del store  # 规则自管
    from ..db_store import files_rid
    from ..remote_tools import analyze_remote_tools

    rid = files_rid(report) or str(report.get("_rid") or report.get("file") or "").strip()
    if not rid:
        return [], {"remote_tools": {"skipped": "no_rid"}}

    try:
        pack = analyze_remote_tools(rid)
    except Exception as e:
        print(f"[remote_tools] analyze {rid}: {e}")
        return [], {"remote_tools": {"error": str(e)}}

    instances = pack.get("instances") or []
    sessions = pack.get("sessions") or []
    findings: List[Finding] = []
    matched: List[Dict[str, Any]] = []

    for inst in instances:
        name = str(inst.get("name") or inst.get("tool_id") or "远控")
        path = str(inst.get("install_path") or "")
        tid = str(inst.get("tool_id") or "")
        bits = []
        if inst.get("unattended"):
            bits.append("无人值守/自动启动服务")
        if inst.get("running"):
            bits.append("进程在跑")
        if inst.get("portable"):
            bits.append("便携/非标准路径")
        if inst.get("client_id"):
            bits.append(f"本机ID {inst['client_id']}")
        if inst.get("version"):
            bits.append(f"版本 {inst['version']}")
        if inst.get("install_time"):
            bits.append(f"安装/注册 {inst['install_time']}")
        priority = str(inst.get("priority") or "medium")
        bits.insert(0, f"优先级 {inst.get('priority_label') or priority}")
        src = "、".join(inst.get("sources") or []) or "文件痕迹"
        sev = "high" if (
            priority == "high"
            or inst.get("unattended")
            or inst.get("running")
            or inst.get("portable")
        ) else "medium"
        evidence = f"{path or '路径未知'} · 来源 {src}"
        if bits:
            evidence += " · " + "；".join(bits)
        svc_names = [str(s.get("name") or "") for s in (inst.get("services") or []) if s.get("name")]
        if svc_names:
            evidence += f" · 服务 {', '.join(svc_names[:4])}"

        key = f"远控痕迹|{name}|{path}|remote_tools"
        if key in seen:
            continue
        seen.add(key)
        matched.append({"tool": name, "path": path, "tool_id": tid})
        findings.append(Finding(
            "远控痕迹",
            sev,
            name,
            evidence,
            "remote_tools",
            tid or "remote",
            "remote_tools",
            extra={
                "tool_id": tid,
                "priority": priority,
                "client_id": inst.get("client_id") or "",
                "unattended": bool(inst.get("unattended")),
                "running": bool(inst.get("running")),
                "portable": bool(inst.get("portable")),
            },
            anchor=build_anchor(path=path) if path else None,
        ))

    # 会话摘要：每种工具最多一条汇总告警（明细在远程访问页）
    by_tool: Dict[str, List[Dict[str, Any]]] = {}
    for s in sessions:
        by_tool.setdefault(str(s.get("tool_id") or s.get("tool_name") or ""), []).append(s)
    for tid, rows in by_tool.items():
        if not rows:
            continue
        tool_name = str(rows[0].get("tool_name") or tid)
        recent = rows[0]
        peers = sorted({str(r.get("peer_id") or r.get("peer_ip") or "") for r in rows if r.get("peer_id") or r.get("peer_ip")})
        evidence = (
            f"解析到 {len(rows)} 场会话；最近 "
            f"{recent.get('start') or recent.get('end') or '?'} "
            f"{recent.get('summary') or ''}"
        )
        if peers:
            evidence += f"；对端 {', '.join(peers[:6])}"
        key = f"远控会话|{tool_name}|remote_tools"
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            "远控痕迹",
            "high",
            f"{tool_name} 远程会话",
            evidence[:500],
            "remote_tools",
            f"session:{tid}",
            "remote_tools",
            extra={"session_count": len(rows), "tool_id": tid},
        ))

    # 境外 IP：对端/采集时连接在境外 → 高危；仅厂商服务器/中继在境外 → 中危提示核实
    by_tool_ip: Dict[str, List[Dict[str, Any]]] = {}
    for r in pack.get("ip_hits") or []:
        if r.get("overseas"):
            by_tool_ip.setdefault(str(r.get("tool_id") or ""), []).append(r)
    for tid, rows in by_tool_ip.items():
        tool_name = str(rows[0].get("tool_name") or tid)
        peers = [r for r in rows if r.get("role") in ("peer", "conn", "unknown")]
        target = peers or rows
        ips = list(dict.fromkeys(str(r.get("ip")) for r in target))
        detail = "；".join(
            f"{r['ip']}（{r.get('role_label') or r.get('role')}"
            + (f"·{r['cloud']}" if r.get("cloud") else "")
            + (f"·{r['last_seen']}" if r.get("last_seen") else "")
            + "）"
            for r in target[:6]
        )
        key = f"远控境外IP|{tool_name}|{','.join(ips[:10])}|remote_tools"
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            "远控痕迹",
            "high" if peers else "medium",
            f"{tool_name} {'境外 IP 连接过本机' if peers else '连接过境外服务器/中继（需核实）'}",
            f"境外 IP {len(ips)} 个：{detail}"[:500],
            "remote_tools",
            f"overseas:{tid}",
            "remote_tools",
            extra={"tool_id": tid, "overseas_ips": ips[:20], "peer": bool(peers)},
        ))

    return findings, {
        "remote_tools": {
            "instances": len(instances),
            "sessions": len(sessions),
            "matched": matched,
            "overseas_ips": sorted({str(r.get("ip")) for r in pack.get("ip_hits") or [] if r.get("overseas")}),
            "stats": pack.get("stats") or {},
        }
    }
