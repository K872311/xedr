"""告警聚合：按工具资产 / IP / 噪声类合并，避免 Temp 刷屏淹没 RMM"""
from __future__ import annotations
import re
from collections import defaultdict
from typing import Any, Dict, List

from .models import Finding

def _persist_kind_from_source(src: str) -> str:
    s = str(src or "").strip()
    sl = s.lower()
    if s in ("计划任务",) or "scheduled" in sl:
        return "task"
    if s in ("启动项",) or "startup" in sl:
        return "startup"
    if s in ("WMI", "wmi") or sl == "wmi":
        return "wmi"
    if s in ("服务注册表", "注册表") or sl in ("registry", "services_registry"):
        return "registry"
    if s in ("服务",) or sl == "service":
        return "service"
    return "other"


NOISE_CATS = {"可疑文件"}
NOISE_TITLES = {"Temp目录可疑文件", "桌面可疑文件", "下载目录可疑文件", "隐藏目录", "大文件", "双扩展名"}
ASSET_CATS = {
    "RMM", "远控痕迹", "云存储", "加密工具", "VPN/隐私", "加密货币",
    "浏览器痕迹", "浏览痕迹", "浏览器下载", "搜索词",
    "登录横向", "凭据威胁", "外联画像", "防护弱化", "外传同步",
}


def _norm_ip(title: str) -> str:
    return (title or "").split(":")[0].strip("[]")


def _asset_key(f: Finding) -> str:
    cat = f.category or ""
    title = f.title or ""
    if cat == "网络外联":
        return f"egress|{_norm_ip(title)}"
    # 目录聚合：不同路径不合并，避免 GameDVR 等目录被挤掉文件列表
    if cat == "可疑目录":
        path = ""
        if isinstance(f.extra, dict):
            path = str(f.extra.get("path") or "")
        if not path:
            path = (f.evidence or "").split(" — ")[0].strip()
        return f"folder|{title}|{path.lower()}"
    # 单文件：按完整路径区分，便于详情定位
    if cat == "可疑文件" and title not in NOISE_TITLES:
        path = ""
        if isinstance(f.extra, dict):
            path = str(f.extra.get("path") or "")
        if not path:
            path = (f.evidence or "").split(" — ")[0].strip()
        if path:
            return f"file|{title}|{path.lower()}"
    # 文件/Prefetch/远控痕迹/回收站 命中同一工具 → 并入资产
    if cat in ("可疑文件", "Prefetch", "远控痕迹", "回收站", "RMM") and title:
        # 噪声文件规则名不并入
        if title not in NOISE_TITLES and title not in ("证书文件", "数据库文件", "系统目录异常文件", "可疑autorun"):
            return f"asset|RMM|{title}"
    if cat in ASSET_CATS:
        return f"asset|{cat}|{title}"
    if cat in NOISE_CATS and title in NOISE_TITLES:
        return f"noise|{title}"
    if cat == "持久化":
        path = ""
        kind = ""
        if isinstance(f.extra, dict):
            path = str(f.extra.get("path") or "")
            kind = str(f.extra.get("persist_kind") or "")
        if not kind:
            kind = _persist_kind_from_source(f.source or "")
        ev = (f.evidence or "")[:220]
        src = f.source or ""
        return f"persist|{kind}|{src}|{title}|{(path or ev).lower()}"
    if cat == "可疑命令":
        rid = str(getattr(f, "rule_id", "") or "")
        return f"cmd|{title}|{rid}"
    if cat == "浏览痕迹":
        return f"browse|{title}"
    if cat == "浏览器痕迹":
        return f"browser|{title}"
    if cat == "浏览器下载":
        return f"bdl|{title}"
    if cat == "搜索词":
        return f"search|{title}"
    if cat == "浏览器登录":
        return f"blogin|{title}"
    if cat == "Hosts篡改":
        return f"hosts|all"
    return f"gen|{cat}|{title}"


def aggregate_findings(findings: List[Finding]) -> Dict[str, Any]:
    groups: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        groups[_asset_key(f)].append(f)

    aggregated = []
    for key, items in groups.items():
        primary = items[0]
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        best = max(items, key=lambda x: sev_rank.get((x.severity or "medium").lower(), 2))
        evidences = []
        seen_ev = set()
        sources = set()
        # 去重后尽量全部保留，仅极端超量截断；界面分页展示
        _EV_KEEP = 10000
        for it in items:
            if it.evidence:
                # 多行证据拆成多条，详情页才能逐条展示
                chunks = [ln.strip() for ln in str(it.evidence).splitlines() if ln.strip()]
                if not chunks:
                    chunks = [str(it.evidence).strip()] if str(it.evidence).strip() else []
                for ev in chunks:
                    key_ev = ev[:400].lower()
                    if key_ev in seen_ev:
                        continue
                    seen_ev.add(key_ev)
                    evidences.append(ev[:2000])
            if it.source:
                sources.add(it.source)
        evidence_total = len(evidences)
        evidence_truncated = evidence_total > _EV_KEEP
        evidences_out = evidences[:_EV_KEEP]
        # 噪声类降级
        sev = best.severity
        if key.startswith("noise|") and len(items) > 3:
            sev = "low" if sev in ("high", "critical") else sev
            if sev == "medium":
                sev = "low"
        extra: Dict[str, Any] = {}
        if isinstance(best.extra, dict) and best.extra:
            extra = dict(best.extra)
        # 合并多条目录命中的成员（同路径一般只有一条）
        if key.startswith("folder|") or (extra.get("kind") == "folder"):
            members: List[Dict] = []
            seen_fp: set = set()
            for it in items:
                ex = it.extra if isinstance(it.extra, dict) else {}
                for m in (ex.get("members") or []):
                    if not isinstance(m, dict):
                        continue
                    fp = str(m.get("full_path") or "")
                    if fp and fp in seen_fp:
                        continue
                    if fp:
                        seen_fp.add(fp)
                    members.append(m)
                    if len(members) >= 120:
                        break
                if len(members) >= 120:
                    break
            if members:
                extra["kind"] = "folder"
                extra["path"] = extra.get("path") or (evidences_out[0].split(" — ")[0].strip() if evidences_out else "")
                extra["members"] = members
                extra["file_count"] = max(int(extra.get("file_count") or 0), len(seen_fp) or len(members))
                extra["members_truncated"] = bool(extra.get("members_truncated")) or len(members) >= 120
        extra["evidence_total"] = evidence_total
        extra["evidence_truncated"] = evidence_truncated
        # 多命中时汇总路径，避免摘要只显示最后一条
        paths: List[str] = []
        seen_paths: set = set()
        for it in items:
            ex = it.extra if isinstance(it.extra, dict) else {}
            for cand in (
                str(ex.get("path") or "").strip(),
                str(ex.get("process_path") or "").strip(),
                str(ex.get("image") or "").strip(),
            ):
                if not cand:
                    continue
                # 事件证据里常是「exe ¦ Acct: …」
                head = cand.split("¦")[0].split("|")[0].strip().strip('"')
                if not head:
                    continue
                low = head.lower()
                if low in seen_paths:
                    continue
                seen_paths.add(low)
                paths.append(head)
                if len(paths) >= 40:
                    break
            if len(paths) >= 40:
                break
        if not paths:
            for ev in evidences_out[:80]:
                m = re.search(
                    r"((?:[A-Za-z]:\\|\\\\)[^|¦\r\n\"]+?\.(?:exe|dll|sys|bat|cmd|ps1|msi))",
                    str(ev),
                    re.I,
                )
                if not m:
                    continue
                head = m.group(1).strip().rstrip(".,;")
                low = head.lower()
                if low in seen_paths:
                    continue
                seen_paths.add(low)
                paths.append(head)
                if len(paths) >= 40:
                    break
        if paths:
            extra["paths"] = paths
            if not extra.get("path"):
                extra["path"] = paths[0]
        if key.startswith("persist|") and not extra.get("persist_kind"):
            extra["persist_kind"] = _persist_kind_from_source(primary.source or "")
        # ATT&CK：聚合成员 union
        mitre_ids = []
        seen_m = set()
        stage = ""
        for it in items:
            ex = it.extra if isinstance(getattr(it, "extra", None), dict) else {}
            for m in (ex.get("mitre") or []):
                s = str(m or "").strip().upper()
                if s and s not in seen_m:
                    seen_m.add(s)
                    mitre_ids.append(s)
            if not stage:
                stage = str(ex.get("attack_stage") or "").strip()
        if mitre_ids:
            extra["mitre"] = mitre_ids
        if stage:
            extra["attack_stage"] = stage
        entry = {
            "id": key,
            "category": primary.category,
            "severity": sev,
            "title": best.title,
            # 匹配阶段已合并的命中（hit_count）按真实次数计
            "count": sum(
                max(1, int((it.extra or {}).get("hit_count") or 1)) if isinstance(it.extra, dict) else 1
                for it in items
            ),
            "evidence": evidences_out,
            "evidence_total": extra["evidence_total"],
            "evidence_truncated": bool(extra["evidence_truncated"]),
            "sources": sorted(sources),
            "rule_id": best.rule_id,
            "matcher": best.matcher,
            "type": primary.category,
            "name": best.title,
            "reason": evidences_out[0] if evidences_out else best.title,
            "extra": extra,
        }
        # 扁平化常用字段，便于前端 / findings_agg 读取
        for k in (
            "kind", "path", "paths", "file_count", "members", "members_truncated", "file",
            "evidence_total", "evidence_truncated", "persist_kind", "mitre", "attack_stage",
        ):
            if k in extra and k not in entry:
                entry[k] = extra[k]
        try:
            from .mitre import enrich_finding_dict
            enrich_finding_dict(entry)
        except Exception:
            pass
        aggregated.append(entry)

    # 排序：严重度 > 资产类 > count
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    aggregated.sort(key=lambda x: (
        order.get(str(x["severity"]).lower(), 9),
        0 if x["category"] in ASSET_CATS or x["category"] == "可疑命令" else 1,
        -x["count"],
        x["title"],
    ))

    summary = {"total": len(aggregated), "raw_total": len(findings), "high": 0, "medium": 0, "low": 0}
    for a in aggregated:
        s = str(a["severity"]).lower()
        if s in ("high", "critical"):
            summary["high"] += 1
        elif s == "medium":
            summary["medium"] += 1
        else:
            summary["low"] += 1
    return {"findings_aggregated": aggregated, "summary_aggregated": summary}
