"""EDR Skill 目录加载器：从 D:\\GeRen\\web\\edr\\skills 读取 SKILL.md。

完整库很大（数千包），本模块：
1) 构建轻量索引（name/description/tags/mitre）
2) 按终端证据关键字挑选相关 Skill
3) 抽取正文要点喂给本地大模型（控制 token）
"""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import config

_LOCK = threading.RLock()
_CACHE: Dict[str, Any] = {"mtime": 0.0, "index": [], "built_at": 0.0}

# 终端/主机威胁研判「置顶」技能（相对 skills 根目录名）——不是唯一白名单
_EDR_PRIORITY = (
    "analyzing-cyber-kill-chain",
    "analyzing-indicators-of-compromise",
    "analyzing-command-and-control-communication",
    "analyzing-cobalt-strike-beacon-configuration",
    "analyzing-cobaltstrike-malleable-c2-profiles",
    "analyzing-malware-persistence-with-autoruns",
    "analyzing-lnk-file-and-jump-list-artifacts",
    "analyzing-macro-malware-in-office-documents",
    "analyzing-dns-logs-for-exfiltration",
    "analyzing-linux-audit-logs-for-intrusion",
    "analyzing-linux-system-artifacts",
    "analyzing-bootkit-and-rootkit-samples",
    "analyzing-malware-sandbox-evasion-techniques",
    "analyzing-campaign-attribution-evidence",
    "analyzing-powershell-empire-artifacts",
    "abusing-dpapi-for-credential-access",
    "analyzing-heap-spray-exploitation",
    "analyzing-malware-behavior-with-cuckoo-sandbox",
)

# 名称/标签命中即视为 EDR / 终端取证相关（用于列表展示，不再只显示 14 个）
_EDR_RELEVANCE_RE = re.compile(
    r"(edr|endpoint|windows|forensic|malware|threat|incident|response|detection|"
    r"powershell|persistence|autorun|cobalt|beacon|c2|credential|ioc|indicator|"
    r"kill.?chain|memory|process|registry|lateral|ransomware|apt|intrusion|"
    r"lolbin|scriptblock|mimikatz|lsass|dpapi|rootkit|bootkit|evasion|"
    r"phishing|lnk|macro|office|dns.?exfil|exfiltration|sandbox|campaign|"
    r"command.?and.?control|privilege|privesc|hunter|yara|sigma|sysmon|"
    r"timeline|artifact|triage|soar|soc|alert|log.?analy)",
    re.I,
)

_KW_MAP = (
    (("powershell", "encodedcommand", "frombase64", "iex", "scriptblock"), ("powershell", "lolbin", "script")),
    (("rundll32", "regsvr32", "mshta", "wscript", "cscript", "certutil", "bitsadmin"), ("lolbin", "execution")),
    (("mimikatz", "lsass", "sekurlsa", "ntds", "procdump", "minidump", "dpapi"), ("credential", "lsass", "dpapi")),
    (("persistence", "run key", "scheduled task", "服务安装", "startup", "autorun"), ("persistence", "autoruns")),
    (("c2", "beacon", "cobalt", "meterpreter", "havoc", "外联", "dns tunnel"), ("c2", "cobalt", "beacon")),
    (("ransomware", "shadowcopy", "vssadmin", "bcdedit", "加密"), ("ransomware", "impact")),
    (("phishing", "lnk", "macro", "office", "winword", "excel"), ("phishing", "lnk", "macro", "office")),
    (("rootkit", "driver", "kernel", "ssdt"), ("rootkit", "bootkit", "kernel")),
    (("linux", "cron", "systemd", "elf", "bash"), ("linux", "audit")),
)


def skills_root() -> Path:
    root = Path(getattr(config, "ROOT", Path(__file__).resolve().parents[2]))
    p = root / "skills"
    if p.is_dir():
        return p
    alt = Path(r"D:\GeRen\web\edr\skills")
    return alt if alt.is_dir() else p


def _parse_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
    raw = text or ""
    if not raw.startswith("---"):
        return {}, raw
    end = raw.find("\n---", 3)
    if end < 0:
        return {}, raw
    head = raw[3:end].strip()
    body = raw[end + 4:].lstrip("\n")
    meta: Dict[str, Any] = {}
    # 轻量 YAML：只取常用标量/简单列表
    key = None
    list_mode = None
    for line in head.splitlines():
        if re.match(r"^\s*-\s+", line) and list_mode:
            val = re.sub(r"^\s*-\s+", "", line).strip().strip("'\"")
            meta.setdefault(list_mode, []).append(val)
            continue
        m = re.match(r"^([A-Za-z0-9_]+):\s*(.*)$", line)
        if not m:
            continue
        key = m.group(1)
        rest = m.group(2).strip()
        if rest == "" or rest == "|" or rest == ">":
            list_mode = key if rest == "" else None
            if rest in ("|", ">"):
                meta[key] = ""
                list_mode = None
                # 折叠块：后续缩进行拼到 description
                continue
            meta[key] = meta.get(key) or []
            list_mode = key
            continue
        list_mode = None
        if (rest.startswith("'") and rest.endswith("'")) or (rest.startswith('"') and rest.endswith('"')):
            rest = rest[1:-1]
        meta[key] = rest
    # description 可能是多行引号块（上面简单解析够用）
    if isinstance(meta.get("description"), str):
        meta["description"] = re.sub(r"\s+", " ", meta["description"]).strip()
    return meta, body


def _extract_guidance(body: str, limit: int = 1800) -> str:
    text = body or ""
    # 优先截取 Workflow / When to Use 段
    for marker in ("## Workflow", "## When to Use", "## Steps", "## Analysis"):
        idx = text.find(marker)
        if idx >= 0:
            text = text[idx:]
            break
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def _skill_dirs(root: Path) -> List[Path]:
    if not root.is_dir():
        return []
    out = []
    for p in root.iterdir():
        if p.is_dir() and (p / "SKILL.md").is_file():
            out.append(p)
    return out


def _is_edr_relevant(
    *,
    sid: str,
    name: str = "",
    description: str = "",
    tags: Optional[List[str]] = None,
    domain: str = "",
    subdomain: str = "",
) -> bool:
    """按目录名/标签/领域判断是否与终端威胁研判相关。"""
    if sid in _EDR_PRIORITY:
        return True
    blob = " ".join([
        sid,
        name or "",
        description or "",
        " ".join(tags or []),
        domain or "",
        subdomain or "",
    ])
    return bool(_EDR_RELEVANCE_RE.search(blob))


def skills_stats() -> Dict[str, Any]:
    items = build_index()
    edr_n = sum(1 for it in items if it.get("edr_relevant"))
    pri_n = sum(1 for it in items if it.get("priority"))
    return {
        "ok": True,
        "root": str(skills_root()),
        "total_indexed": len(items),
        "edr_relevant": edr_n,
        "priority": pri_n,
    }


def build_index(*, force: bool = False) -> List[Dict[str, Any]]:
    root = skills_root()
    with _LOCK:
        try:
            mtime = root.stat().st_mtime if root.is_dir() else 0.0
        except OSError:
            mtime = 0.0
        if (
            not force
            and _CACHE.get("index")
            and abs(float(_CACHE.get("mtime") or 0) - mtime) < 0.01
            and (time.time() - float(_CACHE.get("built_at") or 0)) < 600
        ):
            return list(_CACHE["index"])

        index: List[Dict[str, Any]] = []
        for d in _skill_dirs(root):
            try:
                raw = (d / "SKILL.md").read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            meta, body = _parse_frontmatter(raw)
            name = str(meta.get("name") or d.name).strip()
            desc = str(meta.get("description") or "").strip()
            tags = meta.get("tags") if isinstance(meta.get("tags"), list) else []
            mitre = meta.get("mitre_attack") if isinstance(meta.get("mitre_attack"), list) else []
            domain = str(meta.get("domain") or "")
            subdomain = str(meta.get("subdomain") or "")
            priority = d.name in _EDR_PRIORITY
            edr_relevant = _is_edr_relevant(
                sid=d.name,
                name=name,
                description=desc,
                tags=[str(t) for t in tags],
                domain=domain,
                subdomain=subdomain,
            )
            index.append({
                "id": d.name,
                "name": name,
                "description": desc[:400],
                "tags": [str(t) for t in tags[:16]],
                "mitre": [str(t) for t in mitre[:16]],
                "domain": domain,
                "subdomain": subdomain,
                "path": str(d / "SKILL.md"),
                "priority": priority,
                "edr_relevant": edr_relevant or priority,
                "body_excerpt": _extract_guidance(body, 1600) if priority else "",
            })
        index.sort(key=lambda x: (
            0 if x.get("priority") else 1,
            0 if x.get("edr_relevant") else 1,
            str(x.get("id") or ""),
        ))
        _CACHE["index"] = index
        _CACHE["mtime"] = mtime
        _CACHE["built_at"] = time.time()
        # 旁路写一份轻量索引，便于排查
        try:
            cache_path = Path(config.CONFIG_DIR) / "skills_index_cache.json"
            slim = [{k: v for k, v in it.items() if k != "body_excerpt"} for it in index]
            cache_path.write_text(
                json.dumps({
                    "count": len(slim),
                    "edr_relevant": sum(1 for x in slim if x.get("edr_relevant")),
                    "items": slim[:800],
                }, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass
        return list(index)


def list_skills(*, q: str = "", limit: int = 80, edr_only: bool = False) -> Dict[str, Any]:
    items = build_index(force=False)
    qq = str(q or "").strip().lower()
    out = []
    edr_total = sum(1 for it in items if it.get("edr_relevant") or it.get("priority"))
    for it in items:
        if edr_only and not (it.get("edr_relevant") or it.get("priority")):
            continue
        if qq:
            blob = " ".join([
                str(it.get("id") or ""),
                str(it.get("name") or ""),
                str(it.get("description") or ""),
                " ".join(it.get("tags") or []),
                str(it.get("domain") or ""),
            ]).lower()
            if qq not in blob:
                continue
        out.append({
            k: it.get(k)
            for k in ("id", "name", "description", "tags", "mitre", "priority", "edr_relevant", "domain", "subdomain")
        })
        if len(out) >= max(1, min(int(limit or 80), 500)):
            break
    return {
        "ok": True,
        "root": str(skills_root()),
        "total_indexed": len(items),
        "edr_relevant": edr_total,
        "returned": len(out),
        "items": out,
    }


def load_skill_body(skill_id: str, *, limit: int = 2400) -> Dict[str, Any]:
    sid = str(skill_id or "").strip()
    if not sid or ".." in sid or "/" in sid or "\\" in sid:
        return {"ok": False, "error": "无效 skill id"}
    path = skills_root() / sid / "SKILL.md"
    if not path.is_file():
        return {"ok": False, "error": "skill 不存在"}
    raw = path.read_text(encoding="utf-8", errors="replace")
    meta, body = _parse_frontmatter(raw)
    return {
        "ok": True,
        "id": sid,
        "name": meta.get("name") or sid,
        "description": meta.get("description") or "",
        "guidance": _extract_guidance(body, limit),
        "tags": meta.get("tags") or [],
        "mitre": meta.get("mitre_attack") or [],
    }


# 证据 → 技能 强映射（中英混检），比通用 kill-chain 优先
_EVIDENCE_SKILL_HINTS = (
    (("powershell", "encodedcommand", "scriptblock", "empire", "-enc", "frombase64", "iex(", "invoke-expression"),
     ("analyzing-powershell-empire-artifacts",), "PowerShell/编码执行"),
    (("cobalt", "beacon", "cs.exe", "malleable", "named pipe"),
     ("analyzing-cobalt-strike-beacon-configuration", "analyzing-cobaltstrike-malleable-c2-profiles"), "Cobalt Strike"),
    (("persist", "autorun", "startup", "run key", "计划任务", "持久化", "schtasks", "hkcu\\run", "hklm\\run", "persist_add"),
     ("analyzing-malware-persistence-with-autoruns",), "持久化"),
    (("c2", "外联", "command and control", "dns tunnel", "beacon", "network_connect"),
     ("analyzing-command-and-control-communication", "analyzing-dns-logs-for-exfiltration"), "C2/外联"),
    (("lnk", "jump list", "macro", "winword", "excel", "office", "dcom"),
     ("analyzing-lnk-file-and-jump-list-artifacts", "analyzing-macro-malware-in-office-documents"), "投递/Office"),
    (("mimikatz", "lsass", "dpapi", "credential", "sekurlsa", "credential dump"),
     ("abusing-dpapi-for-credential-access",), "凭证"),
    (("rootkit", "bootkit", "driver", "kernel", "unsigned dll", "ni.dll"),
     ("analyzing-bootkit-and-rootkit-samples",), "Rootkit/可疑模块"),
    (("rop", "stack spoof", "waitfor", "gadget", "image_load", "dll load"),
     ("analyzing-heap-spray-exploitation", "analyzing-malware-sandbox-evasion-techniques"), "内存/加载规避"),
    (("ioc", "indicator", "hash", "sha256", "8.8.4.4"),
     ("analyzing-indicators-of-compromise",), "IoC"),
    (("regsvcs", "teamcity", "lolbin", "mshta", "wscript", "cscript", "rundll32", "regsvr32"),
     ("analyzing-malware-behavior-with-cuckoo-sandbox", "analyzing-cyber-kill-chain"), "可疑进程/LOLBin"),
)


def _needle_in(text: str, needle: str) -> bool:
    """短词用边界匹配，避免 dcom⊂encodedcommand 这类误伤。"""
    n = (needle or "").lower().strip()
    if not n:
        return False
    if len(n) <= 4 and re.fullmatch(r"[a-z0-9_.\\-]+", n):
        return bool(re.search(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", text))
    return n in text


def select_skills_for_evidence(evidence_text: str, *, max_skills: int = 6) -> List[Dict[str, Any]]:
    """根据证据文本挑选高相关 Skill；返回 score / why（完全按证据匹配，而非固定前几名）。"""
    index = build_index()
    by_id = {str(it["id"]): it for it in index}
    text = (evidence_text or "").lower()
    scores: Dict[str, int] = {}
    why: Dict[str, List[str]] = {}

    def bump(sid: str, pts: int, reason: str) -> None:
        if sid not in by_id:
            return
        scores[sid] = scores.get(sid, 0) + pts
        why.setdefault(sid, [])
        if reason and reason not in why[sid]:
            why[sid].append(reason)

    # 1) 证据强映射
    for needles, sids, label in _EVIDENCE_SKILL_HINTS:
        hit_ns = [n for n in needles if _needle_in(text, n)]
        if hit_ns:
            for sid in sids:
                bump(sid, 12 + min(6, len(hit_ns)), f"证据命中:{label}({','.join(hit_ns[:3])})")

    # 2) Skill 名称/标签与证据词面重叠
    for it in index:
        sid = str(it.get("id") or "")
        if not sid:
            continue
        name = str(it.get("name") or "").lower()
        tags = " ".join(it.get("tags") or []).lower()
        tokens = [t for t in re.findall(r"[a-z0-9]{4,}", f"{sid} {name} {tags}") if t not in {
            "analyzing", "with", "from", "for", "and", "the", "into", "using",
        }]
        overlap = [t for t in tokens if t in text]
        if len(overlap) >= 2:
            bump(sid, 3 + min(8, len(overlap) * 2), f"名称重叠:{','.join(overlap[:4])}")
        elif len(overlap) == 1 and overlap[0] not in ("windows", "linux", "malware"):
            bump(sid, 2, f"名称重叠:{overlap[0]}")

    # 3) 关键字标签加权
    for needles, boost_tags in _KW_MAP:
        if any(n in text for n in needles):
            for it in index:
                sid = str(it.get("id") or "")
                tags = " ".join(it.get("tags") or []).lower() + " " + sid
                if any(t in tags for t in boost_tags):
                    bump(sid, 4, f"标签:{','.join(boost_tags[:2])}")
                elif any(n in (it.get("description") or "").lower() for n in needles[:2]):
                    bump(sid, 2, "描述关键词")

    # 4) 轻度保底：仅当几乎无命中时带上 kill-chain
    if not scores:
        bump("analyzing-cyber-kill-chain", 3, "默认方法论")
        bump("analyzing-indicators-of-compromise", 3, "默认 IoC")
    else:
        bump("analyzing-cyber-kill-chain", 1, "辅助:攻击链")

    ranked = sorted(scores.items(), key=lambda x: (-x[1], x[0]))
    picked: List[Dict[str, Any]] = []
    for sid, sc in ranked:
        if sc < 2 and picked:
            continue
        it = by_id.get(sid)
        if not it:
            continue
        body = it.get("body_excerpt") or ""
        if not body:
            full = load_skill_body(sid, limit=1800)
            if not full.get("ok"):
                continue
            body = str(full.get("guidance") or "")
        picked.append({
            "id": sid,
            "name": it.get("name") or sid,
            "description": it.get("description") or "",
            "score": sc,
            "why": why.get(sid) or [],
            "matched": True,
            "guidance": body[:1800],
            "mitre": it.get("mitre") or [],
        })
        if len(picked) >= max(1, min(int(max_skills or 6), 8)):
            break
    return picked
