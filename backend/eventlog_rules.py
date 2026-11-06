"""加载 log_rules/rules 下的 Sigma（Channel/EventID），按 EventID 建索引快匹配。"""
from __future__ import annotations

import html
import re
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from . import config

_LOCK = threading.RLock()
_CACHE: Optional[Dict[str, Any]] = None
_DISABLED_TITLES: Optional[Set[str]] = None
_DISABLED_MTIME: float = -1.0


def _disabled_titles(root: Path) -> Set[str]:
    """log_rules/rules/.disabled_titles.json → 跳过加载。"""
    global _DISABLED_TITLES, _DISABLED_MTIME
    p = root / ".disabled_titles.json"
    try:
        mt = p.stat().st_mtime if p.is_file() else -1.0
    except OSError:
        mt = -1.0
    if _DISABLED_TITLES is not None and mt == _DISABLED_MTIME:
        return _DISABLED_TITLES
    titles: Set[str] = set()
    if p.is_file():
        try:
            import json

            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            data = None
        if isinstance(data, dict):
            for t in data.get("titles") or []:
                if t:
                    titles.add(str(t).strip())
        elif isinstance(data, list):
            for t in data:
                if t:
                    titles.add(str(t).strip())
    _DISABLED_TITLES = titles
    _DISABLED_MTIME = mt
    return titles


# 默认启用 low 及以上；informational 与 low 同档，避免 log_rules 大量 Info 规则被默默丢弃
_LEVEL_RANK = {
    "informational": 1,
    "info": 1,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Sigma logsource.service / category → 采集报告里常见 Channel（子串匹配仍保留原 service 名）
_SERVICE_CHANNEL = {
    "security": "Security",
    "system": "System",
    "application": "Application",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "powershell-classic": "Windows PowerShell",
    "windefend": "Microsoft-Windows-Windows Defender/Operational",
    "bits": "Microsoft-Windows-Bits-Client/Operational",
    "taskscheduler": "Microsoft-Windows-TaskScheduler/Operational",
    "dns-server": "DNS Server",
    "ntlm": "Microsoft-Windows-NTLM/Operational",
    "smbclient": "Microsoft-Windows-SmbClient/Security",
    "smbserver": "Microsoft-Windows-SMBServer/Security",
    "applocker": "Microsoft-Windows-AppLocker/EXE and DLL",
    "codeintegrity": "Microsoft-Windows-CodeIntegrity/Operational",
    # 采集器通道枚举后新增可采的通道
    "firewall-as": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "dns-client": "Microsoft-Windows-DNS-Client/Operational",
    "wmi": "Microsoft-Windows-WMI-Activity/Operational",
    "winrm": "Microsoft-Windows-WinRM/Operational",
    "terminalservices-localsessionmanager": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "shell-core": "Microsoft-Windows-Shell-Core/Operational",
}
_CATEGORY_CHANNEL = {
    "ps_script": "Microsoft-Windows-PowerShell/Operational",
    "ps_module": "Microsoft-Windows-PowerShell/Operational",
    "ps_classic_start": "Windows PowerShell",
    "ps_classic_provider_start": "Windows PowerShell",
}


def log_rules_dir() -> Path:
    """优先用精选包 log_rules/rules；若空则回退 logrules/rules（不全量加载 sigma，避免卡顿）。"""
    root = Path(config.ROOT)
    primary = root / "log_rules" / "rules"
    fallback = root / "logrules" / "rules"
    try:
        if primary.is_dir() and any(primary.glob("*.yml")):
            return primary
    except OSError:
        pass
    try:
        if fallback.is_dir() and any(fallback.glob("*.yml")):
            return fallback
    except OSError:
        pass
    return primary


def _min_level() -> str:
    try:
        from .settings import get_settings
        return str(get_settings().get("eventlog_min_level") or "low").lower()
    except Exception:
        return "low"


def _level_ok(level: str, min_level: str) -> bool:
    return _LEVEL_RANK.get((level or "medium").lower(), 2) >= _LEVEL_RANK.get((min_level or "medium").lower(), 2)


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _parse_modifiers(key: str) -> Tuple[str, List[str]]:
    """CommandLine|contains|all -> field, mods"""
    parts = str(key).split("|")
    return parts[0], [p.lower() for p in parts[1:]]


def _clause_op(mods: List[str]) -> str:
    """把修饰符固化成单个比较算子，避免每条事件重复走 in 判断链。"""
    if "endswith" in mods:
        return "endswith"
    if "startswith" in mods:
        return "startswith"
    if "equals" in mods or "eq" in mods:
        return "equals"
    if "contains" in mods or not mods:
        return "contains"
    if "re" in mods:
        return "re"
    return "contains"


def _finish_clause(clause: Dict[str, Any]) -> Dict[str, Any]:
    """预算好算子/小写字面量/正则，匹配时直接用。"""
    mods = clause.get("mods") or ["contains"]
    op = _clause_op(mods)
    clause["op"] = op
    clause["want_all"] = "all" in mods
    vals = [str(x) for x in (clause.get("values") or [])]
    if op == "re":
        compiled = []
        for p in vals:
            try:
                compiled.append(re.compile(p, re.I))
            except re.error:
                compiled.append(None)
        clause["values_re"] = tuple(compiled)
    else:
        clause["values_lc"] = tuple(p.lower() for p in vals)
    return clause


def _compile_selection_block(v: Any) -> List[Dict[str, Any]]:
    """Sigma selection 块：dict 为 AND；list[dict] 为 OR（任一条命中）。"""
    clauses: List[Dict[str, Any]] = []
    if isinstance(v, dict):
        items = [v]
        list_or = False
    elif isinstance(v, list):
        items = [x for x in v if isinstance(x, dict)]
        list_or = True
    else:
        return []
    for item in items:
        group: List[Dict[str, Any]] = []
        for fk, fv in item.items():
            field, mods = _parse_modifiers(fk)
            fl = field.lower()
            vals = [str(x) for x in _as_list(fv)]
            if fl in ("eventid", "event_id"):
                group.append({"field": "EventID", "mods": mods or ["equals"], "values": vals})
            elif fl == "channel":
                group.append({"field": "Channel", "mods": mods or ["equals"], "values": vals})
            else:
                # Sigma 无修饰符时默认 equals（避免 LogonType=10 误命中 contains 0）
                group.append({
                    "field": field,
                    "mods": mods or ["equals"],
                    "values": vals,
                })
        if not group:
            continue
        group = [_finish_clause(c) for c in group]
        if list_or:
            # OR 组：用特殊标记，匹配时任一组全命中即可
            clauses.append({"_or_group": group})
        else:
            clauses.extend(group)
    return clauses


def _compile_rule(doc: Dict[str, Any], path: Path) -> Optional[Dict[str, Any]]:
    if not isinstance(doc, dict):
        return None
    det = doc.get("detection") or {}
    if not isinstance(det, dict):
        return None
    condition = str(det.get("condition") or "selection").strip().lower()
    event_ids: Set[int] = set()
    channels: Set[str] = set()
    selections: Dict[str, List[Dict[str, Any]]] = {}

    for k, v in det.items():
        if k == "condition":
            continue
        clauses = _compile_selection_block(v)
        if not clauses:
            continue
        selections[str(k).lower()] = clauses
        for c in clauses:
            group = c.get("_or_group") if isinstance(c, dict) else None
            walk = group if isinstance(group, list) else [c]
            for one in walk:
                fl = str(one.get("field") or "").lower()
                if fl in ("eventid", "event_id"):
                    for x in one.get("values") or []:
                        try:
                            event_ids.add(int(float(x)))
                        except Exception:
                            pass
                elif fl == "channel":
                    for x in one.get("values") or []:
                        channels.add(str(x))

    ls = doc.get("logsource") or {}
    if isinstance(ls, dict):
        svc = str(ls.get("service") or "").strip()
        cat = str(ls.get("category") or "").strip().lower()
        if svc:
            channels.add(svc)
            mapped = _SERVICE_CHANNEL.get(svc.lower())
            if mapped:
                channels.add(mapped)
        if not channels and cat:
            mapped = _CATEGORY_CHANNEL.get(cat)
            if mapped:
                channels.add(mapped)
            # 兜底：类别名本身也参与子串匹配
            channels.add(cat)

    if not event_ids and not any(selections.values()):
        return None

    level = str(doc.get("level") or "medium").lower()
    return {
        "id": str(doc.get("id") or path.stem),
        "title": str(doc.get("title") or path.stem),
        "description": str(doc.get("description") or "").strip(),
        "details": str(doc.get("details") or "").strip(),
        "level": level,
        "status": str(doc.get("status") or ""),
        "condition": condition,
        "cond_plan": _compile_condition_plan(condition, selections),
        "event_ids": sorted(event_ids),
        "channels": sorted(channels),
        "channels_lc": tuple(sorted({str(c).lower() for c in channels})),
        "selections": selections,
        "path": str(path),
    }


def load_eventlog_rules(force: bool = False) -> Dict[str, Any]:
    global _CACHE
    with _LOCK:
        if _CACHE is not None and not force:
            return _CACHE
        root = log_rules_dir()
        rules: List[Dict[str, Any]] = []
        by_eid: Dict[int, List[Dict[str, Any]]] = {}
        no_eid: List[Dict[str, Any]] = []
        errors = 0
        if root.is_dir():
            for p in sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml")):
                try:
                    doc = yaml.safe_load(p.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    errors += 1
                    continue
                rule = _compile_rule(doc or {}, p)
                if not rule:
                    continue
                if rule["title"] in _disabled_titles(root):
                    continue
                rules.append(rule)
                if rule["event_ids"]:
                    for eid in rule["event_ids"]:
                        by_eid.setdefault(eid, []).append(rule)
                else:
                    no_eid.append(rule)
        # 加载时按危急度排好，匹配时合并两路有序列表，避免对每条事件再 sort
        _rk = lambda r: -_level_rank(r.get("level") or "medium")
        no_eid.sort(key=_rk)
        for lst in by_eid.values():
            lst.sort(key=_rk)
        _CACHE = {
            "rules": rules,
            "by_eid": by_eid,
            "no_eid": no_eid,
            "count": len(rules),
            "errors": errors,
            "dir": str(root),
            "min_level": _min_level(),
        }
        return _CACHE


def reload_eventlog_rules() -> Dict[str, Any]:
    return load_eventlog_rules(force=True)


def event_hit_key(channel: Any, event_id: Any, time: Any) -> str:
    """与前端系统日志页一致的命中索引键：channel|event_id|time(19)。"""
    ch = str(channel or "").strip().lower()
    try:
        eid = int(event_id or 0)
    except Exception:
        eid = 0
    t = normalize_event_time(time)
    return f"{ch}|{eid}|{t}"


def normalize_event_time(time: Any) -> str:
    t = str(time or "").strip()
    if not t:
        return ""
    t = re.sub(r"[Zz]$", "", t)
    t = re.sub(r"[+-]\d{2}:\d{2}$", "", t)
    if "." in t:
        t = t.split(".", 1)[0]
    return t.replace("T", " ")[:19]


def event_ce_key(channel: Any, event_id: Any) -> str:
    try:
        eid = int(event_id or 0)
    except Exception:
        eid = 0
    return f"{str(channel or '').strip().lower()}|{eid}"


def _format_event_evidence(ev: Dict[str, Any], limit: int = 1200) -> str:
    from .text_fix import fix_mojibake
    msg = fix_mojibake(str(ev.get("message") or "").strip())
    fields = ev.get("fields") or {}
    if not isinstance(fields, dict):
        fields = {}
    # Defender 告警：威胁名 + 路径置前，避免列表/摘要只见引擎版本等杂项
    prefer = (
        "Threat Name", "ThreatName", "Path", "File Path", "Process Name", "ProcessName",
        "Severity Name", "SeverityName", "Severity ID", "SeverityID",
        "Category Name", "Detection User", "Detection Time",
        "ProviderName", "NewProviderState", "CommandLine", "ScriptBlockText",
        "SubjectUserName", "TargetUserName", "IpAddress", "LogonType",
        "Image", "ParentImage", "User", "Computer",
        "ServiceName", "ServiceType", "StartType", "ImagePath", "AccountName",
        "Param1", "Param2", "Param3", "Address", "SessionID", "UserName", "Domain",
        "FWLink", "Engine Version", "Product Name",
    )
    parts: List[str] = []
    seen: Set[str] = set()
    for pk in prefer:
        v = fields.get(pk)
        if v is None:
            # 兼容无空格键名
            alt = pk.replace(" ", "")
            if alt != pk:
                v = fields.get(alt)
        if v is None:
            continue
        sv = fix_mojibake(str(v).strip())
        if not sv:
            continue
        parts.append(f"{pk}={sv}")
        seen.add(pk)
        seen.add(pk.replace(" ", ""))
    for k, v in fields.items():
        if not k or k in seen or k == str(k).lower():
            continue
        sv = fix_mojibake(str(v or "").strip())
        if not sv:
            continue
        parts.append(f"{k}={sv}")
    text = " · ".join(parts)
    if text:
        return text[:limit]
    if msg:
        return msg[:limit]
    return ""


_FIELD_KEY_SEP_RE = re.compile(r"[\s_\-]+")


@lru_cache(maxsize=8192)
def _norm_field_key(s: str) -> str:
    """Severity ID / SeverityID / severity_id → severityid

    字段名集合很小但每条子句都要归一化一遍，不缓存的话正则替换会占掉大半匹配时间。
    """
    return _FIELD_KEY_SEP_RE.sub("", str(s or "").lower())


def _unescape(s: str) -> str:
    if not s:
        return ""
    try:
        return html.unescape(s)
    except Exception:
        return s


def _field_get(ev: Dict[str, Any], field: str) -> str:
    fl = field.lower()
    if fl in ("eventid", "event_id"):
        return str(ev.get("event_id") or ev.get("EventID") or "")
    if fl == "channel":
        return str(ev.get("channel") or "")
    if fl == "provider":
        return str(ev.get("provider") or "")
    if fl in ("message", "description"):
        return _unescape(str(ev.get("message") or ""))
    want = _norm_field_key(field)
    fields = ev.get("fields") or {}
    if isinstance(fields, dict):
        if field in fields:
            return _unescape(str(fields.get(field) or ""))
        if fl in fields:
            return _unescape(str(fields.get(fl) or ""))
        for k, v in fields.items():
            if _norm_field_key(k) == want:
                return _unescape(str(v or ""))
    for k in (field, fl):
        if k in ev and k not in ("fields",):
            return _unescape(str(ev.get(k) or ""))
    for k, v in ev.items():
        if k == "fields":
            continue
        if _norm_field_key(k) == want:
            return _unescape(str(v or ""))
    return ""


_PLACEHOLDER_RE = re.compile(r"%([A-Za-z_][\w.-]*)%")


def _render_details_template(tpl: str, ev: Dict[str, Any]) -> str:
    """Hayabusa details：%UserDataParam3% / %UserDataUser% → 事件字段。"""
    tpl = str(tpl or "").strip()
    if not tpl:
        return ""

    def repl(m: re.Match) -> str:
        key = m.group(1)
        val = _field_get(ev, key)
        if val:
            return val
        kl = key.lower()
        if kl.startswith("userdata") and len(key) > 8:
            val = _field_get(ev, key[8:])
        elif kl.startswith("eventdata") and len(key) > 9:
            rest = key[9:]
            val = _field_get(ev, rest)
            if not val:
                n = rest.lower().replace("param", "")
                if n.isdigit():
                    val = _field_get(ev, f"Data{n}") or _field_get(ev, f"Data{int(n) - 1}")
        return val or ""

    text = _PLACEHOLDER_RE.sub(repl, tpl).strip()
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"(?:\s*[|¦]\s*){2,}", " ¦ ", text).strip(" |¦")
    return text


def _format_hit_evidence(ev: Dict[str, Any], rule: Dict[str, Any], limit: int = 1200) -> str:
    details = _render_details_template(rule.get("details") or "", ev)
    if details:
        return details[:limit]
    return _format_event_evidence(ev, limit=limit)


def _match_clause(ev: Dict[str, Any], clause: Dict[str, Any]) -> bool:
    if not (clause.get("values") or []):
        return True
    if "op" not in clause:
        _finish_clause(clause)
    val = _field_get(ev, clause["field"])
    op = clause["op"]
    want_all = clause["want_all"]

    if op == "re":
        pats = clause.get("values_re") or ()
        if want_all:
            return all(p is not None and p.search(val) is not None for p in pats)
        return any(p is not None and p.search(val) is not None for p in pats)

    vl = val.lower()
    pats = clause.get("values_lc") or ()
    if op == "endswith":
        hits = (vl.endswith(p) for p in pats)
    elif op == "startswith":
        hits = (vl.startswith(p) for p in pats)
    elif op == "equals":
        hits = (vl == p for p in pats)
    else:
        hits = (p in vl for p in pats)
    return all(hits) if want_all else any(hits)


def _match_selection(ev: Dict[str, Any], clauses: List[Dict[str, Any]]) -> bool:
    if not clauses:
        return True
    # 普通子句 AND，OR 组之间为 OR（任一组全命中）；普通子句一失败就短路
    or_groups: Optional[List[Any]] = None
    for c in clauses:
        g = c.get("_or_group") if isinstance(c, dict) else None
        if g is None:
            if not _match_clause(ev, c):
                return False
        else:
            if or_groups is None:
                or_groups = []
            or_groups.append(g)
    if or_groups:
        return any(all(_match_clause(ev, c) for c in g) for g in or_groups if g)
    return True


def _compile_condition_plan(cond: str, sels: Dict[str, Any]) -> List[List[Tuple[bool, bool, Tuple[str, ...]]]]:
    """把 Sigma condition 预编译成 OR 支路，避免每条事件重新分词、重算 selection_* 通配。

    支路内每步为 (取反, 是否要求全部命中, 选择块名)；块名为空表示恒不命中。
    """
    cond = str(cond or "").strip().lower()
    if not cond:
        return []

    def resolve(token: str) -> Tuple[str, ...]:
        t = str(token or "").strip().strip("()[]")
        if not t:
            return ()
        if t.endswith("*"):
            prefix = t[:-1]
            return tuple(k for k in sels if k.startswith(prefix))
        return (t,) if t in sels else ()

    plan: List[List[Tuple[bool, bool, Tuple[str, ...]]]] = []
    cond_flat = cond.replace("(", " ").replace(")", " ")
    for part in re.split(r"\s+or\s+", cond_flat):
        tokens = [t for t in re.split(r"\s+", part.strip()) if t]
        if not tokens:
            continue
        steps: List[Tuple[bool, bool, Tuple[str, ...]]] = []
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t in ("and", "or"):
                i += 1
                continue
            neg = False
            if t == "not":
                neg = True
                i += 1
                if i >= len(tokens):
                    steps.append((False, False, ()))  # 悬空的 not：整条支路恒假
                    break
                t = tokens[i]
            if t in ("all", "1") and i + 2 < len(tokens) and tokens[i + 1] == "of":
                steps.append((neg, t == "all", resolve(tokens[i + 2])))
                i += 3
                continue
            if t in ("1", "of", "all", "them"):
                # 残片跳过
                i += 1
                continue
            steps.append((neg, False, resolve(t)))
            i += 1
        plan.append(steps)
    return plan


def _eval_condition(ev: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    sels = rule.get("selections") or {}
    plan = rule.get("cond_plan")
    if plan is None:
        plan = _compile_condition_plan(rule.get("condition") or "selection", sels)
        rule["cond_plan"] = plan
    for steps in plan:
        ok = True
        for neg, need_all, names in steps:
            if not names:
                hit = False
            elif need_all:
                hit = all(_match_selection(ev, sels[n]) for n in names)
            else:
                hit = any(_match_selection(ev, sels[n]) for n in names)
            if neg:
                hit = not hit
            if not hit:
                ok = False
                break
        if ok:
            return True
    return False


def _level_rank(level: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}.get(
        str(level or "").lower(), 2
    )


def _iter_sorted_cands(eid_rules: List[Dict[str, Any]], no_eid: List[Dict[str, Any]]):
    """合并两路已按危急度降序排好的规则列表。"""
    i = j = 0
    n_a, n_b = len(eid_rules), len(no_eid)
    while i < n_a or j < n_b:
        if j >= n_b:
            yield eid_rules[i]
            i += 1
        elif i >= n_a:
            yield no_eid[j]
            j += 1
        elif _level_rank(eid_rules[i].get("level") or "medium") >= _level_rank(
            no_eid[j].get("level") or "medium"
        ):
            yield eid_rules[i]
            i += 1
        else:
            yield no_eid[j]
            j += 1


def match_events(events: List[Dict[str, Any]], max_hits: int = 2000) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    pack = load_eventlog_rules()
    min_lv = _min_level()
    high_hits: List[Dict[str, Any]] = []
    other_hits: List[Dict[str, Any]] = []
    scanned = 0
    no_eid = pack.get("no_eid") or []
    by_eid = pack.get("by_eid") or {}

    # 候选规则只跟 (EventID, 通道) 有关，按事件重算等于把 325 条规则过滤十几万遍
    cand_cache: Dict[Tuple[int, str], List[Dict[str, Any]]] = {}

    def candidates(eid: int, ech: str) -> List[Dict[str, Any]]:
        key = (eid, ech)
        got = cand_cache.get(key)
        if got is not None:
            return got
        picked: List[Dict[str, Any]] = []
        seen_r: Set[str] = set()
        for rule in _iter_sorted_cands(by_eid.get(eid, []) if eid else [], no_eid):
            rid = rule["id"]
            if rid in seen_r:
                continue
            seen_r.add(rid)
            if not _level_ok(rule.get("level") or "medium", min_lv):
                continue
            chs = rule.get("channels_lc")
            if chs is None:
                chs = tuple(str(c).lower() for c in (rule.get("channels") or ()))
            if chs and not any(c in ech for c in chs):
                continue
            picked.append(rule)
        cand_cache[key] = picked
        return picked

    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        scanned += 1
        try:
            eid = int(ev.get("event_id") or ev.get("EventID") or 0)
        except Exception:
            eid = 0
        for rule in candidates(eid, str(ev.get("channel") or "").lower()):
            try:
                if not _eval_condition(ev, rule):
                    continue
            except Exception:
                continue
            evidence = _format_hit_evidence(ev, rule, limit=1200)
            ch = ev.get("channel") or ""
            tm = ev.get("time") or ""
            item = {
                "rule_id": rule["id"],
                "title": rule["title"],
                "level": rule["level"],
                "event_id": eid,
                "channel": ch,
                "time": tm,
                "hit_key": event_hit_key(ch, eid, tm),
                "evidence": evidence,
                "provider": ev.get("provider") or "",
            }
            lv = str(rule.get("level") or "").lower()
            if lv in ("high", "critical"):
                high_hits.append(item)
            else:
                other_hits.append(item)
            # 高危未满时继续扫；低危已达上限且高危已达上限才停
            if len(high_hits) >= max_hits and len(other_hits) >= max_hits:
                break
        if len(high_hits) >= max_hits and len(other_hits) >= max_hits:
            break
    # 输出优先高危，再补中低危
    remain = max(0, max_hits - len(high_hits[:max_hits]))
    hits = high_hits[:max_hits] + other_hits[:remain]
    meta = {
        "rules_loaded": pack.get("count") or 0,
        "events_scanned": scanned,
        "hits": len(hits),
        "hits_high": len(high_hits),
        "min_level": min_lv,
        "capped": len(high_hits) + len(other_hits) > max_hits,
    }
    return hits, meta
