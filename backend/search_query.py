"""普通检索：字段前缀解析 + 结果分面。"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

# hash: / ip: / path: / name: / pid: / host: 及别名
_FIELD_RE = re.compile(
    r"(?i)(?:^|\s)(hash|md5|sha1|sha256|ip|path|file|name|basename|pid|host|hostname)\s*:\s*"
    r'(?:"([^"]+)"|(\S+))'
)
_BARE_HASH_RE = re.compile(r"^(?:0x)?([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
_BARE_IP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})$")
_PID_IN_TEXT_RE = re.compile(r"\bpid\s*[:=]?\s*(\d{1,10})\b", re.I)
# 短文件名：1.exe / a.dll —— 默认子串会很宽（命中 v3.1.exe）
_BASENAME_RE = re.compile(
    r'^[^\\/:*?"<>|\s]{1,80}\.[A-Za-z0-9]{1,12}$'
)

_FIELD_ALIASES = {
    "hash": "hash",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "ip": "ip",
    "path": "path",
    "file": "path",
    "name": "name",
    "basename": "name",
    "pid": "pid",
    "host": "host",
    "hostname": "host",
}


def parse_field_query(q: str) -> Tuple[str, Dict[str, List[str]]]:
    """解析字段前缀，返回 (自由文本, {field: [values]})。

    例：
      hash:abc path:\"c:\\\\temp\\\\a.exe\" mimikatz
      → free='mimikatz', fields={hash:[abc], path:[c:\\temp\\a.exe]}
    纯哈希 / 纯 IP 自动识别为对应字段。
    """
    raw = (q or "").strip()
    fields: Dict[str, List[str]] = {}
    if not raw:
        return "", fields

    consumed: List[Tuple[int, int]] = []
    for m in _FIELD_RE.finditer(raw):
        key = _FIELD_ALIASES.get((m.group(1) or "").lower())
        val = (m.group(2) if m.group(2) is not None else m.group(3) or "").strip()
        if not key or not val:
            continue
        fields.setdefault(key, [])
        if val not in fields[key]:
            fields[key].append(val)
        consumed.append((m.start(), m.end()))

    if consumed:
        parts: List[str] = []
        last = 0
        for a, b in sorted(consumed):
            parts.append(raw[last:a])
            last = b
        parts.append(raw[last:])
        free = " ".join(" ".join(parts).split())
    else:
        free = raw

    # 无前缀时：整段是哈希 / IP 则升为字段检索
    if not fields and free:
        hm = _BARE_HASH_RE.match(free.strip())
        if hm:
            fields["hash"] = [hm.group(1).lower()]
            free = ""
        else:
            im = _BARE_IP_RE.match(free.strip())
            if im:
                fields["ip"] = [im.group(1)]
                free = ""

    return free.strip(), fields


def looks_like_basename(q: str) -> bool:
    s = (q or "").strip().strip('"').strip("'")
    if not s or len(s) > 64 or "\\" in s or "/" in s:
        return False
    return bool(_BASENAME_RE.match(s))


def item_basename(item: Dict[str, Any]) -> str:
    title = str(item.get("title") or item.get("name") or item.get("path") or "").strip()
    if not title:
        return ""
    t = title.replace("/", "\\").rstrip("\\")
    return t.rsplit("\\", 1)[-1].lower()


def field_search_needle(free: str, fields: Dict[str, List[str]]) -> str:
    """给底层全文检索用的主关键词：优先自由文本，否则取首个字段值。"""
    if free:
        return free
    for k in ("hash", "ip", "name", "path", "pid", "host"):
        vals = fields.get(k) or []
        if vals:
            return vals[0]
    return ""


def basename_hint(free: str, fields: Dict[str, List[str]]) -> str:
    """短文件名默认子串过宽时给提示。"""
    if fields.get("name"):
        return ""
    cand = (free or "").strip().strip('"')
    if not cand and fields.get("path"):
        return ""
    if looks_like_basename(cand):
        return (
            f"当前为子串包含：「{cand}」也会命中 …v3.1.exe / net1.exe 等。"
            f"精确文件名请用 name:{cand} 或 \"{cand}\"。"
        )
    return ""


def _item_blob(item: Dict[str, Any]) -> str:
    ev = item.get("evidence")
    if isinstance(ev, list):
        ev = " ".join(str(i) for i in ev[:12])
    return " ".join([
        str(item.get("title") or item.get("name") or ""),
        str(ev or item.get("reason") or ""),
        str(item.get("category") or ""),
        str(item.get("rule_id") or ""),
        str(item.get("hostname") or ""),
        str(item.get("path") or ""),
        str(item.get("ip") or ""),
        str(item.get("note") or ""),
        str(item.get("module") or ""),
        str(item.get("kind") or ""),
        str(item.get("file") or item.get("report_id") or ""),
    ]).lower()


def item_matches_fields(item: Dict[str, Any], fields: Dict[str, List[str]]) -> bool:
    """字段约束：同名字段多值 OR，不同字段 AND。"""
    if not fields:
        return True
    blob = _item_blob(item)
    for key, vals in fields.items():
        if not vals:
            continue
        ok = False
        for v in vals:
            vl = str(v or "").strip().lower()
            if not vl:
                continue
            if key == "host":
                hn = str(item.get("hostname") or "").strip().lower()
                if vl == hn or vl in hn or vl in blob:
                    ok = True
                    break
            elif key == "ip":
                ip = str(item.get("ip") or "").strip().lower()
                if vl == ip or vl in blob:
                    ok = True
                    break
            elif key == "hash":
                if vl in blob.replace("0x", ""):
                    ok = True
                    break
            elif key == "path":
                if vl in blob or vl.replace("/", "\\") in blob.replace("/", "\\"):
                    ok = True
                    break
            elif key == "name":
                # 精确文件名（basename），避免 1.exe 命中 v3.1.exe
                base = item_basename(item)
                if base == vl:
                    ok = True
                    break
                # title/path 以 \name 或 /name 结尾
                title = str(item.get("title") or item.get("path") or "").replace("/", "\\").lower()
                if title.endswith("\\" + vl) or title == vl:
                    ok = True
                    break
            elif key == "pid":
                if (
                    f"pid {vl}" in blob
                    or f"pid={vl}" in blob
                    or f"pid:{vl}" in blob
                    or f"(pid {vl})" in blob
                ):
                    ok = True
                    break
            else:
                if vl in blob:
                    ok = True
                    break
        if not ok:
            return False
    return True


def apply_field_filters(items: List[Dict[str, Any]], fields: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    if not fields:
        return items
    return [x for x in items if isinstance(x, dict) and item_matches_fields(x, fields)]


def prefer_exact_basename(items: List[Dict[str, Any]], needle: str) -> List[Dict[str, Any]]:
    """短文件名检索时，把 basename 精确命中排到前面（不删宽匹配）。"""
    n = (needle or "").strip().strip('"').lower()
    if not looks_like_basename(n) or len(items) < 2:
        return items

    def rank(it: Dict[str, Any]) -> Tuple[int, str]:
        base = item_basename(it)
        if base == n:
            return (0, base)
        if base.endswith(n):
            return (1, base)
        return (2, base)

    return sorted(items, key=rank)


def path_segment_hint(free: str, fields: Dict[str, List[str]]) -> str:
    """路径段词默认按分隔符匹配时的提示。"""
    if fields:
        return ""
    cand = (free or "").strip().strip('"')
    from backend.search_sql import looks_like_path_segment
    if looks_like_path_segment(cand):
        return (
            f"「{cand}」按路径段匹配（如 \\{cand}\\），不会命中 PrintTemplate 这类子串。"
            f"若要宽匹配请用 contains 或在词前后加 *。"
        )
    return ""


def prefer_path_segment(items: List[Dict[str, Any]], needle: str) -> List[Dict[str, Any]]:
    """路径段检索：段命中靠前；纯中间子串沉底（不删除，避免漏报感）。"""
    from backend.search_sql import looks_like_path_segment, path_segment_hit

    n = (needle or "").strip().strip('"')
    if not looks_like_path_segment(n) or len(items) < 2:
        return items

    def rank(it: Dict[str, Any]) -> Tuple[int, str]:
        blob = _item_blob(it)
        if path_segment_hit(blob, n):
            return (0, str(it.get("title") or ""))
        if n.lower() in blob:
            return (2, str(it.get("title") or ""))
        return (1, str(it.get("title") or ""))

    return sorted(items, key=rank)


def filter_path_segment_loose(items: List[Dict[str, Any]], needle: str) -> List[Dict[str, Any]]:
    """路径段模式：丢掉仅中间子串命中（PrintTemplate），保留段命中与无路径的告警标题命中。"""
    from backend.search_sql import looks_like_path_segment, path_segment_hit

    n = (needle or "").strip().strip('"')
    if not looks_like_path_segment(n):
        return items
    out: List[Dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        blob = _item_blob(it)
        if path_segment_hit(blob, n):
            out.append(it)
            continue
        # 无路径的文本告警：Temp目录可疑文件 等
        title = str(it.get("title") or it.get("name") or "")
        if path_segment_hit(title, n):
            out.append(it)
    return out


def apply_facet_filters(
    items: List[Dict[str, Any]],
    *,
    facet_host: str = "",
    facet_severity: str = "",
    facet_category: str = "",
    facet_source: str = "",
    facet_module: str = "",
) -> List[Dict[str, Any]]:
    fh = (facet_host or "").strip().lower()
    fs = (facet_severity or "").strip().lower()
    fc = (facet_category or "").strip().lower()
    fsrc = (facet_source or "").strip().lower()
    fm = (facet_module or "").strip().lower()
    if not (fh or fs or fc or fsrc or fm):
        return items
    out: List[Dict[str, Any]] = []
    for x in items:
        if not isinstance(x, dict):
            continue
        if fh and str(x.get("hostname") or "").strip().lower() != fh:
            continue
        if fs and str(x.get("severity") or "").strip().lower() != fs:
            continue
        if fc and str(x.get("category") or x.get("type") or "").strip().lower() != fc:
            continue
        if fsrc:
            src = str(x.get("_source") or "").strip().lower()
            kind = str(x.get("kind") or "").strip().lower()
            if fsrc not in (src, kind) and fsrc != src:
                # 兼容「匹配类型」用 content/hosts/mysql 或 kind
                if fsrc != src and fsrc != kind:
                    continue
        if fm and str(x.get("module") or x.get("kind") or "").strip().lower() != fm:
            continue
        out.append(x)
    return out


def _top_counts(counter: Counter, limit: int = 12) -> List[Dict[str, Any]]:
    items = []
    for value, count in counter.most_common(limit):
        v = str(value or "").strip()
        if not v:
            continue
        items.append({"value": v, "count": int(count), "label": v})
    return items


_SOURCE_LABEL = {
    "mysql": "告警",
    "local": "本地告警",
    "redis": "缓存告警",
    "es": "ES 告警",
    "content": "报告内容",
    "hosts": "台账",
}
_SEV_LABEL = {"high": "高危", "medium": "中危", "low": "低危", "info": "信息", "critical": "严重"}


def build_facets(items: List[Dict[str, Any]], *, limit: int = 12) -> Dict[str, List[Dict[str, Any]]]:
    hosts: Counter = Counter()
    sevs: Counter = Counter()
    cats: Counter = Counter()
    srcs: Counter = Counter()
    mods: Counter = Counter()
    for x in items:
        if not isinstance(x, dict):
            continue
        hn = str(x.get("hostname") or "").strip()
        if hn:
            hosts[hn] += 1
        sev = str(x.get("severity") or "").strip().lower() or "info"
        sevs[sev] += 1
        cat = str(x.get("category") or x.get("type") or "").strip()
        if cat:
            cats[cat] += 1
        src = str(x.get("_source") or "").strip().lower()
        if src:
            srcs[src] += 1
        mod = str(x.get("module") or x.get("kind") or "").strip()
        if mod:
            mods[mod] += 1

    host_items = _top_counts(hosts, limit)
    sev_items = []
    for value, count in sevs.most_common(8):
        sev_items.append({
            "value": value,
            "count": int(count),
            "label": _SEV_LABEL.get(value, value),
        })
    cat_items = _top_counts(cats, limit)
    src_items = []
    for value, count in srcs.most_common(8):
        src_items.append({
            "value": value,
            "count": int(count),
            "label": _SOURCE_LABEL.get(value, value),
        })
    mod_items = _top_counts(mods, limit)
    return {
        "hostname": host_items,
        "severity": sev_items,
        "category": cat_items,
        "source": src_items,
        "module": mod_items,
    }


def extract_trace_pivot(item: Dict[str, Any], fallback_q: str = "") -> Dict[str, Any]:
    """从检索结果抽出可带入威胁溯查的 q / pid。"""
    title = str(item.get("title") or item.get("name") or "").strip()
    evidence = item.get("evidence")
    if isinstance(evidence, list):
        evidence = " ".join(str(i) for i in evidence[:6])
    evidence = str(evidence or item.get("reason") or "")
    blob = f"{title} {evidence}"
    pid = 0
    m = _PID_IN_TEXT_RE.search(blob)
    if m:
        try:
            pid = int(m.group(1))
        except (TypeError, ValueError):
            pid = 0
    # 路径优先
    path = ""
    pm = re.search(r'([a-zA-Z]:\\[^\s|"\']+|\\\\[^\s|"\']+|/(?:[\w.-]+/)+[\w.-]+)', blob)
    if pm:
        path = pm.group(1).strip().strip('"').rstrip(",;）)")
    # 哈希
    hm = re.search(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b", blob)
    ipm = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", blob)
    q = path or (hm.group(1) if hm else "") or (ipm.group(1) if ipm else "") or title or fallback_q
    # 文件名短一些更利于溯查
    if path and ("\\" in path or "/" in path):
        base = path.replace("/", "\\").rsplit("\\", 1)[-1]
        if base and len(base) >= 4:
            q = path  # 完整路径对溯查更准
    return {
        "q": str(q or "").strip()[:260],
        "pid": pid if pid > 0 else 0,
        "file": str(item.get("file") or item.get("report_id") or ""),
        "hostname": str(item.get("hostname") or ""),
    }
