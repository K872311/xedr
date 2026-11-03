"""跨主机检索：告警 / 报告内容 / 台账。FastAPI 与后续 Django 管理域共用。"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from backend.search_query import (
    apply_facet_filters,
    apply_field_filters,
    basename_hint,
    build_facets,
    field_search_needle,
    filter_path_segment_loose,
    parse_field_query,
    path_segment_hint,
    prefer_exact_basename,
    prefer_path_segment,
)


def _split_exclude_tokens(raw: str) -> List[str]:
    out: List[str] = []
    seen = set()
    for part in re.split(r"[\s,;，；]+", (raw or "").strip()):
        t = part.strip().lower()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


_HASH_TOKEN_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_PATH_TOKEN_RE = re.compile(
    r"([a-zA-Z]:\\[^\"'<>|\r\n]+?\.(?:exe|dll|bat|cmd|ps1|vbs|js|scr|sys))\b",
    re.I,
)


def _search_expand_fields(x: Dict[str, Any]) -> Dict[str, str]:
    """检索结果附带扩散字段（哈希/路径/命令），供前端一键扩散。"""
    extra = x.get("extra") if isinstance(x.get("extra"), dict) else {}
    out: Dict[str, str] = {}

    def _put(key: str, *cands: Any, limit: int = 500) -> None:
        for c in cands:
            s = str(c or "").strip()
            if s:
                out[key] = s[:limit]
                return

    _put("md5", x.get("md5"), extra.get("md5"))
    _put("sha1", x.get("sha1"), extra.get("sha1"))
    _put("sha256", x.get("sha256"), extra.get("sha256"))
    _put("path", x.get("path"), extra.get("path"), x.get("resolved_path"), extra.get("resolved_path"))
    _put(
        "command",
        x.get("command"),
        extra.get("command"),
        x.get("image_path"),
        extra.get("image_path"),
        extra.get("path") if "cmd" in str(extra.get("path") or "").lower() else "",
    )
    _put("image_path", x.get("image_path"), extra.get("image_path"))

    # 文件扫描：title 即路径
    title = str(x.get("title") or "")
    if not out.get("path") and re.match(r"^[a-zA-Z]:\\", title):
        out["path"] = title[:500]
        if str(x.get("kind") or "") == "file" or str(x.get("module") or "") in ("file", "filetree"):
            pass

    blob = " ".join(
        str(v or "")
        for v in (
            x.get("evidence"),
            x.get("reason"),
            title,
            out.get("path"),
            out.get("command"),
        )
    )
    if not any(out.get(k) for k in ("md5", "sha1", "sha256")):
        m = _HASH_TOKEN_RE.search(blob)
        if m:
            h = m.group(1).lower()
            if len(h) == 32:
                out["md5"] = h
            elif len(h) == 40:
                out["sha1"] = h
            else:
                out["sha256"] = h
    if not out.get("path"):
        m = _PATH_TOKEN_RE.search(blob)
        if m:
            out["path"] = m.group(1)[:500]
    if not out.get("command"):
        ev = str(x.get("evidence") or x.get("reason") or "")
        for sep in ("=>", "→", "->"):
            if sep in ev:
                out["command"] = ev.split(sep, 1)[-1].strip()[:500]
                break
    return out


def _parse_needle_exclude(q: str, exclude: Optional[str] = None) -> Tuple[str, List[str]]:
    """主关键词 + 排除词。排除来自 exclude 参数，以及 q 中的 -词。

    注意：shell 短选项（-e / -c / -rf）不能当排除词，否则 cron/cmdline
    里的 ``test -e`` 会把排除词变成单字母 e，结果被清空。
    行内排除要求去掉 ``-`` 后至少 3 个字符（如 -tmp、-chrome）。
    """
    excludes = _split_exclude_tokens(exclude or "")
    keep: List[str] = []
    for tok in (q or "").strip().split():
        # 保留 field:value；纯 -词 且足够长才作排除
        if tok.startswith("-") and len(tok) > 1 and ":" not in tok[1:]:
            t = tok[1:].strip().lower()
            # 单字母/双字母短选项（-e、-c、-rf）保留在检索词里
            if t and len(t) >= 3 and re.fullmatch(r"[a-z0-9_\u4e00-\u9fff.-]+", t):
                if t not in excludes:
                    excludes.append(t)
                continue
        keep.append(tok)
    return " ".join(keep).strip(), excludes


def _item_search_blob(item: Dict[str, Any]) -> str:
    ev = item.get("evidence")
    if isinstance(ev, list):
        ev = " ".join(str(i) for i in ev[:8])
    return " ".join([
        str(item.get("title") or item.get("name") or ""),
        str(ev or item.get("reason") or ""),
        str(item.get("category") or ""),
        str(item.get("rule_id") or ""),
        str(item.get("hostname") or ""),
        str(item.get("path") or ""),
        str(item.get("ip") or ""),
        str(item.get("note") or ""),
        str(item.get("os") or ""),
        str(item.get("module") or ""),
        str(item.get("kind") or ""),
    ]).lower()


def _pass_exclude(item: Dict[str, Any], excludes: List[str]) -> bool:
    if not excludes:
        return True
    blob = _item_search_blob(item)
    return not any(ex in blob for ex in excludes)


def search_findings(
    user: Optional[Dict[str, Any]],
    q: str,
    hostname: Optional[str] = None,
    severity: Optional[str] = None,
    scope: str = "all",
    exclude: Optional[str] = None,
    size: int = 50,
    offset: int = 0,
    match: str = "smart",
    facet_host: str = "",
    facet_severity: str = "",
    facet_category: str = "",
    facet_source: str = "",
    facet_module: str = "",
) -> Dict[str, Any]:
    from backend.db_store import list_index

    raw_q, exclude_tokens = _parse_needle_exclude(q, exclude)
    free_text, field_map = parse_field_query(raw_q)
    needle = field_search_needle(free_text, field_map)
    # name: 精确文件名 → 报告内容走 exact，避免再扫出 v3.1.exe
    match_mode = (match or "smart").strip().lower()
    if field_map.get("name") and not (free_text or "").strip() and match_mode == "smart":
        match_mode = "exact"
    host_from_field = ""
    if field_map.get("host"):
        host_from_field = str(field_map["host"][0] or "").strip()
    hostname_v = (hostname or "").strip() or host_from_field
    if match_mode not in ("smart", "exact", "prefix", "contains", "segment", "glob"):
        match_mode = "smart"
    exclude_key = " ".join(exclude_tokens)
    scope_v = (scope or "all").strip().lower()
    if scope_v not in ("findings", "content", "hosts", "kb", "knowledge", "all"):
        scope_v = "all"
    if scope_v == "knowledge":
        scope_v = "kb"
    want_findings = scope_v in ("findings", "all")
    want_content = scope_v in ("content", "all")
    want_hosts = scope_v in ("hosts", "all")
    want_kb = scope_v in ("kb", "all")
    from backend.mysql_db import mysql_ready
    from backend.redis_client import is_available as redis_ok

    facet_host_v = (facet_host or "").strip()
    facet_sev_v = (facet_severity or "").strip()
    facet_cat_v = (facet_category or "").strip()
    facet_src_v = (facet_source or "").strip()
    facet_mod_v = (facet_module or "").strip()
    severity_v = (facet_sev_v or severity or "").strip() or None
    if facet_host_v and not hostname_v:
        hostname_v = facet_host_v

    empty_facets: Dict[str, List] = {
        "hostname": [], "severity": [], "category": [], "source": [], "module": [],
    }
    if not needle:
        return {
            "q": "",
            "exclude": exclude_key,
            "scope": scope_v,
            "fields": field_map,
            "findings": [],
            "items": [],
            "facets": empty_facets,
            "total": 0,
            "offset": max(0, int(offset or 0)),
            "size": max(1, int(size or 50)),
            "has_next": False,
            "reports": [],
            "engine": "-",
            "es": False,
            "mysql": mysql_ready(),
            "redis": redis_ok(),
            "hint": "请输入检索关键词；支持 hash: / ip: / path: / pid: / host: 字段前缀。",
            "cache": "",
            "match": match_mode,
            "match_label": "",
        }
    findings: List[Dict[str, Any]] = []
    es_used = False
    mysql_hits = False
    mysql_queried = False
    mysql_total = 0
    local_hits = False
    content_more = False
    hosts_more = False
    seen = set()
    offset_v = max(0, int(offset or 0))
    size_v = max(1, int(size or 50))
    pack_all: Optional[List[Dict[str, Any]]] = None

    def _merge(extra, src=""):
        nonlocal findings
        n = 0
        for item in extra or []:
            if not isinstance(item, dict):
                continue
            if not _pass_exclude(item, exclude_tokens):
                continue
            if field_map and not apply_field_filters([item], field_map):
                continue
            key = "|".join([
                str(item.get("report_id") or item.get("file") or ""),
                str(item.get("title") or ""),
                str(item.get("evidence") or "")[:80],
            ])
            if key in seen:
                continue
            if src and not item.get("_source"):
                item["_source"] = src
            findings.append(item)
            seen.add(key)
            n += 1
            if len(findings) >= size_v:
                break
        return n

    cache_hit = False
    if needle and want_findings and mysql_ready():
        try:
            from backend.hot_cache import (
                SEARCH_PACK_CAP,
                SEARCH_PACK_COLD,
                findings_search_digest,
                get_search_pack,
                set_search_pack,
            )
            from backend.mysql_store import search_findings_mysql
            from backend.ownership import is_admin
            owner_id = "" if (not user or is_admin(user)) else str(user.get("id") or "")
            # severity 不进 digest：分面级别在 pack 上过滤，避免重复缓存
            digest = findings_search_digest(
                needle, hostname_v, None, owner_id, exclude=exclude_key,
            )
            packed_items: List[Dict[str, Any]] = []
            pack = get_search_pack(digest)
            if isinstance(pack, dict) and isinstance(pack.get("items"), list):
                packed_items = [x for x in pack["items"] if isinstance(x, dict)]
                mysql_total = int(pack.get("total") or len(packed_items))
                cache_hit = True
                # 翻页超出冷包：回源拉满上限再缓存
                if offset_v + size_v > len(packed_items) and mysql_total > len(packed_items):
                    packed = search_findings_mysql(
                        needle, hostname=hostname_v or None, severity=None,
                        size=SEARCH_PACK_CAP, offset=0, user=user,
                    )
                    if isinstance(packed, tuple):
                        packed_items, mysql_total = packed
                    else:
                        packed_items = packed or []
                        mysql_total = len(packed_items)
                    if exclude_tokens:
                        packed_items = [
                            x for x in (packed_items or [])
                            if isinstance(x, dict) and _pass_exclude(x, exclude_tokens)
                        ]
                        mysql_total = len(packed_items)
                    try:
                        set_search_pack(digest, {
                            "total": int(mysql_total or 0),
                            "items": packed_items or [],
                        })
                    except Exception:
                        pass
                    cache_hit = False
            else:
                # 冷查询先拉一小包，降低首屏 LIKE/FULLTEXT 成本
                cold_n = min(
                    SEARCH_PACK_CAP,
                    max(int(SEARCH_PACK_COLD), offset_v + size_v * 4, size_v + 50),
                )
                packed = search_findings_mysql(
                    needle, hostname=hostname_v or None, severity=None,
                    size=cold_n, offset=0, user=user,
                )
                if isinstance(packed, tuple):
                    packed_items, mysql_total = packed
                else:
                    packed_items = packed or []
                    mysql_total = len(packed_items)
                if exclude_tokens:
                    packed_items = [
                        x for x in (packed_items or [])
                        if isinstance(x, dict) and _pass_exclude(x, exclude_tokens)
                    ]
                    mysql_total = len(packed_items)
                try:
                    set_search_pack(digest, {
                        "total": int(mysql_total or 0),
                        "items": packed_items or [],
                    })
                except Exception:
                    pass

            filtered = apply_field_filters(list(packed_items or []), field_map)
            if exclude_tokens and cache_hit:
                filtered = [x for x in filtered if _pass_exclude(x, exclude_tokens)]
            pack_all = filtered
            faceted = apply_facet_filters(
                filtered,
                facet_host=facet_host_v,
                facet_severity=facet_sev_v or (severity or ""),
                facet_category=facet_cat_v,
                facet_source=facet_src_v,
                facet_module=facet_mod_v,
            )
            mysql_total = len(faceted)
            extra = faceted[offset_v:offset_v + size_v]
            deep = (
                offset_v >= SEARCH_PACK_CAP
                and offset_v < int(mysql_total or 0)
                and not field_map
                and not (facet_host_v or facet_sev_v or facet_cat_v or facet_src_v or facet_mod_v)
            )
            if deep:
                packed = search_findings_mysql(
                    needle, hostname=hostname_v or None, severity=severity_v,
                    size=size_v, offset=offset_v, user=user,
                )
                if isinstance(packed, tuple):
                    extra, mysql_total = packed
                else:
                    extra = packed or []
                if exclude_tokens:
                    extra = [
                        x for x in (extra or [])
                        if isinstance(x, dict) and _pass_exclude(x, exclude_tokens)
                    ]
            mysql_queried = True
            mysql_hits = bool(extra)
            for item in extra or []:
                if not isinstance(item, dict):
                    continue
                key = "|".join([
                    str(item.get("report_id") or item.get("file") or ""),
                    str(item.get("title") or ""),
                    str(item.get("evidence") or "")[:80],
                ])
                if key in seen:
                    continue
                if not item.get("_source"):
                    item["_source"] = "mysql"
                findings.append(item)
                seen.add(key)
        except Exception as e:
            print(f"[search] mysql findings: {e}")

    allow_fill = (not mysql_queried) or (offset_v == 0 and len(findings) < size_v)
    if needle and want_findings and len(findings) < size_v and allow_fill:
        try:
            from backend.db_store import search_findings_local
            extra = search_findings_local(
                needle, hostname=hostname_v or None, severity=severity_v,
                size=size_v, offset=offset_v, user=user,
            )
            local_hits = bool(extra)
            _merge(extra, "local")
        except Exception as e:
            print(f"[search] local findings: {e}")
    redis_hits = False
    if needle and want_findings and redis_ok() and len(findings) < size_v and allow_fill and offset_v == 0:
        try:
            from backend.result_sync import search_findings_redis
            extra = search_findings_redis(
                needle, hostname=hostname_v or None, severity=severity_v,
                size=size_v - len(findings), user=user,
            )
            redis_hits = bool(extra)
            _merge(extra, "redis")
        except Exception as e:
            print(f"[search] redis findings: {e}")
    if needle and want_findings and len(findings) < size_v and allow_fill and offset_v == 0:
        try:
            from backend.es_client import search_findings, is_available as es_ok
            if es_ok():
                _merge(
                    search_findings(
                        needle, hostname=hostname_v or None, severity=severity_v,
                        size=size_v, user=user,
                    ) or [],
                    "es",
                )
                es_used = True
        except Exception as e:
            print(f"[search] es findings: {e}")
            es_used = False
    content_hits = False
    # scope=all 且告警已有命中时，默认不再扫报告内容（避免 fanout）。
    # 但 match=contains/exact（狩猎跳转）必须继续扫内容，否则 wefault / SiPolicy 等落点只在正文里会漏检。
    # 有分类分面时继续扫正文：点「系统日志」等需把 event_logs 内容类命中并进来再滤
    skip_content = bool(
        scope_v == "all"
        and want_findings
        and mysql_hits
        and match_mode not in ("contains", "exact", "glob")
        and not facet_cat_v
    )
    if (
        needle
        and want_content
        and not skip_content
        and len(findings) < size_v
        and (offset_v == 0 or not want_findings)
    ):
        try:
            from backend.db_store import search_report_content_local
            if want_findings:
                extra = search_report_content_local(
                    needle, hostname=hostname_v or None, size=size_v - len(findings), user=user,
                    match_mode=match_mode,
                )
            else:
                fetched = search_report_content_local(
                    needle, hostname=hostname_v or None, size=offset_v + size_v + 1, user=user,
                    match_mode=match_mode,
                ) or []
                content_more = len(fetched) > offset_v + size_v
                extra = fetched[offset_v:offset_v + size_v]
            content_hits = bool(extra)
            _merge(extra, "content")
        except Exception as e:
            print(f"[search] report content: {e}")
    hosts_hits = False
    if needle and want_hosts and len(findings) < size_v and (offset_v == 0 or not want_findings):
        try:
            from backend.ownership import can_view_hosts
            if can_view_hosts(user):
                from backend.hosts import search_hosts
                if want_findings:
                    extra = search_hosts(
                        needle, hostname=hostname_v or None, size=size_v - len(findings),
                    )
                else:
                    fetched = search_hosts(
                        needle, hostname=hostname_v or None, size=offset_v + size_v + 1,
                    ) or []
                    hosts_more = len(fetched) > offset_v + size_v
                    extra = fetched[offset_v:offset_v + size_v]
                hosts_hits = bool(extra)
                _merge(extra, "hosts")
        except Exception as e:
            print(f"[search] hosts: {e}")
    kb_hits = False
    if needle and want_kb and len(findings) < size_v and (offset_v == 0 or not want_findings):
        try:
            from backend.knowledge_store import search_knowledge
            if want_findings:
                extra = search_knowledge(needle, limit=max(5, size_v - len(findings)))
            else:
                fetched = search_knowledge(needle, limit=min(80, offset_v + size_v + 1)) or []
                extra = fetched[offset_v:offset_v + size_v]
            kb_hits = bool(extra)
            _merge(extra, "kb")
        except Exception as e:
            print(f"[search] knowledge: {e}")

    if pack_all is None:
        pack_all = list(findings)
    else:
        # 分面宇宙补上本页合并进的 content/hosts，避免芯片计数只有 MySQL 告警
        pack_keys = {
            "|".join([
                str(x.get("report_id") or x.get("file") or ""),
                str(x.get("title") or ""),
                str(x.get("evidence") or "")[:80],
            ])
            for x in pack_all
            if isinstance(x, dict)
        }
        for x in findings:
            if not isinstance(x, dict):
                continue
            key = "|".join([
                str(x.get("report_id") or x.get("file") or ""),
                str(x.get("title") or ""),
                str(x.get("evidence") or "")[:80],
            ])
            if key in pack_keys:
                continue
            pack_all.append(x)
            pack_keys.add(key)

    # 最终统一过一遍分面：MySQL 打包路径上后合并的报告内容/台账此前会漏滤，
    # 导致点「分类=IOC」仍混进系统日志等其它结果。
    has_facet = bool(
        facet_host_v or facet_sev_v or facet_cat_v or facet_src_v or facet_mod_v or (severity or "").strip()
    )
    if has_facet:
        findings = apply_facet_filters(
            findings,
            facet_host=facet_host_v,
            facet_severity=facet_sev_v or (severity or ""),
            facet_category=facet_cat_v,
            facet_source=facet_src_v,
            facet_module=facet_mod_v,
        )

    reports = []
    if needle:
        from backend.search_sql import text_matches_query
        for row in list_index(80, user=user):
            blob = " ".join([
                str(row.get("hostname") or ""),
                str(row.get("file") or ""),
                str(row.get("ip") or ""),
            ])
            if text_matches_query(blob, needle) and (
                not exclude_tokens or not any(ex in blob.lower() for ex in exclude_tokens)
            ):
                reports.append(row)
            if len(reports) >= 20:
                break
    srcs = {(x.get("_source") or "") for x in findings}
    if "mysql" in srcs or mysql_hits:
        engine = "mysql"
    elif "content" in srcs or content_hits:
        engine = "content"
    elif "local" in srcs or local_hits:
        engine = "local"
    elif "redis" in srcs or redis_hits:
        engine = "redis"
    elif "es" in srcs or es_used:
        engine = "elasticsearch"
    elif "kb" in srcs or kb_hits:
        engine = "knowledge"
    else:
        engine = "mysql" if mysql_ready() else "local"
    hint = ""
    if needle and not findings:
        if scope_v == "content":
            hint = "未命中报告内容。可搜文件路径、文件名、哈希、日志正文；需先完成分析。"
        elif scope_v == "findings":
            hint = "未命中告警。可搜标题/证据/路径/分类；需先完成分析并同步到 MySQL。"
        elif scope_v == "hosts":
            hint = "未命中台账。可搜主机名、IP、备注、系统版本、报告/告警统计。"
        elif scope_v == "kb":
            hint = "未命中知识库。可搜特征文件名、路径片段、哈希、手法标签；请到「知识库」补充条目。"
        else:
            hint = "未命中。可搜告警、文件/日志、主机台账、知识库；也可用 hash: / ip: / path: 前缀。"
    elif kb_hits and scope_v == "kb":
        hint = "已从应急知识库检索（特征 / 误报 / 剧本）。"
    elif hosts_hits and scope_v == "hosts":
        hint = "已从主机台账检索（主机名 / IP / 备注 / 系统 / 统计）。"
    elif content_hits and scope_v == "content":
        hint = "已从报告内容库检索（文件扫描 / 系统日志）。"
    elif (content_hits or hosts_hits or kb_hits) and scope_v == "all":
        bits = []
        if want_findings and (mysql_hits or local_hits or redis_hits or es_used):
            bits.append("告警")
        if content_hits:
            bits.append("报告内容")
        if hosts_hits:
            bits.append("台账")
        if kb_hits:
            bits.append("知识库")
        hint = f"已合并{' + '.join(bits)}检索结果。" if bits else "已合并多源检索结果。"
    elif content_hits and want_findings:
        hint = "已合并告警库与报告内容检索结果。"
    elif mysql_hits:
        hint = "已从 MySQL 告警库检索。"
    elif local_hits:
        hint = "MySQL 未命中或不足，已从本地分析结果补齐。"
    elif redis_hits:
        hint = "已从 Redis 分析缓存补齐告警。"
    elif es_used:
        hint = "已从 Elasticsearch 补齐（可选）。"
    elif kb_hits:
        hint = "已附带知识库命中。"
    if field_map:
        bits = [f"{k}:{v[0]}" for k, v in field_map.items() if v]
        if bits:
            hint = ((hint + " ") if hint else "") + "字段：" + " ".join(bits[:4])
    bh = basename_hint(free_text, field_map)
    if bh:
        hint = ((hint + " ") if hint else "") + bh
    from backend.search_sql import classify
    plan = classify(needle, match_mode)
    if plan.mode == "segment":
        findings = filter_path_segment_loose(findings, plan.term)
        findings = prefer_path_segment(findings, plan.term)
        ph = path_segment_hint(free_text, field_map)
        if ph:
            hint = ((hint + " ") if hint else "") + ph
    elif plan.mode == "glob":
        from backend.search_query import _item_blob
        from backend.search_sql import text_matches_query
        findings = [
            x for x in findings
            if isinstance(x, dict) and text_matches_query(_item_blob(x), plan.raw or plan.term)
        ]
        hint = ((hint + " ") if hint else "") + (
            "通配匹配：「*」任意长度、「?」单字符。例 Temp\\*.cfg\\*.exe"
        )
    if want_content and content_hits and plan.mode not in ("contains",):
        hint = (hint + " ") if hint else ""
        hint += f"报告内容按「{plan.label}」匹配。"
    # 分面必须在合并告警+内容+台账之后再滤一次。
    # 否则 MySQL 分页切片后再并入的报告内容会绕过分类/级别等分面（点 IOC 仍看到系统日志）。
    has_facet = bool(facet_host_v or facet_sev_v or facet_cat_v or facet_src_v or facet_mod_v)
    if has_facet:
        findings = apply_facet_filters(
            findings,
            facet_host=facet_host_v,
            facet_severity=facet_sev_v or (severity or ""),
            facet_category=facet_cat_v,
            facet_source=facet_src_v,
            facet_module=facet_mod_v,
        )
    # 短文件名：精确 basename 优先展示
    if not field_map.get("name"):
        findings = prefer_exact_basename(findings, needle)
    clean = []
    for x in findings:
        if not isinstance(x, dict):
            continue
        ev = x.get("evidence")
        if isinstance(ev, list):
            ev = "；".join(str(i) for i in ev[:4])
        clean.append({
            "hostname": str(x.get("hostname") or ""),
            "report_id": str(x.get("report_id") or x.get("file") or ""),
            "file": str(x.get("file") or x.get("report_id") or ""),
            "title": str(x.get("title") or x.get("name") or ""),
            "evidence": str(ev or x.get("reason") or "")[:500],
            "severity": str(x.get("severity") or "medium"),
            "category": str(x.get("category") or x.get("type") or ""),
            "rule_id": str(x.get("rule_id") or ""),
            "matcher": str(x.get("matcher") or ""),
            "module": str(x.get("module") or ""),
            "kind": str(x.get("kind") or ""),
            "_source": str(x.get("_source") or ""),
            "host_id": str(x.get("host_id") or ""),
            "ip": str(x.get("ip") or ""),
            "note": str(x.get("note") or "")[:500],
            "os": str(x.get("os") or "")[:200],
            "os_family": str(x.get("os_family") or ""),
            "report_count": int(x.get("report_count") or 0),
            "issues": int(x.get("issues") or 0),
            "last_time": str(x.get("last_time") or ""),
            # 一键扩散：保留哈希 / 路径 / 命令
            **_search_expand_fields(x),
        })
    facets = build_facets(pack_all if pack_all is not None else clean)
    total = 0
    if has_facet:
        # 分面后以当前页实际条数为准，避免仍显示未过滤的「共 50 条」
        if pack_all is not None:
            faceted_n = len(apply_facet_filters(
                pack_all,
                facet_host=facet_host_v,
                facet_severity=facet_sev_v or (severity or ""),
                facet_category=facet_cat_v,
                facet_source=facet_src_v,
                facet_module=facet_mod_v,
            ))
            total = max(faceted_n, offset_v + len(clean))
            has_next = offset_v + len(clean) < faceted_n
        else:
            total = offset_v + len(clean)
            has_next = False
    elif mysql_queried:
        total = max(int(mysql_total or 0), offset_v + len(clean))
        has_next = offset_v + len(clean) < int(mysql_total or 0)
    elif content_more or hosts_more:
        total = offset_v + len(clean) + 1
        has_next = True
    else:
        total = offset_v + len(clean)
        has_next = len(clean) >= size_v
        if has_next:
            total = offset_v + len(clean) + 1
    return {
        "q": needle,
        "exclude": exclude_key,
        "scope": scope_v,
        "fields": field_map,
        "findings": clean,
        "items": clean,
        "facets": facets,
        "total": total,
        "offset": offset_v,
        "size": size_v,
        "has_next": bool(has_next),
        "reports": reports,
        "engine": engine or ("local" if clean else "-"),
        "es": es_used,
        "mysql": mysql_ready(),
        "redis": redis_ok(),
        "hint": hint,
        "cache": "redis" if cache_hit else "",
        "match": match_mode,
        "match_label": plan.label if want_content else "",
    }
