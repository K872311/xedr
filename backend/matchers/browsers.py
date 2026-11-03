"""按 rules-browsers.json：解析采集端 SQL 抽取的 browser_artifacts + 路径闭环"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from ..models import Finding
from ..rules_loader import RuleStore
from .rule_engine import match_rmm_rule

BROWSER_PATH_HINTS = [
    ("History", "浏览器History"),
    ("Login Data", "浏览器Login Data"),
    ("Cookies", "浏览器Cookies"),
    ("Web Data", "浏览器Web Data"),
    ("places.sqlite", "Firefox书签/历史"),
    ("cookies.sqlite", "Firefox Cookies"),
    ("formhistory.sqlite", "Firefox表单"),
]

# 高价值浏览/下载线索（比 Temp 刷屏更有研判意义）
SUSPICIOUS_URL_HINTS = [
    ("threatbook", "high", "威胁情报站"),
    ("abuse.ch", "high", "恶意样本情报"),
    ("vuldb.com", "high", "漏洞库"),
    ("malware", "high", "恶意软件关键词"),
    ("raw.githubusercontent.com", "medium", "GitHub Raw"),
    ("gist.github.com", "medium", "GitHub Gist"),
    ("pastebin.com", "medium", "Pastebin"),
    ("ngrok", "high", "隧道外联"),
    ("hack", "medium", "黑客相关"),
    ("exploit", "high", "Exploit"),
    ("cobaltstrike", "critical", "CobaltStrike"),
    ("mimikatz", "critical", "Mimikatz"),
    ("powershell", "medium", "PS相关下载页"),
    ("todesk", "high", "ToDesk官网/下载"),
    ("sunlogin", "high", "向日葵"),
    ("oray.com", "high", "向日葵/花生壳"),
    ("anydesk", "high", "AnyDesk"),
    ("teamviewer", "medium", "TeamViewer"),
    ("rustdesk", "high", "RustDesk"),
]

SEARCH_ENGINES = [
    ("google.", "q"),
    ("bing.", "q"),
    ("baidu.", "wd"),
    ("baidu.", "word"),
    ("duckduckgo.", "q"),
    ("sogou.", "query"),
    ("so.com", "q"),
]


def _row_url(row: Dict) -> str:
    for k in ("url", "origin_url", "page_url", "tab_url"):
        v = row.get(k)
        if v:
            return str(v)
    return ""


def _row_text(row: Dict) -> str:
    parts = []
    for k, v in row.items():
        if v is None or k.endswith("_iso"):
            continue
        parts.append(str(v))
    return " ".join(parts)


def _extract_search(url: str) -> str:
    try:
        u = urlparse(url)
        host = (u.netloc or "").lower()
        qs = parse_qs(u.query)
        for dom, key in SEARCH_ENGINES:
            if dom in host and key in qs and qs[key]:
                return unquote(qs[key][0])[:200]
    except Exception:
        pass
    return ""


def run_browser_sql(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    meta = {"browser_blocks": 0, "browser_rows": 0, "browser_sql_ok": 0}
    arts = report.get("browser_artifacts") or []
    meta["browser_blocks"] = len(arts)
    rmm = store.rmm_rules()
    ioc_domains = set(x.lower() for x in (store.ioc.get("domain") or []) if x)
    ioc_urls = set(x.lower() for x in (store.ioc.get("url") or []) if x)

    # 用 rules 元数据标记已消费
    _ = store.browsers

    for art in arts:
        if not isinstance(art, dict):
            continue
        kind = art.get("kind") or ""
        browser = art.get("browser") or "?"
        user = art.get("user") or ""
        status = art.get("status") or ""
        if status == "ok" and (art.get("row_count") or 0) > 0:
            meta["browser_sql_ok"] += 1
        rows = art.get("rows") or []
        meta["browser_rows"] += len(rows)

        if status in ("locked", "error") and art.get("db_path"):
            key = f"浏览器采集|{status}|{art.get('db_path')}|browser"
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    "浏览器采集", "low", f"{browser} {kind} {status}",
                    art.get("error") or art.get("db_path"), "browser_artifacts", kind, "browsers",
                ))

        for row in rows:
            if not isinstance(row, dict):
                continue
            url = _row_url(row)
            blob = _row_text(row)
            low = (url + " " + blob).lower()

            # IOC
            for d in ioc_domains:
                if d and d in low:
                    key = f"IOC|domain|{d}|{url[:120]}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding("IOC", "critical", f"域名 {d}", url or blob[:200], "browser_sql", d, "browsers"))
                    break
            for iu in ioc_urls:
                if iu and iu in low:
                    key = f"IOC|url|{iu[:80]}|{url[:80]}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding("IOC", "critical", "URL命中", url or iu, "browser_sql", iu, "browsers"))

            # 可疑 URL / 下载
            if kind in ("history", "downloads", "bookmarks", "favicons") and url:
                for hint, sev, title in SUSPICIOUS_URL_HINTS:
                    if hint in low:
                        key = f"浏览痕迹|{title}|{url[:160]}|browser_sql"
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding(
                                "浏览痕迹", sev, title,
                                f"{browser}/{user}: {url}"[:300], "browser_sql", hint, "browsers",
                            ))
                        break
                # 搜索词（rules crossBrowserSearchQueryAnalysis）
                q = _extract_search(url)
                if q:
                    qlow = q.lower()
                    hot = any(x in qlow for x in (
                        "远控", "木马", "免杀", "提权", "mimikatz", "cobalt", "漏洞", "hack",
                        "todesk", "向日葵", "代理", "翻墙", "vpn",
                    ))
                    if hot:
                        key = f"搜索词|{q}|browser_sql"
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding(
                                "搜索词", "high", q[:80],
                                f"{browser}: {url[:200]}", "browser_sql", "SEUQA", "browsers",
                            ))

            # 下载可执行
            if kind == "downloads":
                path = str(row.get("full_path") or row.get("target") or "")
                if re.search(r"\.(exe|dll|bat|cmd|ps1|vbs|msi|scr)\b", path, re.I):
                    key = f"浏览器下载|{path}|{url[:80]}"
                    if key not in seen:
                        seen.add(key)
                        sev = "high"
                        title = "浏览器下载可执行"
                        for rule in rmm:
                            if match_rmm_rule(path, rule, is_path=True) or match_rmm_rule(url, rule, is_path=True):
                                title = rule.get("tool", title)
                                break
                        findings.append(Finding(
                            "浏览器下载", sev, title,
                            f"{path} ← {url}"[:300], "browser_sql", "download", "browsers",
                        ))

            # 登录域（不含密码）
            if kind == "logins":
                origin = str(row.get("origin_url") or row.get("signon_realm") or "")
                user_v = str(row.get("username_value") or "")
                if origin and any(x in origin.lower() for x in ("mail", "bank", "vpn", "admin", "oa", "erp", "login")):
                    key = f"浏览器登录|{origin}|{user_v}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding(
                            "浏览器登录", "medium", "敏感站点凭据痕迹",
                            f"{browser}: {origin} user={user_v}"[:240], "browser_sql", "logins", "browsers",
                        ))

    return findings, meta


def run_browser_paths(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings = []
    hints = BROWSER_PATH_HINTS
    # 从 rules-browsers databases.file 补充
    for b in (store.browsers.get("browsers") or []):
        for db in b.get("databases") or []:
            fn = db.get("file")
            if fn and not any(fn == h[0] for h in hints):
                hints = hints + [(fn, f"浏览器{fn}")]
    scans = report.get("file_scans") or []
    if not scans:
        from ..db_store import files_rid, query_files
        rid = files_rid(report)
        if rid:
            seen_p = set()
            extra = []
            for hint, _title in hints[:24]:
                try:
                    for row in query_files(rid, name_contains=hint, limit=8):
                        fp = row.get("full_path") or ""
                        if fp in seen_p:
                            continue
                        seen_p.add(fp)
                        extra.append(row)
                except Exception:
                    pass
            scans = extra
    for f in scans:
        full = f.get("full_path") or ""
        name = f.get("name") or ""
        for hint, title in hints:
            if name == hint or full.endswith("\\" + hint) or full.endswith("/" + hint):
                key = f"浏览器痕迹|{title}|{full}|文件扫描"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding("浏览器痕迹", "medium", title, full, "文件扫描", hint, "browsers"))
                break
    return findings, {}


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    f1, m1 = run_browser_sql(report, store, seen)
    f2, m2 = run_browser_paths(report, store, seen)
    meta = {**m1, **m2}
    return f1 + f2, meta
