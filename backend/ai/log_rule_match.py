"""AI 研判侧：用系统日志规则库（log_rules + logrules）对照终端时间线/日志。"""
from __future__ import annotations

import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import config

_LOCK = threading.RLock()
_TITLE_CACHE: Dict[str, Any] = {"built_at": 0.0, "items": []}


def logrules_roots() -> List[Path]:
    root = Path(getattr(config, "ROOT", Path(__file__).resolve().parents[2]))
    cands = [
        root / "log_rules" / "rules",
        root / "logrules" / "rules",
        root / "logrules" / "hayabusa",
        root / "logrules" / "sigma",
    ]
    return [p for p in cands if p.is_dir()]


def _load_title_index(*, force: bool = False, limit: int = 2500) -> List[Dict[str, str]]:
    """轻量索引：规则标题/文件名，供证据关键字命中（不全量解析 4k+ Sigma）。"""
    with _LOCK:
        if (
            not force
            and _TITLE_CACHE.get("items")
            and (time.time() - float(_TITLE_CACHE.get("built_at") or 0)) < 1800
        ):
            return list(_TITLE_CACHE["items"])
        items: List[Dict[str, str]] = []
        seen = set()
        # 1) 平台已编译的 eventlog 规则（精确、优先）
        try:
            from ..eventlog_rules import load_eventlog_rules, log_rules_dir
            pack = load_eventlog_rules()
            for r in pack.get("rules") or []:
                title = str(r.get("title") or "").strip()
                if not title:
                    continue
                key = title.lower()
                if key in seen:
                    continue
                seen.add(key)
                items.append({
                    "title": title,
                    "level": str(r.get("level") or ""),
                    "source": "log_rules",
                    "path": str(r.get("path") or ""),
                    "id": str(r.get("id") or title)[:120],
                })
            # 记录目录
            _ = log_rules_dir()
        except Exception:
            pass

        # 2) logrules 目录：用文件名做补充索引（快）
        for root in logrules_roots():
            if "log_rules" in str(root).replace("\\", "/"):
                continue
            try:
                files = list(root.rglob("*.yml"))[:1200] + list(root.rglob("*.yaml"))[:400]
            except OSError:
                continue
            for p in files:
                stem = p.stem.replace("_", " ").replace("-", " ").strip()
                if len(stem) < 6:
                    continue
                key = stem.lower()
                if key in seen:
                    continue
                seen.add(key)
                items.append({
                    "title": stem[:160],
                    "level": "",
                    "source": "logrules",
                    "path": str(p)[:260],
                    "id": p.name[:120],
                })
                if len(items) >= limit:
                    break
            if len(items) >= limit:
                break

        _TITLE_CACHE["items"] = items
        _TITLE_CACHE["built_at"] = time.time()
        return list(items)


def _tokens(text: str) -> List[str]:
    raw = re.findall(r"[A-Za-z0-9_\.]{4,}|[\u4e00-\u9fff]{2,}", (text or "").lower())
    stop = {"process", "create", "windows", "system32", "event", "summary", "agent", "desktop"}
    out = []
    for t in raw:
        if t in stop:
            continue
        if t.isdigit():
            continue
        out.append(t)
        if len(out) >= 40:
            break
    return out


def match_logs_to_rules(
    rows: List[Dict[str, Any]],
    *,
    limit: int = 40,
) -> Dict[str, Any]:
    """把时间线/调查日志样本对照规则标题，返回命中列表。"""
    titles = _load_title_index()
    hits: List[Dict[str, Any]] = []
    seen = set()

    # 精确：若有 event_id+channel，走平台 Sigma 匹配
    try:
        from ..eventlog_rules import match_events
        events = []
        for r in rows or []:
            eid = r.get("event_id")
            ch = r.get("channel")
            if eid in (None, "") or not ch:
                continue
            events.append({
                "Channel": ch,
                "EventID": eid,
                "event_id": eid,
                "channel": ch,
                "TimeCreated": r.get("ts") or "",
                "Message": r.get("summary") or "",
                "CommandLine": r.get("command_line") or "",
            })
        if events:
            matched, _stats = match_events(events[:80])
            for m in (matched or [])[:20]:
                title = str(m.get("title") or m.get("rule_title") or "")
                key = ("exact", title)
                if not title or key in seen:
                    continue
                seen.add(key)
                hits.append({
                    "match": "event_id",
                    "rule_title": title,
                    "level": str(m.get("level") or ""),
                    "source": "log_rules",
                    "evidence": str(m.get("summary") or m.get("message") or "")[:200],
                    "etype": "",
                    "ts": str(m.get("time") or m.get("ts") or ""),
                })
    except Exception:
        pass

    # 模糊：证据关键词 ∩ 规则标题（每条日志可贡献 1 条最佳命中）
    for row in rows or []:
        blob = " ".join(
            str(row.get(k) or "")
            for k in (
                "summary", "etype", "command_line", "path", "script_block",
                "matched", "title", "process_name", "image", "parent_image",
                "target_filename", "rule", "rule_name", "detail",
            )
        )
        toks = _tokens(blob)
        if not toks:
            continue
        # 额外：威胁名 / 规则名整词优先
        extras = []
        for k in ("matched", "title", "rule", "rule_name", "etype"):
            v = str(row.get(k) or "").strip().lower()
            if len(v) >= 5:
                extras.append(v)
        best: Optional[Tuple[int, Dict[str, str]]] = None
        for rule in titles:
            title = rule.get("title") or ""
            tl = title.lower()
            score = 0
            for t in toks:
                if t in tl:
                    score += 2 if len(t) >= 6 else 1
            for ex in extras:
                if ex and (ex in tl or tl in ex):
                    score += 5
            if score < 2:
                continue
            if best is None or score > best[0]:
                best = (score, rule)
        # 次优：同条证据再补 1 条不同规则，提升可见命中面
        second: Optional[Tuple[int, Dict[str, str]]] = None
        if best:
            for rule in titles:
                title = rule.get("title") or ""
                if title == (best[1].get("title") or ""):
                    continue
                tl = title.lower()
                score = sum(2 if len(t) >= 6 else 1 for t in toks if t in tl)
                for ex in extras:
                    if ex and (ex in tl or tl in ex):
                        score += 4
                if score < 3:
                    continue
                if second is None or score > second[0]:
                    second = (score, rule)
        for cand in (best, second):
            if not cand:
                continue
            score, rule = cand
            key = ("kw", rule.get("title"))
            if key in seen:
                continue
            seen.add(key)
            hits.append({
                "match": "keyword",
                "rule_title": rule.get("title"),
                "level": rule.get("level") or "",
                "source": rule.get("source") or "logrules",
                "score": score,
                "evidence": str(row.get("summary") or row.get("command_line") or row.get("title") or "")[:200],
                "etype": str(row.get("etype") or ""),
                "ts": str(row.get("ts") or ""),
                "path": rule.get("path") or "",
            })
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break

    roots = [str(p) for p in logrules_roots()]
    return {
        "ok": True,
        "rules_indexed": len(titles),
        "roots": roots,
        "hits": hits[:limit],
        "hit_count": len(hits),
    }
