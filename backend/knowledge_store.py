# -*- coding: utf-8 -*-
"""应急知识库：特征 / 研判卡片 / 误报说明（独立 SQLite）。

用于全局检索与 AI 窗口增强；不是 IOC，也不是检测规则。
有效条目应含：可检索特征键 + 简短判定 + 建议打开模块。
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

TABLE = "kb_articles"
DB_NAME = "knowledge.db"

_KINDS = ("feature", "playbook", "false_positive", "technique", "note")
_SEVERITIES = ("", "info", "low", "medium", "high", "critical")

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'feature',
    severity TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    features TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    body TEXT DEFAULT '',
    modules TEXT DEFAULT '',
    query_hint TEXT DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT DEFAULT 'manual',
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_kb_kind ON {TABLE}(kind);
CREATE INDEX IF NOT EXISTS idx_kb_enabled ON {TABLE}(enabled);
CREATE INDEX IF NOT EXISTS idx_kb_title ON {TABLE}(title);
"""

_lock = threading.RLock()


def db_path() -> Path:
    d = Path(getattr(config, "IOC_DIR", None) or (Path(config.ROOT) / "ioc"))
    # 知识库与人工 IOC 同目录，便于备份
    d.mkdir(parents=True, exist_ok=True)
    return d / DB_NAME


def _connect() -> sqlite3.Connection:
    path = db_path()
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def ensure_db() -> Path:
    with _lock:
        conn = _connect()
        conn.close()
    return db_path()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _split_csv(raw: Any) -> List[str]:
    if isinstance(raw, list):
        parts = [str(x or "").strip() for x in raw]
    else:
        parts = re.split(r"[,;\n|/]+", str(raw or ""))
    out: List[str] = []
    seen = set()
    for p in parts:
        p = p.strip()
        if not p:
            continue
        key = p.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p[:200])
    return out[:40]


def _join_csv(items: List[str]) -> str:
    return ", ".join(items)


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["tags"] = _split_csv(d.get("tags"))
    d["features"] = _split_csv(d.get("features"))
    d["modules"] = _split_csv(d.get("modules"))
    d["enabled"] = bool(int(d.get("enabled") or 0))
    return d


def _validate_payload(payload: Dict[str, Any], *, partial: bool = False) -> Dict[str, Any]:
    title = str(payload.get("title") or "").strip()
    if not partial and not title:
        raise ValueError("标题不能为空")
    kind = str(payload.get("kind") or "feature").strip().lower() or "feature"
    if kind not in _KINDS:
        raise ValueError(f"kind 须为 {' / '.join(_KINDS)}")
    sev = str(payload.get("severity") or "").strip().lower()
    if sev not in _SEVERITIES:
        sev = ""
    summary = str(payload.get("summary") or "").strip()[:2000]
    body = str(payload.get("body") or "").strip()[:20000]
    query_hint = str(payload.get("query_hint") or "").strip()[:500]
    source = str(payload.get("source") or "manual").strip()[:120] or "manual"
    enabled = 1 if payload.get("enabled", True) else 0
    tags = _split_csv(payload.get("tags"))
    features = _split_csv(payload.get("features"))
    modules = _split_csv(payload.get("modules"))
    out: Dict[str, Any] = {
        "kind": kind,
        "severity": sev,
        "tags": _join_csv(tags),
        "features": _join_csv(features),
        "summary": summary,
        "body": body,
        "modules": _join_csv(modules),
        "query_hint": query_hint,
        "enabled": enabled,
        "source": source,
    }
    if title or not partial:
        out["title"] = title[:200]
    return out


def create_article(payload: Dict[str, Any]) -> Dict[str, Any]:
    data = _validate_payload(payload, partial=False)
    now = _now()
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                f"""INSERT INTO {TABLE}
                (title, kind, severity, tags, features, summary, body, modules, query_hint, enabled, source, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    data["title"], data["kind"], data["severity"], data["tags"], data["features"],
                    data["summary"], data["body"], data["modules"], data["query_hint"],
                    data["enabled"], data["source"], now, now,
                ),
            )
            conn.commit()
            rid = int(cur.lastrowid)
            row = conn.execute(f"SELECT * FROM {TABLE} WHERE id=?", (rid,)).fetchone()
            return {"ok": True, "item": _row_to_dict(row)}
        finally:
            conn.close()


def update_article(article_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    data = _validate_payload(payload, partial=True)
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(f"SELECT * FROM {TABLE} WHERE id=?", (int(article_id),)).fetchone()
            if not row:
                return {"ok": False, "error": "条目不存在"}
            merged = _row_to_dict(row)
            for k in ("title", "kind", "severity", "summary", "body", "query_hint", "source"):
                if k in data:
                    merged[k] = data[k]
            if "tags" in data:
                merged["tags"] = _split_csv(data["tags"])
            if "features" in data:
                merged["features"] = _split_csv(data["features"])
            if "modules" in data:
                merged["modules"] = _split_csv(data["modules"])
            if "enabled" in data:
                merged["enabled"] = bool(data["enabled"])
            now = _now()
            conn.execute(
                f"""UPDATE {TABLE} SET
                title=?, kind=?, severity=?, tags=?, features=?, summary=?, body=?,
                modules=?, query_hint=?, enabled=?, source=?, updated_at=?
                WHERE id=?""",
                (
                    merged["title"], merged["kind"], merged["severity"],
                    _join_csv(merged["tags"]), _join_csv(merged["features"]),
                    merged["summary"], merged["body"], _join_csv(merged["modules"]),
                    merged["query_hint"], 1 if merged["enabled"] else 0,
                    merged["source"], now, int(article_id),
                ),
            )
            conn.commit()
            row2 = conn.execute(f"SELECT * FROM {TABLE} WHERE id=?", (int(article_id),)).fetchone()
            return {"ok": True, "item": _row_to_dict(row2)}
        finally:
            conn.close()


def delete_article(article_id: int) -> Dict[str, Any]:
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(f"DELETE FROM {TABLE} WHERE id=?", (int(article_id),))
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "条目不存在"}
            return {"ok": True, "deleted": int(article_id)}
        finally:
            conn.close()


def get_article(article_id: int) -> Optional[Dict[str, Any]]:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(f"SELECT * FROM {TABLE} WHERE id=?", (int(article_id),)).fetchone()
            return _row_to_dict(row) if row else None
        finally:
            conn.close()


def list_articles(
    *,
    q: str = "",
    kind: str = "",
    enabled_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 50), 200))
    offset = max(0, int(offset or 0))
    where = ["1=1"]
    args: List[Any] = []
    if enabled_only:
        where.append("enabled=1")
    kind_v = str(kind or "").strip().lower()
    if kind_v and kind_v in _KINDS:
        where.append("kind=?")
        args.append(kind_v)
    qn = str(q or "").strip().lower()
    if qn:
        where.append(
            "(lower(title) LIKE ? OR lower(tags) LIKE ? OR lower(features) LIKE ? "
            "OR lower(summary) LIKE ? OR lower(body) LIKE ? OR lower(query_hint) LIKE ?)"
        )
        like = f"%{qn}%"
        args.extend([like, like, like, like, like, like])
    sql_where = " AND ".join(where)
    with _lock:
        conn = _connect()
        try:
            total = int(conn.execute(f"SELECT COUNT(*) FROM {TABLE} WHERE {sql_where}", args).fetchone()[0])
            rows = conn.execute(
                f"SELECT * FROM {TABLE} WHERE {sql_where} ORDER BY updated_at DESC, id DESC LIMIT ? OFFSET ?",
                (*args, limit, offset),
            ).fetchall()
            return {
                "ok": True,
                "total": total,
                "items": [_row_to_dict(r) for r in rows],
                "limit": limit,
                "offset": offset,
            }
        finally:
            conn.close()


def search_knowledge(q: str, *, limit: int = 20, enabled_only: bool = True) -> List[Dict[str, Any]]:
    """供全局检索 / AI 调用：按特征键与标题打分。"""
    needle = str(q or "").strip()
    if not needle or len(needle) < 2:
        return []
    limit = max(1, min(int(limit or 20), 50))
    low = needle.lower()
    # 去掉常见前缀，便于 hash:xxx / name:xxx
    bare = re.sub(r"^(?:hash|md5|sha1|sha256|name|path|file)\s*:\s*", "", low, flags=re.I).strip()
    bare = bare.strip('"').strip("'")
    with _lock:
        conn = _connect()
        try:
            where = ["1=1"]
            args: List[Any] = []
            if enabled_only:
                where.append("enabled=1")
            like = f"%{bare[:120]}%"
            where.append(
                "(lower(title) LIKE ? OR lower(features) LIKE ? OR lower(tags) LIKE ? "
                "OR lower(summary) LIKE ? OR lower(query_hint) LIKE ? OR lower(body) LIKE ?)"
            )
            args.extend([like, like, like, like, like, like])
            rows = conn.execute(
                f"SELECT * FROM {TABLE} WHERE {' AND '.join(where)} ORDER BY updated_at DESC LIMIT 80",
                args,
            ).fetchall()
        finally:
            conn.close()

    scored: List[tuple] = []
    for row in rows:
        item = _row_to_dict(row)
        blob_feats = " ".join(item.get("features") or []).lower()
        title = str(item.get("title") or "").lower()
        tags = " ".join(item.get("tags") or []).lower()
        summary = str(item.get("summary") or "").lower()
        score = 0
        if bare and bare in blob_feats:
            score += 100
        if bare and bare in title:
            score += 80
        if any(bare == f.lower() for f in (item.get("features") or [])):
            score += 40
        if bare and bare in tags:
            score += 30
        if bare and bare in summary:
            score += 20
        if bare and bare in str(item.get("body") or "").lower():
            score += 8
        if score <= 0:
            continue
        scored.append((score, item))
    scored.sort(key=lambda x: (-x[0], -(x[1].get("id") or 0)))
    out = []
    for score, item in scored[:limit]:
        out.append({
            "id": item["id"],
            "kb_id": item["id"],
            "kind": "knowledge",
            "module": "knowledge",
            "_source": "kb",
            "title": item.get("title") or "",
            "severity": item.get("severity") or "info",
            "category": item.get("kind") or "feature",
            "evidence": item.get("summary") or "",
            "summary": item.get("summary") or "",
            "body": (item.get("body") or "")[:800],
            "features": item.get("features") or [],
            "tags": item.get("tags") or [],
            "modules": item.get("modules") or [],
            "query_hint": item.get("query_hint") or "",
            "score": score,
            "hostname": "",
            "file": "",
            "report_id": "",
        })
    return out


def context_for_ai(needles: List[str], *, limit: int = 6) -> List[Dict[str, Any]]:
    """从多个关键词汇总短知识卡，供 AI prompt。"""
    seen = set()
    cards: List[Dict[str, Any]] = []
    for n in needles or []:
        n = str(n or "").strip()
        if not n:
            continue
        for hit in search_knowledge(n, limit=4):
            kid = hit.get("kb_id") or hit.get("id")
            if kid in seen:
                continue
            seen.add(kid)
            cards.append({
                "id": kid,
                "title": hit.get("title"),
                "kind": hit.get("category"),
                "severity": hit.get("severity"),
                "summary": hit.get("summary") or hit.get("evidence") or "",
                "features": hit.get("features") or [],
                "modules": hit.get("modules") or [],
                "query_hint": hit.get("query_hint") or "",
            })
            if len(cards) >= limit:
                return cards
    return cards


def seed_defaults(*, force: bool = False) -> Dict[str, Any]:
    """写入范文条目（仅空库或 force）。"""
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            n = int(conn.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0])
        finally:
            conn.close()
    if n > 0 and not force:
        return {"ok": True, "seeded": 0, "skipped": True, "existing": n}

    samples = [
        {
            "title": "AppData 随机目录落地 exe（如 comain_ev2c34）",
            "kind": "feature",
            "severity": "high",
            "tags": "落点,持久化,LOLBin",
            "features": "ev2c34.exe, comain_ev2c34, \\AppData\\Roaming\\comain_",
            "summary": "用户 Roaming 下仿系统/随机目录中的 exe，常配合计划任务或 rundll32 拉起，属高优落地特征。",
            "body": (
                "判定要点：\n"
                "1) 路径在 %AppData%\\Roaming\\ 下非厂商目录；\n"
                "2) 文件名短随机或仿系统；\n"
                "3) 常有计划任务 / 启动项指向该路径，或 rundll32 shell32 拉起。\n"
                "建议：威胁溯查该文件名 → 查计划任务/启动项 → 跨主机 locate 同名哈希。"
            ),
            "modules": "threat-trace,task,startup,findings",
            "query_hint": "ev2c34.exe",
            "source": "seed",
        },
        {
            "title": "Microsoft\\Windows\\Application Experience 类 COM 任务",
            "kind": "false_positive",
            "severity": "low",
            "tags": "误报,计划任务,COM",
            "features": "\\Microsoft\\Windows\\Application Experience, PrintJobCleanup, Diagnostics",
            "summary": "大量系统 COM 计划任务会触发宽规则；无异常载荷路径时优先视为基线噪声，勿直接当失陷。",
            "body": (
                "说明：Windows 自带 Application Experience / 打印清理等任务命令常含 rundll32 shell32。\n"
                "仅当任务指向用户目录异常 exe、或命令被篡改时再升级。\n"
                "平台持久化审视已对部分 COM 高频任务降权。"
            ),
            "modules": "task",
            "query_hint": "Application Experience",
            "source": "seed",
        },
        {
            "title": "远控本机 ID / 对端 IP 跨主机聚合",
            "kind": "playbook",
            "severity": "high",
            "tags": "远控,战役,横向",
            "features": "ToDesk, Sunlogin, AnyDesk, client_id, 向日葵",
            "summary": "同一远控本机 ID 或对端 IP 出现在多台主机时，优先走战役聚合，再逐台打开远控模块核对授权。",
            "body": (
                "步骤：\n"
                "1) 战役聚合筛「远控」；\n"
                "2) 点开各主机 remote 页核对配置/会话；\n"
                "3) 结合登录/横向与外联时间窗；\n"
                "4) 无授权记录则按候选入侵扩面。"
            ),
            "modules": "remote,campaign,lateral,network",
            "query_hint": "ToDesk",
            "source": "seed",
        },
        {
            "title": "压缩打包后短时内外传/云同步",
            "kind": "technique",
            "severity": "medium",
            "tags": "外传,压缩,云同步",
            "features": "7z.exe, rar.exe, OneDrive, 百度网盘, zip",
            "summary": "短时间出现压缩工具 + 云同步/大文件外传，需结合进程用户与目标路径，排除运维备份。",
            "body": "建议打开外传模块看工具时间线，并关联前后 ±45 分钟网络与文件落点。",
            "modules": "exfil,network,process",
            "query_hint": "7z.exe",
            "source": "seed",
        },
        {
            "title": "如何写一条有效知识条目",
            "kind": "note",
            "severity": "info",
            "tags": "规范,写作",
            "features": "知识库,写作规范",
            "summary": "有效条目 = 可检索特征键 + 一两句判定 + 建议打开的模块；避免长篇百科。",
            "body": (
                "推荐字段：\n"
                "- 标题：人话场景名\n"
                "- features：文件名/路径片段/哈希/命令关键词（逗号分隔，越具体越好）\n"
                "- summary：≤120 字判定\n"
                "- body：要点列表，可含误报边界\n"
                "- modules：threat-trace / task / startup / remote / exfil 等\n"
                "- query_hint：一键检索用的词\n"
                "不要：整篇威胁情报长文、无特征键的空泛描述、未脱敏的内网敏感原文。"
            ),
            "modules": "",
            "query_hint": "知识库",
            "source": "seed",
        },
    ]
    added = 0
    for s in samples:
        r = create_article(s)
        if r.get("ok"):
            added += 1
    return {"ok": True, "seeded": added, "skipped": False}
