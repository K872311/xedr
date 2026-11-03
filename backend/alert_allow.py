# -*- coding: utf-8 -*-
"""告警加白：所有告警入库前（report_event）统一匹配 agent_whitelist，命中则不再产生告警。

条目语义：kind/value 指定对象（进程、路径、哈希、注册表键……），
可选 agent_id 限定主机、rule 限定告警标题（通配），三者同时满足才抑制。
"""
from __future__ import annotations

import fnmatch
import json
import sqlite3
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

KINDS: Tuple[str, ...] = (
    "title", "process", "path", "hash", "signer", "cmdline", "registry", "domain", "ip",
)

KIND_LABELS = {
    "title": "告警标题", "process": "进程名", "path": "文件路径", "hash": "文件哈希",
    "signer": "签名者", "cmdline": "命令行", "registry": "注册表键", "domain": "域名", "ip": "IP",
}

_FIELD_KEYS: Dict[str, Tuple[str, ...]] = {
    "hash": ("sha256", "hash", "md5", "sha1", "file_sha256", "image_sha256", "process_sha256"),
    "path": ("path", "image", "image_path", "exe", "file_path", "process_path", "target_path",
             "target", "dll", "dll_path", "module_path", "file"),
    "process": ("process_name", "name", "image_name", "process"),
    "signer": ("signer", "publisher"),
    "cmdline": ("command_line", "cmdline", "command"),
    "registry": ("key", "reg_key", "registry_key"),
    "domain": ("domain", "query", "qname"),
    "ip": ("remote_ip", "dst_ip", "ip", "remote", "remote_addr"),
}

_PATH_LIKE = ("path", "registry")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _norm(s: Any) -> str:
    return str(s or "").strip().lower().replace("/", "\\")


def _basename(p: str) -> str:
    p = str(p or "").replace("/", "\\").rstrip("\\")
    return p.rsplit("\\", 1)[-1]


def _strip_port(v: str) -> str:
    v = str(v or "").strip()
    if v.startswith("[") and "]" in v:
        return v[1:v.index("]")]
    if v.count(":") == 1:
        return v.split(":", 1)[0]
    return v


def _flatten(detail: Any) -> Dict[str, Any]:
    if not isinstance(detail, dict):
        return {}
    out: Dict[str, Any] = {}
    for k, v in detail.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if not isinstance(v2, (dict, list)):
                    out.setdefault(str(k2), v2)
        elif not isinstance(v, list):
            out[str(k)] = v
    # 顶层优先于嵌套（evidence 等）
    for k, v in detail.items():
        if not isinstance(v, (dict, list)):
            out[str(k)] = v
    return out


def parse_detail(detail: Any) -> Dict[str, Any]:
    if isinstance(detail, dict):
        return detail
    s = str(detail or "")
    if not s.startswith("{"):
        return {}
    try:
        d = json.loads(s)
    except Exception:
        return {}
    return d if isinstance(d, dict) else {}


def _title_display_tail(title: str) -> str:
    t = str(title or "").strip()
    for sep in ("：", ": ", ":"):
        if sep in t:
            tail = t.split(sep, 1)[1].strip()
            if tail:
                return tail
    return ""


def extract_fields(title: str, detail: Any) -> Dict[str, List[str]]:
    """从告警标题 + 详情抽取可加白的对象值。"""
    flat = _flatten(parse_detail(detail))
    fields: Dict[str, List[str]] = {k: [] for k in KINDS}
    fields["title"] = [str(title or "")]
    for kind, keys in _FIELD_KEYS.items():
        for k in keys:
            v = flat.get(k)
            if v in (None, "") or isinstance(v, bool):
                continue
            sv = str(v).strip()
            if not sv:
                continue
            if kind == "ip":
                sv = _strip_port(sv)
            if kind == "path" and "\\" not in sv and "/" not in sv:
                continue
            fields[kind].append(sv)
    for p in list(fields["path"]):
        b = _basename(p)
        if b.lower().endswith((".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js")):
            fields["process"].append(b)
    vn = str(flat.get("value_name") or "").strip()
    if vn:
        for k in list(fields["registry"]):
            fields["registry"].append(k.rstrip("\\") + "\\" + vn)
    label = str(flat.get("label") or "").strip()
    if label and vn:
        fields["registry"].append(label + "\\" + vn)
    tail = _title_display_tail(title)
    if tail:
        fields["registry"].append(tail)
        if "\\" in tail:
            parent = tail.rsplit("\\", 1)[0]
            if parent:
                fields["registry"].append(parent + "\\")
    for kind in fields:
        seen, uniq = set(), []
        for v in fields[kind]:
            n = _norm(v)
            if n and n not in seen:
                seen.add(n)
                uniq.append(v)
        fields[kind] = uniq
    return fields


def _glob(pattern: str, value: str) -> bool:
    return fnmatch.fnmatchcase(value, pattern.replace("[", "[[]"))


def match_value(kind: str, pattern: str, value: str) -> bool:
    p, v = _norm(pattern), _norm(value)
    if not p or not v:
        return False
    if "*" in p or "?" in p:
        return _glob(p, v)
    if kind in _PATH_LIKE and p.endswith("\\"):
        return v.startswith(p)
    if kind == "cmdline":
        return p in v
    return v == p


def entry_matches(entry: Dict[str, Any], agent_id: str, title: str, fields: Dict[str, List[str]]) -> bool:
    if not int(entry.get("enabled", 1) or 0):
        return False
    scope = str(entry.get("agent_id") or "").strip()
    if scope and scope != str(agent_id or ""):
        return False
    rule = str(entry.get("rule") or "").strip()
    if rule and not match_value("title", rule, title):
        return False
    kind = str(entry.get("kind") or "").strip().lower()
    value = str(entry.get("value") or "")
    if kind not in KINDS:
        return False
    return any(match_value(kind, value, v) for v in fields.get(kind) or [])


def _entries(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    try:
        rows = conn.execute("SELECT * FROM agent_whitelist WHERE enabled=1").fetchall()
    except sqlite3.Error:
        return []
    return [dict(r) for r in rows]


def find_match(conn: sqlite3.Connection, agent_id: str, title: str, detail: Any) -> Optional[Dict[str, Any]]:
    entries = _entries(conn)
    if not entries:
        return None
    fields = extract_fields(title, detail)
    for e in entries:
        if entry_matches(e, agent_id, title, fields):
            return e
    return None


def record_hit(conn: sqlite3.Connection, entry_id: str) -> None:
    try:
        conn.execute(
            "UPDATE agent_whitelist SET hits=COALESCE(hits,0)+1, last_hit_at=? WHERE id=?",
            (_now(), str(entry_id)),
        )
        conn.commit()
    except sqlite3.Error:
        pass


def rule_prefix(title: str) -> str:
    """告警标题去掉具体对象部分，得到「同类告警」通配，如「注册表安全项变更*」。"""
    t = str(title or "").strip()
    for sep in ("：", ": ", ":"):
        if sep in t:
            head = t.split(sep, 1)[0].strip()
            if head:
                return head + "*"
    return t


def candidates(event: Dict[str, Any]) -> List[Dict[str, str]]:
    """告警详情页「加白」可选项：按价值排序，越具体越靠前。"""
    title = str(event.get("title") or "")
    detail_raw = event.get("detail_obj") or event.get("detail")
    fields = extract_fields(title, detail_raw)
    flat = _flatten(parse_detail(detail_raw))
    et = str(flat.get("etype") or "").lower()
    out: List[Dict[str, str]] = []
    order = ("hash", "path", "process", "registry", "cmdline", "signer", "domain", "ip")
    for kind in order:
        for v in fields.get(kind, [])[:3]:
            out.append({"kind": kind, "value": v[:500], "label": KIND_LABELS[kind]})
    out.append({"kind": "title", "value": title[:500], "label": "完全相同的告警"})
    rp = rule_prefix(title)
    if rp and rp != title:
        out.append({"kind": "title", "value": rp[:500], "label": "同类告警（标题通配）"})
    if et in ("registry_set", "registry_delete", "persist_add", "persist_modify", "persist_delete"):
        tail = _title_display_tail(title)
        if tail and not any(x.get("value") == tail for x in out):
            out.insert(0, {
                "kind": "registry",
                "value": tail[:500],
                "label": "监控项（标题中的 FIM/持久化路径，推荐同类）",
            })
        if label := str(flat.get("label") or "").strip():
            prefix = label + "\\"
            if not any(x.get("value") == prefix for x in out):
                out.insert(0, {
                    "kind": "registry",
                    "value": prefix[:500],
                    "label": f"整类监控标签「{label}」（其下所有子项）",
                })
    return out


def default_allow_pick_indices(items: List[Dict[str, str]], event: Dict[str, Any]) -> List[int]:
    """加白对话框默认勾选：注册表/FIM 类优先「标题通配」或监控标签前缀。"""
    if not items:
        return []
    title = str(event.get("title") or "")
    detail_raw = event.get("detail_obj") or event.get("detail")
    flat = _flatten(parse_detail(detail_raw))
    et = str(flat.get("etype") or "").lower()
    if et not in ("registry_set", "registry_delete", "persist_add", "persist_modify", "persist_delete"):
        return [0]
    rp = rule_prefix(title)
    for i, it in enumerate(items):
        if it.get("kind") == "title" and it.get("value") == rp and "通配" in str(it.get("label") or ""):
            return [i]
    for i, it in enumerate(items):
        if it.get("kind") == "registry" and "整类监控标签" in str(it.get("label") or ""):
            return [i]
    return [0]


def apply_all_enabled(conn: sqlite3.Connection, *, limit: int = 5000) -> int:
    """把当前全部启用的加白条目套到未处置告警上。"""
    n = 0
    for entry in _entries(conn):
        n += apply_to_open_events(conn, entry, limit=limit)
    return n


def apply_to_open_events(conn: sqlite3.Connection, entry: Dict[str, Any], *, limit: int = 5000) -> int:
    """新加白条目回溯：把已存在、命中的未处置告警标为「无需处置」。"""
    rows = conn.execute(
        "SELECT id, agent_id, title, detail FROM agent_events WHERE status='open' ORDER BY id DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    ids: List[int] = []
    for r in rows:
        if entry_matches(entry, r["agent_id"], r["title"] or "", extract_fields(r["title"] or "", r["detail"])):
            ids.append(int(r["id"]))
    now = _now()
    for chunk in _chunks(ids, 400):
        conn.execute(
            f"UPDATE agent_events SET status='ignored', updated_at=? WHERE id IN ({','.join('?' * len(chunk))})",
            (now, *chunk),
        )
    if ids:
        conn.commit()
    return len(ids)


def _chunks(seq: List[int], n: int) -> Iterable[List[int]]:
    for i in range(0, len(seq), n):
        yield seq[i:i + n]
