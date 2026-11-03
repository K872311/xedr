"""检索查询形态 + 通配符。

默认 smart：
- 含 * / ? → 通配（glob）
- 短路径段词（Temp / AppData）→ 按路径分隔符匹配
- 其余 → 子串包含

显式 match=contains|prefix|exact|segment|glob 可覆盖。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

MODE_CONTAINS = "contains"
MODE_PREFIX = "prefix"
MODE_EXACT = "exact"
MODE_SEGMENT = "segment"
MODE_GLOB = "glob"

TRIGRAM_MIN = 3
#: LIKE ESCAPE 字符（避开路径反斜杠）
LIKE_ESCAPE = "#"

_RE_HEX = re.compile(r"^[0-9a-fA-F]+$")
_HASH_COLS = {32: "md5", 40: "sha1", 64: "sha256"}
_PATH_SEG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,40}$")
_PATH_SEG_WRAP_RE = re.compile(r"^[\\/]+(.+?)[\\/]*$")


@dataclass(frozen=True)
class QueryPlan:
    mode: str
    term: str
    raw: str
    label: str

    @property
    def hex_term(self) -> bool:
        return bool(self.term) and bool(_RE_HEX.match(self.term))

    @property
    def full_hash(self) -> bool:
        return self.hex_term and len(self.term) in _HASH_COLS

    @property
    def hash_col(self) -> str:
        return _HASH_COLS.get(len(self.term), "") if self.hex_term else ""

    @property
    def trigram_ok(self) -> bool:
        # 通配串含 % 时 trigram 价值有限，仍可尝试
        core = self.term.replace("*", "").replace("?", "").replace("%", "").replace("_", "")
        return len(core) >= TRIGRAM_MIN


def has_glob_meta(q: str) -> bool:
    return "*" in (q or "") or "?" in (q or "")


def looks_like_literal_glob_chars(q: str) -> bool:
    """cron / shell 行里的 * 多为字面量，不应当路径通配。

    典型：``30 3 * * 0 root test -e /run/systemd/...``
    路径通配仍识别：``*.exe``、``Temp\\*``、``foo*bar``（粘连通配）。
    """
    s = (q or "").strip()
    if not s or not has_glob_meta(s):
        return False
    # 明确的文件/路径通配
    if re.search(r"\*\.[A-Za-z0-9]{1,12}\b", s):
        return False
    if re.search(r"[\\/]\*|\*[\\/]", s):
        return False
    if re.search(r"[A-Za-z0-9]\*[A-Za-z0-9]", s):
        return False
    # cron：数字 + 字段 + 独立 *
    if re.search(r"(?:^|\s)\d{1,2}\s+\S+\s+\*(?:\s+\*)+", s):
        return True
    # 多个被空白隔开的孤立 *
    if len(re.findall(r"(?:^|\s)\*(?=\s|$)", s)) >= 2:
        return True
    # shell：含 || 或短选项，且带 *
    if "*" in s and ("||" in s or re.search(r"(?:^|\s)-[a-z]\b", s)):
        return True
    return False


def looks_like_path_segment(q: str) -> bool:
    s = (q or "").strip().strip('"').strip("'")
    if not s or len(s) < 2:
        return False
    m = _PATH_SEG_WRAP_RE.match(s)
    if m:
        s = m.group(1).strip()
    if not s or "\\" in s or "/" in s or "." in s or has_glob_meta(s) or "%" in s:
        return False
    return bool(_PATH_SEG_RE.match(s))


def normalize_path_segment(q: str) -> str:
    s = (q or "").strip().strip('"').strip("'")
    m = _PATH_SEG_WRAP_RE.match(s)
    if m:
        s = m.group(1).strip()
    return s


def glob_to_like(pattern: str, *, wrap: bool = True, escape: str = LIKE_ESCAPE) -> str:
    """用户 glob → SQL LIKE 串（配合 ESCAPE）。

    * → %（任意长度）
    ? → _（单字符）
    字面 % / _ / escape 会转义
    路径 / 与 \\ 统一成 \\
    wrap=True 且首尾无 * 时两侧加 %，便于 Temp\\*.exe 命中绝对路径
    """
    raw = (pattern or "").strip()
    if not raw:
        return "%"
    s = raw.replace("/", "\\")
    out: List[str] = []
    for c in s:
        if c == "*":
            out.append("%")
        elif c == "?":
            out.append("_")
        elif c in ("%", "_", escape):
            out.append(escape + c)
        else:
            out.append(c)
    like = "".join(out)
    if wrap:
        if not raw.startswith("*") and not like.startswith("%"):
            like = "%" + like
        if not raw.endswith("*") and not like.endswith("%"):
            like = like + "%"
    return like


def glob_to_regex(pattern: str, *, search: bool = True) -> re.Pattern[str]:
    """用户 glob → 正则（结果侧过滤 / 高亮）。"""
    s = (pattern or "").replace("/", "\\")
    parts: List[str] = []
    for c in s:
        if c == "*":
            parts.append(".*")
        elif c == "?":
            parts.append(".")
        else:
            parts.append(re.escape(c))
    body = "".join(parts)
    if search:
        return re.compile(body, re.I)
    return re.compile(f"^{body}$", re.I)


def text_matches_query(text: str, q: str) -> bool:
    """内存侧匹配：通配走 glob，cron/shell 字面 * 走子串，否则子串。"""
    blob = (text or "")
    needle = (q or "").strip()
    if not needle:
        return True
    if has_glob_meta(needle):
        if looks_like_literal_glob_chars(needle):
            return needle.lower() in blob.lower()
        return bool(glob_to_regex(needle).search(blob.replace("/", "\\")))
    return needle.lower() in blob.lower()


def classify(q: str, mode: str = "smart") -> QueryPlan:
    raw = (q or "").strip()
    if not raw:
        return QueryPlan(MODE_CONTAINS, "", "", "空")

    forced = (mode or "smart").strip().lower()
    if forced == "exact":
        return QueryPlan(MODE_EXACT, raw, raw, "精确匹配")
    if forced == "prefix":
        return QueryPlan(MODE_PREFIX, raw, raw, "前缀匹配")
    if forced == "segment":
        seg = normalize_path_segment(raw)
        return QueryPlan(MODE_SEGMENT, seg or raw, raw, "路径段匹配")
    if forced == "glob":
        return QueryPlan(MODE_GLOB, raw, raw, "通配匹配")
    if forced == "contains":
        # contains：路径通配仍走 glob；cron/shell 字面 * 保持包含匹配
        if has_glob_meta(raw) and not looks_like_literal_glob_chars(raw):
            return QueryPlan(MODE_GLOB, raw, raw, "通配匹配")
        return QueryPlan(MODE_CONTAINS, raw, raw, "包含匹配")

    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        inner = raw[1:-1].strip()
        if inner:
            return QueryPlan(MODE_EXACT, inner, raw, "精确匹配")

    if has_glob_meta(raw):
        if looks_like_literal_glob_chars(raw):
            return QueryPlan(MODE_CONTAINS, raw, raw, "包含匹配")
        return QueryPlan(MODE_GLOB, raw, raw, "通配匹配")

    if looks_like_path_segment(raw):
        seg = normalize_path_segment(raw)
        return QueryPlan(MODE_SEGMENT, seg, raw, "路径段匹配")

    return QueryPlan(MODE_CONTAINS, raw, raw, "包含匹配")


def _like_contains(term: str) -> str:
    return f"%{term}%"


def _like_sql(col_expr: str, pattern: str, *, escape: str = LIKE_ESCAPE) -> Tuple[str, List[Any]]:
    return f"{col_expr} LIKE ? ESCAPE '{escape}'", [pattern]


def _segment_path_preds(col: str, term: str) -> Tuple[str, List[Any]]:
    t = (term or "").lower()
    norm = f"lower(replace({col}, '/', '\\'))"
    return (
        f"({norm} LIKE ? OR {norm} LIKE ? OR {norm} LIKE ? "
        f"OR lower(name) = ? OR lower(name) LIKE ?)",
        [
            f"%\\{t}\\%",
            f"%\\{t}.%",
            f"%\\{t}",
            t,
            f"{t}.%",
        ],
    )


def _glob_path_preds(col: str, term: str) -> Tuple[str, List[Any]]:
    like = glob_to_like(term).lower()
    esc = LIKE_ESCAPE
    norm = f"lower(replace({col}, '/', '\\'))"
    return (
        f"({norm} LIKE ? ESCAPE '{esc}' OR lower(name) LIKE ? ESCAPE '{esc}')",
        [like, like],
    )


def files_where(plan: QueryPlan) -> Tuple[str, List[Any]]:
    t = plan.term
    if plan.mode == MODE_EXACT:
        return "(full_path = ? COLLATE NOCASE OR name = ? COLLATE NOCASE)", [t, t]
    if plan.mode == MODE_PREFIX:
        return "(full_path LIKE ? OR name LIKE ?)", [f"{t}%", f"{t}%"]
    if plan.mode == MODE_SEGMENT:
        return _segment_path_preds("full_path", t)
    if plan.mode == MODE_GLOB:
        return _glob_path_preds("full_path", t)
    like = _like_contains(t)
    if plan.full_hash:
        col = plan.hash_col
        return f"(full_path LIKE ? OR {col} = ?)", [like, t.lower()]
    if plan.hex_term:
        return (
            "(full_path LIKE ? OR md5 LIKE ? OR sha1 LIKE ? OR sha256 LIKE ?)",
            [like, like, like, like],
        )
    return "full_path LIKE ?", [like]


def files_hash_where(plan: QueryPlan) -> Tuple[str, List[Any]]:
    if plan.mode != MODE_CONTAINS or not plan.hex_term:
        return "", []
    if plan.full_hash:
        return f"{plan.hash_col} = ?", [plan.term.lower()]
    like = _like_contains(plan.term)
    return "(md5 LIKE ? OR sha1 LIKE ? OR sha256 LIKE ?)", [like, like, like]


def eventlog_where(plan: QueryPlan) -> Tuple[str, List[Any]]:
    t = plan.term
    if plan.mode == MODE_EXACT:
        return (
            "(channel = ? COLLATE NOCASE OR provider = ? COLLATE NOCASE "
            "OR CAST(event_id AS TEXT) = ?)",
            [t, t, t],
        )
    if plan.mode == MODE_PREFIX:
        p = f"{t}%"
        return "(message LIKE ? OR channel LIKE ? OR provider LIKE ?)", [p, p, p]
    if plan.mode == MODE_SEGMENT:
        tl = t.lower()
        return (
            "(lower(replace(IFNULL(message,''), '/', '\\')) LIKE ? "
            "OR lower(replace(IFNULL(message,''), '/', '\\')) LIKE ? "
            "OR lower(IFNULL(message,'')) LIKE ? "
            "OR lower(IFNULL(message,'')) LIKE ?)",
            [
                f"%\\{tl}\\%",
                f"%\\{tl}.%",
                f"%{tl}目录%",
                f"%{tl}下%",
            ],
        )
    if plan.mode == MODE_GLOB:
        like = glob_to_like(t).lower()
        esc = LIKE_ESCAPE
        return (
            f"(lower(replace(IFNULL(message,''), '/', '\\')) LIKE ? ESCAPE '{esc}' "
            f"OR lower(IFNULL(channel,'')) LIKE ? ESCAPE '{esc}' "
            f"OR CAST(event_id AS TEXT) LIKE ? ESCAPE '{esc}')",
            [like, like, like],
        )
    like = _like_contains(t)
    return (
        "(message LIKE ? OR channel LIKE ? OR CAST(event_id AS TEXT) LIKE ?)",
        [like, like, like],
    )


def fts_like_pattern(plan: QueryPlan) -> str:
    if not plan.trigram_ok:
        return ""
    if plan.mode == MODE_GLOB:
        # FTS 宽召回用去通配后的最长字面片段；精过滤在 WHERE
        lit = re.split(r"[*?]+", plan.term)
        lit = [x for x in lit if len(x) >= TRIGRAM_MIN]
        if not lit:
            return ""
        lit.sort(key=len, reverse=True)
        return _like_contains(lit[0].replace("/", "\\"))
    if plan.mode == MODE_SEGMENT:
        return _like_contains(plan.term)
    if plan.mode != MODE_CONTAINS:
        return ""
    return _like_contains(plan.term)


def path_segment_hit(text: str, term: str) -> bool:
    t = (term or "").strip().lower()
    if not t:
        return False
    b = (text or "").lower().replace("/", "\\")
    if f"\\{t}\\" in b or f"\\{t}." in b or b.endswith(f"\\{t}"):
        return True
    if f"{t}目录" in b or f"{t}下" in b:
        return True
    if re.search(rf"(?<![a-z0-9_]){re.escape(t)}(?![a-z0-9_])", b):
        return True
    base = b.rstrip("\\").rsplit("\\", 1)[-1]
    if base == t or base.startswith(t + "."):
        return True
    return False


def needle_as_like(q: str) -> Tuple[str, Optional[str]]:
    """任意入口：把用户输入变成 (LIKE串, ESCAPE或None)。"""
    plan = classify(q, "smart")
    if plan.mode == MODE_GLOB:
        return glob_to_like(plan.term).lower(), LIKE_ESCAPE
    if plan.mode == MODE_SEGMENT:
        # 段模式不走单 LIKE；调用方应走 files_where
        return f"%\\{plan.term.lower()}\\%", None
    if plan.mode == MODE_PREFIX:
        return f"{plan.term.lower()}%", None
    if plan.mode == MODE_EXACT:
        return plan.term.lower(), None
    return f"%{plan.term.lower()}%", None
