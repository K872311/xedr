"""AI 研判证据引用：送入证据编号 E1..En，回复须以 [E编号] 标注依据，引用不存在的编号即视为编造。"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

REF_RE = re.compile(r"\[\s*(E\d{1,4}(?:\s*[,，、]\s*E\d{1,4})*)\s*\]")
_ID_RE = re.compile(r"E\d{1,4}")
# 「1) 风险等级」等编号行是固定分节标题，不算条目
_ITEM_LINE_RE = re.compile(r"^\s*(?:[-*+]\s+|\|)")
_TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}")

CITATION_RULE = (
    "\n证据引用规则（必须遵守）：输入中每条证据都带 ref 编号（如 E3）。"
    "每个可疑条目、风险点或表格行末尾必须用方括号标注依据，例如 [E3] 或 [E3, E7]；"
    "只能引用输入里真实存在的 ref，禁止编造编号；没有对应证据的结论不要写。"
)

MAX_REF_FIELDS = ("title", "name", "evidence", "detail", "path", "command_line", "command", "rule_id")


def attach_refs(items: Sequence[Any], start: int = 1) -> Tuple[List[Any], Dict[str, Dict[str, Any]]]:
    """给证据加 ref；返回 (带 ref 的副本, ref → 摘要)。非 dict 条目包装为 {ref, text}。"""
    out: List[Any] = []
    index: Dict[str, Dict[str, Any]] = {}
    n = start
    for it in items or []:
        ref = f"E{n}"
        n += 1
        if isinstance(it, dict):
            row = {"ref": ref, **{k: v for k, v in it.items() if k != "ref"}}
        else:
            row = {"ref": ref, "text": str(it)[:300]}
        out.append(row)
        brief = {k: row[k] for k in MAX_REF_FIELDS if row.get(k) not in (None, "")}
        if not brief and row.get("text"):
            brief = {"text": row["text"]}
        index[ref] = {k: (str(v)[:240] if isinstance(v, str) else v) for k, v in brief.items()}
    return out, index


def cited_ids(text: str) -> List[str]:
    seen: List[str] = []
    for m in REF_RE.finditer(text or ""):
        for rid in _ID_RE.findall(m.group(1)):
            if rid not in seen:
                seen.append(rid)
    return seen


def _is_item_line(line: str) -> bool:
    if not _ITEM_LINE_RE.match(line) or _TABLE_SEP_RE.match(line):
        return False
    stripped = line.strip().strip("|").strip()
    if not stripped:
        return False
    # 表头行：名称|位置/路径|原因
    return not re.fullmatch(r"[\s|]*(?:名称|条目|项)\s*\|.*(?:原因|理由).*", line.strip())


def verify(text: str, valid: Sequence[str]) -> Dict[str, Any]:
    valid_set = set(valid)
    cited = cited_ids(text)
    invalid = [r for r in cited if r not in valid_set]
    uncited = sum(1 for ln in (text or "").splitlines() if _is_item_line(ln) and not REF_RE.search(ln))
    return {"cited": [r for r in cited if r in valid_set], "invalid": invalid, "uncited_lines": uncited}


def drop_invalid_lines(text: str, invalid: Sequence[str]) -> Tuple[str, int]:
    """删除引用了不存在编号的条目行；正文段落里的假编号只去掉标注。"""
    bad = set(invalid)
    kept: List[str] = []
    dropped = 0
    for ln in (text or "").splitlines():
        refs = set(_ID_RE.findall(" ".join(m.group(1) for m in REF_RE.finditer(ln))))
        if refs & bad:
            if _is_item_line(ln):
                dropped += 1
                continue

            def _strip(m: re.Match) -> str:
                ok = [r for r in _ID_RE.findall(m.group(1)) if r not in bad]
                return f"[{', '.join(ok)}]" if ok else ""

            ln = REF_RE.sub(_strip, ln)
        kept.append(ln)
    return "\n".join(kept), dropped


def cited_completion(
    send: Callable[[List[Dict[str, str]]], str],
    messages: List[Dict[str, str]],
    valid: Sequence[str],
) -> Tuple[str, Dict[str, Any]]:
    """请求一次；有编造编号则带错误说明重试一次；仍有则删除对应条目。"""
    text = send(messages)
    if not text:
        return text, {"status": "empty", "attempts": 1}
    check = verify(text, valid)
    attempts = 1
    if check["invalid"]:
        retry = messages + [
            {"role": "assistant", "content": text},
            {
                "role": "user",
                "content": (
                    f"上次回复引用了不存在的证据编号：{', '.join(check['invalid'])}。"
                    f"可用编号仅为 E1–E{len(valid)}。请按原格式完整重写，"
                    "删除没有真实依据的条目，只引用输入中存在的 ref。"
                ),
            },
        ]
        attempts = 2
        again = send(retry)
        if again:
            text = again
            check = verify(text, valid)
    status = "ok" if attempts == 1 else "repaired"
    dropped = 0
    if check["invalid"]:
        text, dropped = drop_invalid_lines(text, check["invalid"])
        status = "filtered"
    elif not check["cited"]:
        status = "uncited"
    return text, {
        "status": status,
        "attempts": attempts,
        "cited": check["cited"],
        "invalid": check["invalid"],
        "dropped_lines": dropped,
        "uncited_lines": check["uncited_lines"],
        "evidence_total": len(valid),
    }


def citation_note(info: Optional[Dict[str, Any]]) -> str:
    if not info:
        return ""
    st = info.get("status")
    if st == "ok":
        return f"证据引用校验通过：引用 {len(info.get('cited') or [])}/{info.get('evidence_total', 0)} 条证据。"
    if st == "repaired":
        return "首次回复引用了不存在的证据编号，已要求模型重写并通过校验。"
    if st == "filtered":
        return (
            f"模型重写后仍引用不存在的编号（{', '.join(info.get('invalid') or [])}），"
            f"已删除 {info.get('dropped_lines', 0)} 条无依据条目。"
        )
    if st == "uncited":
        return "模型回复未标注证据编号，结论无法逐条对应原始证据，请谨慎参考。"
    return ""
