"""USN 短时写/重命名聚类 → 勒索软件候选。"""
from __future__ import annotations

import csv
import io
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import Finding

# USN reason 位（与 fsutil / NTFS 一致）
_REASON_WRITE = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000100  # overwrite/extend/trunc/create
_REASON_RENAME = 0x00001000 | 0x00002000  # old/new name

_WRITE_WORDS = (
    "data overwrite", "data extend", "data truncation", "file create",
    "basic info change", "close",
    "数据覆盖", "数据扩展", "数据截断", "文件创建",
)
_RENAME_WORDS = (
    "rename new name", "rename old name", "renamenewname", "renameoldname",
    "重命名", "新名称", "旧名称",
)
_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
)


def _parse_reason_flags(raw: str) -> Tuple[bool, bool]:
    """返回 (is_write, is_rename)。"""
    s = (raw or "").strip()
    if not s:
        return False, False
    low = s.lower().replace("_", " ")
    flags = 0
    # 0x... 或 数字，或 0x1|0x2 组合
    for part in re.split(r"[|,;\s]+", s):
        part = part.strip()
        if not part:
            continue
        try:
            if part.lower().startswith("0x"):
                flags |= int(part, 16)
            elif part.isdigit():
                flags |= int(part)
        except ValueError:
            pass
    is_write = bool(flags & _REASON_WRITE)
    is_rename = bool(flags & _REASON_RENAME)
    if not (is_write or is_rename):
        if any(w in low for w in _RENAME_WORDS):
            is_rename = True
        if any(w in low for w in _WRITE_WORDS) and "rename" not in low and "重命名" not in low:
            is_write = True
        # Close  alone 不算写；若同时有 overwrite 已由 flags 覆盖
        if "close" in low and not is_write and not is_rename:
            pass
    return is_write, is_rename


def _parse_ts(raw: str) -> Optional[float]:
    s = (raw or "").strip().strip('"').replace("Z", "")
    if not s:
        return None
    # 纯数字 epoch
    try:
        if re.fullmatch(r"\d+(\.\d+)?", s):
            v = float(s)
            if v > 1e12:  # ms
                v /= 1000.0
            if v > 1e9:
                return v
    except ValueError:
        pass
    # 去掉时区尾巴
    s2 = re.sub(r"[+-]\d{2}:?\d{2}$", "", s).strip()
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s2[:26], fmt).timestamp()
        except ValueError:
            continue
    # 宽松：抓 YYYY-mm-dd HH:MM:SS
    m = re.search(r"(\d{4}[-/]\d{1,2}[-/]\d{1,2})[ T](\d{1,2}:\d{2}:\d{2})", s)
    if m:
        try:
            return datetime.strptime(f"{m.group(1)} {m.group(2)}".replace("/", "-"), "%Y-%m-%d %H:%M:%S").timestamp()
        except ValueError:
            pass
    return None


def parse_usn_csv_text(text: str) -> List[Dict[str, Any]]:
    """解析 fsutil usn csv 或摘要文本，产出 [{ts, name, reason, is_write, is_rename}, ...]。"""
    if not text or not str(text).strip():
        return []
    lines = str(text).replace("\r\n", "\n").replace("\r", "\n").split("\n")
    # 跳过摘要前缀行
    body_lines = [ln for ln in lines if ln.strip() and not ln.strip().startswith("[USN") and not ln.strip().startswith("...")]
    if not body_lines:
        return []

    # 尝试 CSV
    sample = "\n".join(body_lines[:5])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;")
    except Exception:
        dialect = csv.excel

    reader = csv.reader(io.StringIO("\n".join(body_lines)), dialect)
    rows = list(reader)
    if not rows:
        return []

    header = [c.strip().lower() for c in rows[0]]
    has_header = any(
        k in " ".join(header)
        for k in ("usn", "reason", "file name", "time", "文件", "原因", "时间")
    )
    data_rows = rows[1:] if has_header else rows

    def _col(*names: str) -> int:
        for i, h in enumerate(header if has_header else []):
            for n in names:
                if n in h:
                    return i
        return -1

    i_reason = _col("reason", "原因")
    i_time = _col("time", "时间", "timestamp")
    i_name = _col("file name", "filename", "文件名", "name")
    # 无表头时按常见 fsutil 列序：Usn, File name, ..., Reason, Time stamp, ...
    if not has_header:
        i_name, i_reason, i_time = 1, 3, 4

    out: List[Dict[str, Any]] = []
    for r in data_rows:
        if not r or len(r) < 2:
            continue
        reason = r[i_reason] if 0 <= i_reason < len(r) else ""
        ts_raw = r[i_time] if 0 <= i_time < len(r) else ""
        name = r[i_name] if 0 <= i_name < len(r) else ""
        # 兜底：整行搜时间与 reason 关键字
        if not ts_raw:
            for cell in r:
                if _parse_ts(cell) is not None:
                    ts_raw = cell
                    break
        if not reason:
            for cell in r:
                iw, irn = _parse_reason_flags(cell)
                if iw or irn:
                    reason = cell
                    break
        ts = _parse_ts(ts_raw)
        if ts is None:
            continue
        is_write, is_rename = _parse_reason_flags(reason)
        if not is_write and not is_rename:
            continue
        out.append({
            "ts": ts,
            "name": (name or "").strip()[:260],
            "reason": (reason or "").strip()[:120],
            "is_write": is_write,
            "is_rename": is_rename,
        })
    return out


def load_usn_text_from_report(report: Dict[str, Any]) -> Tuple[str, str]:
    """返回 (text, pack_file_hint)。"""
    blob = report.get("usn_journal") or ""
    if isinstance(blob, str) and blob.strip():
        return blob, "usn_journal"

    rid = str(report.get("_rid") or report.get("_report_file") or "").strip()
    if not rid:
        return "", ""
    try:
        from .. import paths as P
        folder = P.report_dir(rid, create=False)
    except Exception:
        folder = None
    if not folder or not Path(folder).is_dir():
        return "", ""
    folder = Path(folder)
    candidates: List[Path] = []
    candidates.extend(sorted(folder.glob("usn_*.csv")))
    pack = folder / "pack"
    if pack.is_dir():
        candidates.extend(sorted(pack.glob("usn*.csv")))
        candidates.extend(sorted(pack.glob("*usn*.csv")))
    for p in candidates:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            if text.strip():
                return text, p.name
        except OSError:
            continue
    # 主报告 JSON 旁路字段
    return "", ""


def find_dense_windows(
    events: List[Dict[str, Any]],
    *,
    window_seconds: int = 120,
    min_ops: int = 40,
) -> List[Dict[str, Any]]:
    """滑动窗：按事件时间排序，找 ops 达标的密集窗口。"""
    if not events:
        return []
    evs = sorted(events, key=lambda e: e["ts"])
    win = max(5, int(window_seconds or 120))
    min_ops = max(5, int(min_ops or 40))
    n = len(evs)
    best: List[Dict[str, Any]] = []
    j = 0
    for i in range(n):
        if j < i:
            j = i
        while j + 1 < n and evs[j + 1]["ts"] - evs[i]["ts"] <= win:
            j += 1
        slice_ev = evs[i : j + 1]
        ops = len(slice_ev)
        if ops < min_ops:
            continue
        writes = sum(1 for e in slice_ev if e.get("is_write"))
        renames = sum(1 for e in slice_ev if e.get("is_rename"))
        names = [e.get("name") or "" for e in slice_ev if e.get("name")]
        # 扩展名聚类（重命名后缀）
        ext_counts: Dict[str, int] = {}
        for nm in names:
            if "." in nm:
                ext = nm.rsplit(".", 1)[-1].lower()
                if 1 <= len(ext) <= 16 and ext.isalnum():
                    ext_counts[ext] = ext_counts.get(ext, 0) + 1
        top_ext = ""
        top_ext_n = 0
        if ext_counts:
            top_ext, top_ext_n = max(ext_counts.items(), key=lambda kv: kv[1])
        best.append({
            "t0": evs[i]["ts"],
            "t1": evs[j]["ts"],
            "ops": ops,
            "writes": writes,
            "renames": renames,
            "top_ext": top_ext,
            "top_ext_n": top_ext_n,
            "sample_names": names[:12],
        })
    # 去重叠：按 ops 降序，保留不严重重叠的窗
    best.sort(key=lambda w: (-w["ops"], -w["renames"], w["t0"]))
    picked: List[Dict[str, Any]] = []
    for w in best:
        if any(abs(w["t0"] - p["t0"]) < win * 0.5 for p in picked):
            continue
        picked.append(w)
    return picked


def _fmt_ts(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(int(ts))


def run_host_usn_time_cluster(
    report: Dict[str, Any],
    cfg: Dict[str, Any],
) -> List[Finding]:
    if not cfg.get("enabled", True):
        return []
    window_seconds = int(cfg.get("window_seconds") or 120)
    min_ops = int(cfg.get("min_ops") or 40)
    min_renames_high = int(cfg.get("min_renames_high") or 25)
    min_writes_for_high = int(cfg.get("min_writes_for_high") or 10)
    max_findings = max(1, min(int(cfg.get("max_findings") or 3), 20))
    sev_high = str(cfg.get("severity") or "high")
    sev_med = str(cfg.get("severity_medium") or "medium")
    category = str(cfg.get("category") or "磁盘变更")
    host = str(report.get("hostname") or "").strip()

    t0 = time.perf_counter()
    text, pack_hint = load_usn_text_from_report(report)
    events = parse_usn_csv_text(text)
    if not events:
        print(f"[operators] host-usn-time-cluster events=0 ms={int((time.perf_counter()-t0)*1000)}")
        return []

    windows = find_dense_windows(events, window_seconds=window_seconds, min_ops=min_ops)
    findings: List[Finding] = []
    for w in windows[:max_findings]:
        high = (
            w["renames"] >= min_renames_high
            and w["writes"] >= min_writes_for_high
        ) or (
            w["renames"] >= min_renames_high
            and w.get("top_ext_n", 0) >= max(10, min_renames_high // 2)
        )
        sev = sev_high if high else sev_med
        span = max(1, int(w["t1"] - w["t0"]))
        ext_note = ""
        if w.get("top_ext") and w.get("top_ext_n", 0) >= 5:
            ext_note = f" · 高频后缀 .{w['top_ext']}×{w['top_ext_n']}"
        title = f"USN 短时大量写/重命名（勒索软件候选，{w['ops']} 次/{span}s）"
        evidence = (
            f"主机={host or 'unknown'} · 窗口={_fmt_ts(w['t0'])} ~ {_fmt_ts(w['t1'])} "
            f"（{span}s / 配置窗 {window_seconds}s）\n"
            f"操作总数={w['ops']} · 写/创建≈{w['writes']} · 重命名≈{w['renames']}{ext_note}\n"
            f"数据源={pack_hint or 'usn_journal'} · 判定=候选（需人工复核，非确认勒索）\n"
            f"样本文件名：\n" + "\n".join(f"  - {n}" for n in (w.get("sample_names") or [])[:10])
        )
        sample_path = ""
        for n in w.get("sample_names") or []:
            if n and ("\\" in n or "/" in n):
                sample_path = n
                break
        findings.append(Finding(
            category=category,
            severity=sev,
            title=title,
            evidence=evidence[:2000],
            source="usn_journal",
            rule_id=str(cfg.get("id") or "host-usn-time-cluster"),
            matcher="operator",
            extra={
                "operator": "host-usn-time-cluster",
                "ops": w["ops"],
                "writes": w["writes"],
                "renames": w["renames"],
                "window_seconds": window_seconds,
                "span_seconds": span,
                "t0": _fmt_ts(w["t0"]),
                "t1": _fmt_ts(w["t1"]),
                "top_ext": w.get("top_ext") or "",
                "path": sample_path,
                "pack": pack_hint or "usn_journal",
                "pack_file": pack_hint or "usn_journal",
                "candidate": True,
                "hostname": host,
            },
            anchor={
                "kind": "usn_cluster",
                "host": host,
                "source": "usn_journal",
                "pack_file": pack_hint or "usn_journal",
                "path": sample_path,
                "line": f"{_fmt_ts(w['t0'])}~{_fmt_ts(w['t1'])}",
                "module": "disk",
            },
        ))

    ms = int((time.perf_counter() - t0) * 1000)
    print(f"[operators] host-usn-time-cluster findings={len(findings)} events={len(events)} ms={ms}")
    return findings
