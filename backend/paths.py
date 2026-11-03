"""每份报告对应 reports/<stem>/ 目录。

目录内：
  report.json   — 采集原文
  result.json   — 精简分析结果
  analysis.db   — 前端主读库

逻辑 ID 仍为 report_<stem>.json，兼容前端与索引。
"""
from __future__ import annotations
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional, Set, Tuple

from . import config

RESERVED = {"dbs"}
# 采集目录名常带时区 +08-00
_SAFE_STEM = re.compile(r"^[\w.+\-]{1,180}$", re.UNICODE)


def normalize_report_fn(raw: str) -> str:
    """修正 URL/表单解码把时区 + 变成空格：..._10-05-36 08-00 → ..._10-05-36+08-00"""
    s = str(raw or "").strip()
    if not s:
        return s
    return re.sub(
        r"(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}) (\d{2}-\d{2})",
        r"\1+\2",
        s,
        count=1,
    )


def report_stem(report_file: str) -> str:
    name = Path(normalize_report_fn(report_file)).name
    for prefix in ("report_", "result_", "collect_"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    if name.endswith(".json"):
        name = name[:-5]
    if name.endswith(".db"):
        name = name[:-3]
    if name == "analysis":
        # reports/<stem>/analysis.db → 调用方应传目录名
        pass
    return name


def report_id(report_file: str) -> str:
    return f"report_{report_stem(report_file)}.json"


def normalize_collect_ts(raw: Any = None) -> str:
    """采集时间 → 报告 stem 片段（与入库逻辑一致）。"""
    raw_ts = str(raw or datetime.now().isoformat())
    ts = re.sub(r"[^0-9A-Za-z_.+\-]", "-", raw_ts.replace("T", "_"))[:80].strip(".-_")
    if not ts:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return ts


def report_storage_exists(report_file: str) -> bool:
    """是否已有该逻辑 ID 的报告落盘。"""
    if resolve_report_json(report_file):
        return True
    stem = report_stem(report_file)
    folder = config.REPORTS_DIR / stem
    return (folder / "report.json").is_file()


def allocate_report_rid(
    hostname: str,
    collect_time: Any = None,
    *,
    seen: Optional[Set[str]] = None,
) -> str:
    """生成报告逻辑 ID：hostname+采集时间；冲突时自动 _2、_3…，同主机名多份均保留。"""
    host = str(hostname or "unknown").strip() or "unknown"
    ts = normalize_collect_ts(collect_time)
    base = f"{host}_{ts}"
    seen = seen if seen is not None else set()
    for n in range(1, 10000):
        stem = base if n == 1 else f"{base}_{n}"
        fname = f"report_{stem}.json"
        try:
            rid = safe_report_id(fname)
        except ValueError:
            safe_host = re.sub(r"[^0-9A-Za-z_.+\-]", "-", host)[:64].strip(".-_") or "unknown"
            stem2 = f"{safe_host}_{ts}" if n == 1 else f"{safe_host}_{ts}_{n}"
            rid = safe_report_id(f"report_{stem2}.json")
        if rid not in seen and not report_storage_exists(rid):
            seen.add(rid)
            return rid
    raise ValueError(f"同主机名/时间的报告过多: {host}")


def safe_report_id(report_file: str) -> str:
    """删除/定位用：只允许 basename 形态的逻辑 ID，拒绝路径穿越与模糊串。"""
    raw = str(report_file or "").strip()
    if not raw or len(raw) > 240:
        raise ValueError("非法报告标识")
    if any(c in raw for c in "/\\:\0<>|*?") or ".." in raw:
        raise ValueError("非法报告标识")
    name = Path(raw).name
    if name != raw.replace("\\", "/").rsplit("/", 1)[-1]:
        raise ValueError("非法报告标识")
    if not name or name in {".", ".."} or name.lower() in RESERVED:
        raise ValueError("非法报告标识")
    rid = report_id(name)
    stem = report_stem(rid)
    if not stem or stem in {".", ".."} or stem.lower() in RESERVED:
        raise ValueError("非法报告标识")
    if not _SAFE_STEM.match(stem):
        raise ValueError("非法报告标识")
    return rid


def safe_rmtree(path: Path) -> bool:
    """只允许删除 REPORTS_DIR 内的子目录，解析 .. 后再比。"""
    if not path.exists():
        return False
    try:
        root = config.REPORTS_DIR.resolve()
        target = path.resolve()
        target.relative_to(root)
        if target == root:
            return False
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=False)
        elif target.is_file():
            target.unlink()
        else:
            return False
        return True
    except Exception as e:
        print(f"[paths] safe_rmtree {path}: {e}")
        return False


def report_dir(report_file: str, create: bool = False) -> Path:
    d = config.REPORTS_DIR / report_stem(report_file)
    if create:
        d.mkdir(parents=True, exist_ok=True)
    return d


def report_json_path(report_file: str, create_dir: bool = False) -> Path:
    """写入目标路径：reports/<stem>/report.json"""
    return report_dir(report_file, create=create_dir) / "report.json"


def result_json_path(report_file: str, create_dir: bool = False) -> Path:
    return report_dir(report_file, create=create_dir) / "result.json"


def ai_result_json_path(report_file: str, create_dir: bool = False) -> Path:
    """独立 AI 研判结果：reports/<stem>/ai_result.json"""
    return report_dir(report_file, create=create_dir) / "ai_result.json"


def ai_section_dir(report_file: str, create_dir: bool = False) -> Path:
    """模块级 AI 结果目录：reports/<stem>/ai_sections/"""
    d = report_dir(report_file, create=create_dir) / "ai_sections"
    if create_dir:
        d.mkdir(parents=True, exist_ok=True)
    return d


def ai_section_result_path(report_file: str, section: str, scope: str = "all", create_dir: bool = False) -> Path:
    """模块级 AI：reports/<stem>/ai_sections/<section>__<scope>.json"""
    import re
    sec = re.sub(r"[^\w\-]+", "_", str(section or "section").strip().lower())[:48] or "section"
    sc = re.sub(r"[^\w\-.=]+", "_", str(scope or "all").strip().lower())[:80] or "all"
    return ai_section_dir(report_file, create_dir=create_dir) / f"{sec}__{sc}.json"


def analysis_db_path(report_file: str, create_dir: bool = False) -> Path:
    return report_dir(report_file, create=create_dir) / "analysis.db"


def legacy_flat_report(report_file: str) -> Path:
    return config.REPORTS_DIR / report_id(report_file)


def legacy_flat_result(report_file: str) -> Path:
    return config.REPORTS_DIR / f"result_{report_stem(report_file)}.json"


def legacy_db_path(report_file: str) -> Path:
    return config.REPORTS_DIR / "dbs" / f"{report_stem(report_file)}.db"


def resolve_report_json(report_file: str) -> Optional[Path]:
    stem = report_stem(report_file)
    rid = report_id(report_file)
    for p in (
        config.REPORTS_DIR / stem / "report.json",
        config.REPORTS_DIR / stem / rid,
        config.REPORTS_DIR / rid,
        config.REPORTS_DIR / f"collect_{stem}.json",
    ):
        if p.exists() and p.is_file():
            return p
    return None


def resolve_result_json(report_file: str) -> Optional[Path]:
    stem = report_stem(report_file)
    for p in (
        config.REPORTS_DIR / stem / "result.json",
        config.REPORTS_DIR / f"result_{stem}.json",
    ):
        if p.exists() and p.is_file():
            return p
    return None


def resolve_analysis_db(report_file: str) -> Optional[Path]:
    stem = report_stem(report_file)
    for p in (
        config.REPORTS_DIR / stem / "analysis.db",
        config.REPORTS_DIR / "dbs" / f"{stem}.db",
    ):
        if p.exists() and p.is_file():
            return p
    return None


def db_path_for_write(report_file: str) -> Path:
    return analysis_db_path(report_file, create_dir=True)


def iter_report_ids(limit: int = 200) -> List[str]:
    """发现所有报告逻辑 ID（新目录优先，兼容扁平）。"""
    seen = set()
    out: List[str] = []

    def add(rid: str) -> None:
        if rid not in seen:
            seen.add(rid)
            out.append(rid)

    if config.REPORTS_DIR.exists():
        dirs = []
        for d in config.REPORTS_DIR.iterdir():
            if not d.is_dir() or d.name in RESERVED or d.name.startswith("."):
                continue
            if (d / "report.json").exists() or (d / f"report_{d.name}.json").exists():
                dirs.append(d)
        for d in sorted(dirs, key=lambda p: p.name, reverse=True):
            add(report_id(d.name))

        for f in sorted(config.REPORTS_DIR.glob("report_*.json"), reverse=True):
            add(f.name)

        for f in sorted(config.REPORTS_DIR.glob("collect_*.json"), reverse=True):
            add(report_id(f.name))

    return out[:limit]


def migrate_report_to_folder(report_file: str) -> Tuple[str, Path]:
    """把扁平 report/result/db 迁入 reports/<stem>/。已是目录结构则跳过。"""
    rid = report_id(report_file)
    stem = report_stem(rid)
    folder = report_dir(rid, create=True)
    target_report = folder / "report.json"
    target_result = folder / "result.json"
    target_db = folder / "analysis.db"

    src_report = resolve_report_json(rid)
    if src_report and src_report.resolve() != target_report.resolve():
        if not target_report.exists():
            shutil.move(str(src_report), str(target_report))
        # 若源在根目录且已复制/移动成功，扁平文件已不在

    src_result = resolve_result_json(rid)
    if src_result and src_result.resolve() != target_result.resolve():
        if not target_result.exists():
            shutil.move(str(src_result), str(target_result))

    src_db = resolve_analysis_db(rid)
    if src_db and src_db.resolve() != target_db.resolve():
        if not target_db.exists():
            # 一并搬 WAL/SHM
            for suf in ("", "-wal", "-shm"):
                p = Path(str(src_db) + suf) if suf else src_db
                if p.exists():
                    dest = Path(str(target_db) + suf) if suf else target_db
                    shutil.move(str(p), str(dest))

    return rid, folder


def migrate_all_flat_reports() -> int:
    n = 0
    for rid in list(iter_report_ids(500)):
        flat = legacy_flat_report(rid)
        folder_json = report_dir(rid) / "report.json"
        if flat.exists() or (legacy_db_path(rid).exists() and not folder_json.exists()):
            try:
                migrate_report_to_folder(rid)
                n += 1
            except Exception as e:
                print(f"[paths] migrate {rid}: {e}")
        elif not folder_json.exists() and resolve_report_json(rid):
            # collect_*.json 等 → 拷入目录
            try:
                migrate_report_to_folder(rid)
                n += 1
            except Exception as e:
                print(f"[paths] migrate {rid}: {e}")
    return n
