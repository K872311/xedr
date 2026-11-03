"""rules-email / rules-encryption / rules-file-types 中可落地的路径级匹配"""
from __future__ import annotations
from typing import Dict, List, Set, Tuple

from ..models import Finding
from ..rules_loader import RuleStore

EMAIL_EXTS = {".eml", ".mbox", ".pst", ".ost", ".msg", ".vcf"}
ENC_EXTS = {".tc", ".hc", ".vera", ".kdbx", ".key", ".pgp", ".gpg", ".asc", ".bitlocker"}
ENC_NAMES = ("veracrypt", "truecrypt", "bitlocker", "keepass", "7z", "encrypted")


def _file_rows(report: Dict, **kw):
    scans = report.get("file_scans") or []
    if scans:
        return scans
    from ..db_store import files_rid, query_files
    rid = files_rid(report)
    if not rid:
        return []
    try:
        return query_files(rid, **kw)
    except Exception:
        return []


def run_email(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    _ = store.email
    findings = []
    for f in _file_rows(report, exts=list(EMAIL_EXTS), limit=80):
        name = (f.get("name") or "").lower()
        ext = (f.get("ext") or "").lower()
        if ext and not ext.startswith("."):
            ext = "." + ext
        full = f.get("full_path") or ""
        if ext in EMAIL_EXTS or name.endswith(".mbox"):
            key = f"邮件文件|{full}|email"
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding("邮件文件", "medium", ext or name, full, "文件扫描", "rules-email", "aux_rules"))
    return findings, {"email_files": len(findings)}


def run_encryption(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    _ = store.encryption
    findings = []
    rows = _file_rows(report, exts=list(ENC_EXTS), limit=80)
    if not rows:
        rows = _file_rows(report, name_contains="veracrypt", limit=40) + _file_rows(report, name_contains="keepass", limit=40)
    for f in rows:
        name = (f.get("name") or "")
        low = name.lower()
        ext = (f.get("ext") or "").lower()
        if ext and not ext.startswith("."):
            ext = "." + ext
        full = f.get("full_path") or ""
        size = int(f.get("size") or 0)
        hit = False
        title = ""
        if ext in ENC_EXTS:
            hit, title = True, f"加密容器{ext}"
        elif any(x in low for x in ENC_NAMES) and ext in {".exe", ".sys", ".dll", ""}:
            hit, title = True, name
        # 规则：大体积疑似加密容器（无扩展名 + >5MB）— 保守，只标 info
        min_size = int((store.encryption.get("configurationDefaults") or {}).get("minimumFileSize") or 5242880)
        if not hit and not ext and size >= min_size and size % 512 == 0:
            # 太噪，跳过无扩展名大文件
            pass
        if hit:
            key = f"加密痕迹|{title}|{full}|encryption"
            if key not in seen:
                seen.add(key)
                findings.append(Finding("加密痕迹", "medium", title, full, "文件扫描", "rules-encryption", "aux_rules"))
    # 已装程序 / 进程里的加密工具已由 interesting 覆盖
    return findings, {"encryption_files": len(findings)}


def run_file_types_hint(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    """rules-file-types：对高取证价值扩展名做提示（魔数需原文件，路径级兜底）"""
    _ = store.file_types
    findings = []
    high = {
        ".reg": "注册表导出",
        ".hiv": "注册表Hive",
        ".evtx": "事件日志",
        ".pf": "Prefetch",
        ".lnk": "快捷方式",
        ".dmp": "内存转储",
        ".vhd": "虚拟磁盘",
        ".vhdx": "虚拟磁盘",
        ".e01": "取证镜像",
        ".dd": "磁盘镜像",
    }
    for f in _file_rows(report, exts=list(high.keys()), limit=120):
        ext = (f.get("ext") or "").lower()
        if ext and not ext.startswith("."):
            ext = "." + ext
        if ext not in high:
            continue
        full = f.get("full_path") or ""
        # 仅用户目录/Temp 等非系统海量区，避免 Windows\WinSxS 类噪声
        low = full.lower().replace("/", "\\")
        if "\\windows\\" in low and ext in {".lnk", ".pf"}:
            continue
        if not any(x in low for x in ("\\users\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\documents\\", "\\recycle")):
            continue
        key = f"高价值文件|{ext}|{full}|filetypes"
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding("高价值文件", "low", high[ext], full, "文件扫描", ext, "aux_rules"))
    return findings, {}


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    all_f = []
    meta = {}
    for fn in (run_email, run_encryption, run_file_types_hint):
        f, m = fn(report, store, seen)
        all_f.extend(f)
        meta.update(m or {})
    return all_f, meta
