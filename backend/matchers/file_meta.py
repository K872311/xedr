"""文件扩展名 / 魔术字节规则 → 签名说明（服务器上通常无原始文件，按扩展名+规则推断）"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from ..rules_loader import get_store

# 常见扩展名兜底（rules-file-types 多数是魔数，采集端未存头字节时用此）
EXT_SIGNATURES = {
    ".exe": ("application/x-msdownload", "PE 可执行文件 (MZ)", "4D5A / MZ"),
    ".dll": ("application/x-msdownload", "PE 动态库 (MZ)", "4D5A / MZ"),
    ".sys": ("application/x-msdownload", "PE 驱动 (MZ)", "4D5A / MZ"),
    ".msi": ("application/x-msi", "Windows Installer", "D0CF11E0 (OLE)"),
    ".pdf": ("application/pdf", "PDF 文档", "25504446 %PDF"),
    ".zip": ("application/zip", "ZIP 压缩包", "504B0304 PK"),
    ".7z": ("application/x-7z-compressed", "7-Zip", "377ABCAF"),
    ".rar": ("application/x-rar-compressed", "RAR 压缩包", "52617221 Rar!"),
    ".png": ("image/png", "PNG 图片", "89504E47"),
    ".jpg": ("image/jpeg", "JPEG 图片", "FFD8FF"),
    ".jpeg": ("image/jpeg", "JPEG 图片", "FFD8FF"),
    ".gif": ("image/gif", "GIF 图片", "474946"),
    ".bmp": ("image/bmp", "BMP 图片", "424D"),
    ".sqlite": ("application/x-sqlite3", "SQLite 数据库", "53514C697465"),
    ".db": ("application/x-sqlite3", "数据库文件", "视内容而定"),
    ".evtx": ("application/x-ms-evtx", "Windows 事件日志", "ElfFile"),
    ".reg": ("text/x-ms-regedit", "注册表导出", "Windows Registry Editor"),
    ".pf": ("application/x-prefetch", "Prefetch 执行痕迹", "SCCA"),
    ".lnk": ("application/x-ms-shortcut", "Windows 快捷方式", "4C000000"),
    ".ps1": ("text/x-powershell", "PowerShell 脚本", "文本"),
    ".bat": ("application/x-bat", "批处理脚本", "文本"),
    ".cmd": ("application/x-bat", "CMD 脚本", "文本"),
    ".vbs": ("text/vbscript", "VBScript", "文本"),
    ".js": ("text/javascript", "JavaScript", "文本"),
    ".html": ("text/html", "HTML", "文本"),
    ".htm": ("text/html", "HTML", "文本"),
    ".json": ("application/json", "JSON", "文本"),
    ".xml": ("text/xml", "XML", "3C3F786D6C <?xml"),
    ".txt": ("text/plain", "纯文本", "文本"),
    ".log": ("text/plain", "日志", "文本"),
    ".csv": ("text/csv", "CSV", "文本"),
    ".doc": ("application/msword", "Word 文档 (OLE)", "D0CF11E0"),
    ".docx": ("application/vnd.openxmlformats", "Word OOXML (ZIP)", "504B0304"),
    ".xls": ("application/vnd.ms-excel", "Excel (OLE)", "D0CF11E0"),
    ".xlsx": ("application/vnd.openxmlformats", "Excel OOXML (ZIP)", "504B0304"),
    ".ppt": ("application/vnd.ms-powerpoint", "PowerPoint (OLE)", "D0CF11E0"),
    ".pptx": ("application/vnd.openxmlformats", "PowerPoint OOXML", "504B0304"),
    ".pst": ("application/vnd.ms-outlook", "Outlook PST", "2142444E !BDN"),
    ".ost": ("application/vnd.ms-outlook", "Outlook OST", "魔数视版本"),
    ".eml": ("message/rfc822", "邮件 EML", "文本头"),
    ".dmp": ("application/x-dmp", "内存/崩溃转储", "视格式"),
    ".vhd": ("application/x-vhd", "虚拟硬盘 VHD", "conectix"),
    ".vhdx": ("application/x-vhdx", "虚拟硬盘 VHDX", "vhdxfile"),
    ".iso": ("application/x-iso9660", "ISO 镜像", "CD001"),
    ".cab": ("application/vnd.ms-cab", "CAB 包", "4D534346"),
    ".dat": ("application/octet-stream", "数据文件", "未知/二进制"),
}


def _norm_ext(ext: str, name: str = "") -> str:
    e = (ext or "").lower().strip()
    if e and not e.startswith("."):
        e = "." + e
    if not e and name and "." in name:
        e = "." + name.rsplit(".", 1)[-1].lower()
    return e


def enrich_file_info(entry: Dict[str, Any]) -> Dict[str, Any]:
    name = entry.get("name") or ""
    ext = _norm_ext(entry.get("ext") or "", name)
    full = entry.get("full_path") or entry.get("path") or ""
    size = entry.get("size") or 0
    mime, desc, sig = "application/octet-stream", "未知类型", ""
    if ext in EXT_SIGNATURES:
        mime, desc, sig = EXT_SIGNATURES[ext]

    # 叠加 rules-file-types 中带 ascii/hex 的说明
    note = ""
    significance = "low"
    try:
        store = get_store()
        for m in store.file_types.get("magicBytesSignatures") or []:
            # 按描述关键词弱关联扩展名
            d = (m.get("description") or "").lower()
            mt = (m.get("mimeType") or "").lower()
            if ext == ".vhd" and "vhd" in d:
                mime, desc = m.get("mimeType") or mime, m.get("description") or desc
                sig = m.get("asciiSignature") or m.get("hexSignature") or sig
                significance = m.get("forensicSignificance") or significance
                note = m.get("note") or ""
                break
            if ext in (".jpg", ".jpeg") and "jpeg" in d:
                mime, desc = m.get("mimeType") or mime, m.get("description") or desc
                sig = m.get("hexSignature") or sig
                significance = m.get("forensicSignificance") or "medium"
                note = m.get("note") or ""
                break
            if ext == ".xml" and "xml" in mt:
                mime, desc = m.get("mimeType") or mime, m.get("description") or desc
                sig = m.get("asciiSignature") or sig
                break
            if "registry" in d and ext in (".dat", ".hiv") and "system32\\config" in full.lower().replace("/", "\\"):
                mime, desc = m.get("mimeType") or mime, m.get("description") or desc
                sig = m.get("asciiSignature") or m.get("hexSignature") or sig
                significance = "high"
                note = m.get("note") or ""
                break
    except Exception:
        pass

    # 浏览器库文件名
    if name in ("History", "Cookies", "Login Data", "Web Data", "places.sqlite", "cookies.sqlite"):
        mime, desc, sig = "application/x-sqlite3", f"浏览器数据库: {name}", "SQLite 格式"
        significance = "high"
        note = "可按 rules-browsers.json SQL 抽取"

    # 采集端 Authenticode / 版本信息优先
    magic = (entry.get("magic_hex") or "").strip()
    company = (entry.get("company") or "").strip()
    product = (entry.get("product") or "").strip()
    description = (entry.get("description") or "").strip()
    file_version = (entry.get("file_version") or "").strip()
    signer = (entry.get("signer") or "").strip()
    sig_status = (entry.get("sig_status") or "").strip()
    signed = bool(entry.get("signed"))
    if magic and (not sig or sig.startswith("（")):
        sig = magic
    sig_source = "extension_rules" if sig else "unknown"
    if magic or signer or sig_status or company:
        sig_source = "collected"
        if magic:
            sig = magic + ((" / " + sig) if sig and sig != magic else "")

    return {
        "name": name,
        "path": entry.get("path") or "",
        "full_path": full,
        "ext": ext,
        "size": size,
        "size_human": _human(size),
        "mime_type": mime,
        "type_description": description or desc,
        "signature": sig or "（采集未保存文件头；按扩展名推断）",
        "signature_source": sig_source,
        "forensic_significance": significance,
        "note": note,
        "is_directory": False,
        "company": company,
        "product": product,
        "description": description,
        "file_version": file_version,
        "signed": signed,
        "signer": signer,
        "sig_status": sig_status,
        "magic_hex": magic,
        "authenticode": {
            "signed": signed,
            "signer": signer,
            "status": sig_status,
        },
    }


def _human(n: int) -> str:
    n = int(n or 0)
    if n >= 1048576:
        return f"{n/1048576:.1f} MB"
    if n >= 1024:
        return f"{n/1024:.1f} KB"
    return f"{n} B"


def enrich_folder_listing(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [enrich_file_info(f) for f in files]
