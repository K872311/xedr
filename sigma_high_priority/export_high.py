# -*- coding: utf-8 -*-
"""Filter sigma_all_rules for high/critical Windows rules usable by this platform."""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(r"D:\360极速浏览器X下载\sigma_all_rules")
OUT = Path(__file__).resolve().parent

HIGH = {"high", "critical"}
SKIP_CATEGORY_SYSMON_DEEP = {
    "image_load",
    "process_access",
    "create_remote_thread",
    "create_stream_hash",
    "dns_query",
    "file_block",
    "file_change",
    "file_delete",
    "file_delete_detected",
    "file_event",
    "network_connection",
    "pipe_created",
    "raw_access_thread",
    "registry_add",
    "registry_delete",
    "registry_event",
    "registry_set",
    "wmi_event",
    "driver_load",
    "process_tampering",
    "clipboard_change",
}
EVENTLOG_SERVICES = {
    "security",
    "system",
    "powershell",
    "powershell-classic",
    "windefend",
    "bits",
    "taskscheduler",
    "applocker",
    "codeintegrity",
    "dns-server",
    "ntlm",
    "smbclient",
    "smbserver",
    "microsoft-windows-windows defender/operational",
    "microsoft-windows-bits-client/operational",
}
NON_WIN_PRODUCT = {
    "linux",
    "macos",
    "aws",
    "azure",
    "gcp",
    "okta",
    "github",
    "cisco",
    "fortinet",
    "zeek",
    "nginx",
    "apache",
}
SKIP_PATH_PARTS = (
    "/linux/",
    "/macos/",
    "/cloud/",
    "/web/",
    "/network/",
    "/azure/",
    "/aws/",
    "/gcp/",
    "/okta/",
    "/m365/",
)


def ensure_yaml():
    try:
        import yaml  # noqa: F401
        return
    except ImportError:
        import subprocess

        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])


def load_docs(path: Path):
    import yaml

    text = path.read_text(encoding="utf-8", errors="replace")
    docs = []
    try:
        for d in yaml.safe_load_all(text):
            if isinstance(d, dict):
                docs.append(d)
    except Exception as e:
        return None, str(e)
    return docs, None


def classify(path_l: str, product: str, category: str, service: str) -> str:
    if category in SKIP_CATEGORY_SYSMON_DEEP:
        if "file" in category:
            return "file_path_ioc"
        if "registry" in category:
            return "registry_persist"
        if "driver" in category:
            return "driver_ioc"
        return "skip_sysmon_deep"
    if category == "process_creation":
        return "process_lolbin"
    if "registry" in category or "/registry/" in path_l:
        return "registry_persist"
    if "driver" in category or "driver" in path_l or "vulnerable_driver" in path_l:
        return "driver_ioc"
    if service in EVENTLOG_SERVICES:
        return "eventlog_sigma"
    if category in ("ps_script", "ps_module") or "powershell" in path_l:
        return "eventlog_sigma"
    if "file" in category:
        return "file_path_ioc"
    if "builtin" in path_l or "emerging_threats" in path_l:
        return "eventlog_or_review"
    return "review"


def main() -> int:
    ensure_yaml()
    if not ROOT.is_dir():
        print("MISSING_SOURCE", ROOT)
        return 1

    rows = []
    errors = 0
    for p in ROOT.rglob("*.yml"):
        docs, err = load_docs(p)
        if err or not docs:
            errors += 1
            continue
        for d in docs:
            level = str(d.get("level") or "").lower().strip()
            if level not in HIGH:
                continue
            logsource = d.get("logsource") or {}
            if not isinstance(logsource, dict):
                logsource = {}
            product = str(logsource.get("product") or "").lower()
            category = str(logsource.get("category") or "").lower()
            service = str(logsource.get("service") or "").lower()
            path_l = str(p).lower().replace("\\", "/")
            if any(x in path_l for x in SKIP_PATH_PARTS):
                continue
            if product in NON_WIN_PRODUCT:
                continue
            is_win = (
                product in ("windows", "windows_defender", "microsoft_windows")
                or "windows" in path_l
                or service in EVENTLOG_SERVICES
            )
            if not is_win and product and product not in ("", "windows"):
                if "windows" not in path_l:
                    continue
            tags = d.get("tags") or []
            if not isinstance(tags, list):
                tags = []
            rel = str(p.relative_to(ROOT)).replace("\\", "/")
            rows.append(
                {
                    "file": rel,
                    "id": d.get("id") or "",
                    "title": d.get("title") or p.stem,
                    "level": level,
                    "status": str(d.get("status") or ""),
                    "product": product,
                    "category": category,
                    "service": service,
                    "bucket": classify(path_l, product, category, service),
                    "tags": [str(t) for t in tags[:12]],
                }
            )

    by_bucket = defaultdict(list)
    for r in rows:
        by_bucket[r["bucket"]].append(r)
    summary = {k: len(v) for k, v in sorted(by_bucket.items(), key=lambda x: -len(x[1]))}

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sigma_high_all.json").write_text(
        json.dumps({"total": len(rows), "by_bucket": summary, "rules": rows}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    notes = {
        "eventlog_sigma": "可直接进 log_rules/rules（事件日志）",
        "process_lolbin": "进程/命令行 → 关键词或 process 规则",
        "file_path_ioc": "路径 IOC → rules-files.json（多数需 Sysmon 原规则，取路径）",
        "registry_persist": "注册表持久化 → rules-windows-system.json",
        "driver_ioc": "驱动名 IOC",
        "eventlog_or_review": "需人工看是否可映射事件日志",
        "skip_sysmon_deep": "依赖 Sysmon 深度事件，本平台默认跳过",
        "review": "待人工分类",
        "other": "其他",
    }
    actionable = [
        "eventlog_sigma",
        "process_lolbin",
        "file_path_ioc",
        "registry_persist",
        "driver_ioc",
        "eventlog_or_review",
    ]

    lines = [
        "# Sigma 高危规则候选（level=high/critical，Windows）",
        "",
        f"源目录: `{ROOT}`",
        f"筛选结果: **{len(rows)}** 条 high/critical（Windows 相关）",
        "",
        "## 分桶统计",
        "",
    ]
    for k, v in sorted(by_bucket.items(), key=lambda x: -len(x[1])):
        lines.append(f"- **{k}**: {len(v)}  — {notes.get(k, '')}")
    lines.append("")

    for bucket in actionable:
        items = by_bucket.get(bucket) or []
        if not items:
            continue
        items = sorted(items, key=lambda r: (0 if r["level"] == "critical" else 1, r["title"].lower()))
        lines.append(f"## {bucket} ({len(items)})")
        lines.append("")
        lines.append("| level | title | category/service | file |")
        lines.append("|---|---|---|---|")
        for r in items[:400]:
            cs = r["category"] or r["service"] or "-"
            t = str(r["title"]).replace("|", "/")
            lines.append(f"| {r['level']} | {t} | {cs} | `{r['file']}` |")
        if len(items) > 400:
            lines.append(f"| ... | 另有 {len(items) - 400} 条见 JSON | | |")
        lines.append("")

    (OUT / "README.md").write_text("\n".join(lines), encoding="utf-8")
    ev = sorted(by_bucket.get("eventlog_sigma") or [], key=lambda r: (0 if r["level"] == "critical" else 1, r["file"]))
    (OUT / "eventlog_candidates.txt").write_text("\n".join(r["file"] for r in ev), encoding="utf-8")

    print("TOTAL_HIGH", len(rows), "ERRORS", errors)
    print("SUMMARY", json.dumps(summary, ensure_ascii=False))
    print("WROTE", OUT)
    print(
        "eventlog",
        len(ev),
        "process",
        len(by_bucket.get("process_lolbin") or []),
        "file",
        len(by_bucket.get("file_path_ioc") or []),
        "reg",
        len(by_bucket.get("registry_persist") or []),
        "drv",
        len(by_bucket.get("driver_ioc") or []),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
