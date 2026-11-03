"""Detect guest OS family for report routing (windows | linux)."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_WIN_HINT = re.compile(
    r"windows|win32|win64|microsoft|nt\s*\d|server\s*20\d{2}",
    re.I,
)
_LINUX_HINT = re.compile(
    r"linux|ubuntu|debian|centos|rhel|redhat|fedora|suse|opensuse|"
    r"rocky|alma|麒麟|kylin|uos|deepin|openeuler|anolis|alpine|arch|"
    r"gentoo|busybox|gnu/linux",
    re.I,
)


def detect_os_family(report: Optional[Dict[str, Any]] = None) -> str:
    """Return 'linux' | 'windows'. Default windows for legacy collectors."""
    r = report if isinstance(report, dict) else {}
    explicit = str(r.get("os_family") or r.get("platform") or "").strip().lower()
    if explicit in ("linux", "unix"):
        return "linux"
    if explicit in ("windows", "win", "win32", "win64"):
        return "windows"
    if explicit in ("macos", "darwin", "osx"):
        return "linux"  # treat as non-windows for matcher gating

    blob = " ".join(
        str(x or "")
        for x in (
            r.get("os"),
            r.get("os_name"),
            (r.get("system_info") or {}).get("os") if isinstance(r.get("system_info"), dict) else "",
            (r.get("system_info") or {}).get("pretty_name") if isinstance(r.get("system_info"), dict) else "",
            r.get("collector"),
            r.get("collector_id"),
        )
    )
    if _LINUX_HINT.search(blob) and not _WIN_HINT.search(blob):
        return "linux"
    if _WIN_HINT.search(blob):
        return "windows"

    # Path heuristics: Linux abs paths vs Windows drive letters
    linux_hits = 0
    win_hits = 0
    for p in (r.get("processes") or [])[:80]:
        if not isinstance(p, dict):
            continue
        path = str(p.get("path") or p.get("command_line") or "")
        if re.match(r"^[A-Za-z]:\\", path) or path.startswith("\\\\"):
            win_hits += 1
        elif path.startswith("/") and not path.startswith("//"):
            linux_hits += 1
    if linux_hits >= 3 and linux_hits > win_hits:
        return "linux"
    if win_hits >= 3 and win_hits > linux_hits:
        return "windows"

    # Section presence typical of LinuxSC import
    if r.get("collector") == "linuxsc" or str(r.get("source") or "").lower() == "linuxsc":
        return "linux"
    se = r.get("security_extras")
    if isinstance(se, dict) and (se.get("linuxsc") or se.get("rootkit_hunt")):
        return "linux"

    return "windows"


def apply_os_family(report: Dict[str, Any]) -> Dict[str, Any]:
    """Mutate report with os_family; ensure os display string if empty on linux."""
    if not isinstance(report, dict):
        return report
    fam = detect_os_family(report)
    report["os_family"] = fam
    if fam == "linux" and not str(report.get("os") or "").strip():
        si = report.get("system_info") if isinstance(report.get("system_info"), dict) else {}
        pretty = str(si.get("pretty_name") or si.get("os") or si.get("uname") or "").strip()
        report["os"] = pretty or "Linux"
    return report
