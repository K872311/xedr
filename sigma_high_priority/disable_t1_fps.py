# -*- coding: utf-8 -*-
"""Disable high-FP rules seen in t1 HTML report; expand file excludePatterns."""
from __future__ import annotations

import json
import time
from pathlib import Path

RULES = Path(__file__).resolve().parent.parent / "rules"

# Titles from HTML report that are clearly noisy / wrong evidence
NOISY_FILE_TITLES = {
    "File Creation In Suspicious Directory By Msdt.EXE",
    "File With Uncommon Extension Created By An Office Application",
    "ISO File Created Within Temp Folders",
    "Suspicious Binary Writes Via AnyDesk",
    "Suspicious File Created by ArcSOC.exe",
    "Suspicious MSExchangeMailboxReplication ASPX Write",
    "Uncommon File Creation By Mysql Daemon Process",
    "Legitimate Application Dropped Script",
    "Legitimate Application Dropped Archive",
    "DPAPI Backup Keys And Certificate Export Activity IOC",
    "HackTool - Powerup Write Hijack DLL",
    "Malicious DLL File Dropped in the Teams or OneDrive Folder",
    "WScript or CScript Dropper - File",
    "Process Explorer Driver Creation By Non-Sysinternals Binary",
    "Suspicious Double Extension Files",
}

NOISY_TITLE_SUBSTR = [
    "KnownDlls",
    "LoadAppInit",
    "Windows\\Load",
    "无文件恶意软件常用的PowerShell",
    "Image File Execution Options",
]

EXTRA_EXCLUDES = [
    "\\VMware\\VMware Tools\\",
    "\\Huorong\\",
    "\\Windows Defender\\Definition Updates\\",
    "\\Microsoft\\EdgeUpdate\\",
    "\\Microsoft\\WindowsApps\\",
    "\\Package Cache\\",
]


def load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def save(p: Path, data: dict) -> None:
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def disable_list(items: list, pred, note: str) -> int:
    n = 0
    for x in items or []:
        if not isinstance(x, dict) or x.get("enabled") is False:
            continue
        if pred(x):
            x["enabled"] = False
            x["disabled_reason"] = note
            x["disabled_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            n += 1
    return n


def main() -> None:
    files_p = RULES / "rules-files.json"
    win_p = RULES / "rules-windows-system.json"
    kw_p = RULES / "rules-keywords.json"

    files = load(files_p)
    note = "t1 report FP review 2026-08-13"
    n_file = disable_list(
        files.get("suspiciousRules") or [],
        lambda x: (
            str(x.get("source") or "") == "sigma_high_priority"
            and (
                str(x.get("name") or "") in NOISY_FILE_TITLES
                or any(s.lower() in str(x.get("name") or "").lower() for s in NOISY_FILE_TITLES)
            )
        ),
        note,
    )
    # Also disable sigma file rules that only have very short / generic nameContains
    def generic_sigma_file(x: dict) -> bool:
        if str(x.get("source") or "") != "sigma_high_priority":
            return False
        if x.get("enabled") is False:
            return False
        nc = str(x.get("nameContains") or "").strip().lower()
        pc = str(x.get("pathContains") or "").strip().lower()
        if nc and len(nc) <= 6 and nc.endswith((".dll", ".dat", ".bat", ".cmd", ".tmp", ".vbs", ".ps1")):
            return True
        if pc and pc in ("\\temp\\", "\\tmp\\", "appdata\\local\\temp", "\\programdata\\"):
            return True
        return False

    n_file += disable_list(files.get("suspiciousRules") or [], generic_sigma_file, note + " generic path/name")

    ex = list(files.get("excludePatterns") or [])
    for e in EXTRA_EXCLUDES:
        if e.lower() not in {str(x).lower() for x in ex}:
            ex.append(e)
    files["excludePatterns"] = ex
    save(files_p, files)

    win = load(win_p)

    def noisy_reg(x: dict) -> bool:
        blob = " ".join(
            [
                str(x.get("id") or ""),
                str(x.get("name") or ""),
                str(x.get("reason") or ""),
                " ".join(str(y) for y in (x.get("keyContainsAny") or [])),
                str(x.get("keyContains") or ""),
            ]
        ).lower()
        if "knowndlls" in blob:
            return True
        if "loadappinit" in blob:
            return True
        if "loadappinit_dlls" in blob:
            return True
        # IFEO MitigationOptions alone is often defense config
        if "mitigationoptions" in blob and "image file execution options" in blob:
            return True
        for s in NOISY_TITLE_SUBSTR:
            if s.lower() in blob:
                return True
        return False

    n_reg = disable_list(win.get("registryRules") or [], noisy_reg, note)
    # Disable sigma process→registry command rules that only match very common tools without context
    def noisy_sigma_run(x: dict) -> bool:
        if str(x.get("source") or "") != "sigma_high_priority":
            return False
        name = str(x.get("name") or "")
        if name in NOISY_FILE_TITLES:
            return True
        needles = [str(y).lower() for y in (x.get("commandContainsAny") or [])]
        if not needles:
            return False
        # single short needle like ".dll" / "temp"
        if len(needles) == 1 and len(needles[0]) < 8:
            return True
        return False

    n_run = disable_list(win.get("registryRules") or [], noisy_sigma_run, note + " weak cmdline")
    n_task = disable_list(
        win.get("taskRules") or [],
        lambda x: str(x.get("source") or "") == "sigma_high_priority"
        and (
            str(x.get("name") or "") in NOISY_FILE_TITLES
            or (
                len(x.get("commandContainsAny") or []) == 1
                and len(str((x.get("commandContainsAny") or [""])[0])) < 8
            )
        ),
        note,
    )
    save(win_p, win)

    n_kw = 0
    if kw_p.is_file():
        kw = load(kw_p)
        cmds = kw.get("suspiciousCmds") or []
        keep = []
        for c in cmds:
            if not isinstance(c, dict):
                continue
            needle = str(c.get("needle") or "").strip().lower()
            title = str(c.get("title") or "")
            if str(c.get("source") or "") == "sigma_high_priority" and (
                title in NOISY_FILE_TITLES or len(needle) < 5 or needle in {".dll", ".bat", ".cmd", "temp", "http"}
            ):
                n_kw += 1
                continue
            keep.append(c)
        kw["suspiciousCmds"] = keep
        save(kw_p, kw)

    print(
        json.dumps(
            {
                "disabled_file_rules": n_file,
                "disabled_registry": n_reg + n_run,
                "disabled_task": n_task,
                "removed_keywords": n_kw,
                "exclude_patterns": EXTRA_EXCLUDES,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    import json

    main()
