# -*- coding: utf-8 -*-
"""一次性：禁用高置信误报规则（路径过宽 / 裸关键词 / 弱注册表）。"""
from __future__ import annotations

import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
NOTE = "FP audit 2026-08-13 path/keyword noise"

# 整条禁用的 files 规则 id
DISABLE_FILE_IDS = {
    "sigma.cd6386fabb9a.f2",  # C:\Users\ + 常见扩展
    "sigma.d7b50671d1ad.f1",  # \AppData\ 过宽
    "sigma.736ffa745f6f.f0",  # C:\Windows\Temp\ 过宽
    "sigma.fabb0e80030c.f2",  # \AppData\Local\Microsoft\Windows\ 过宽
    "sigma.0a1f9d296465.f0",  # Prefetch 错配
    "sigma.b447f7de1e53.f0",  # Public 与内置重复
    "sigma.1277f594a7d1.f1",  # Public 重复
    "sigma.28208707fe31.f0",  # Startup 任意 PE
    "sigma.52753ea4b3a0.f0",  # 名实不符仅 Startup
}

# keywords：按 needle+title 禁用裸词行；或按 title 整组禁用中的特定 needle
DISABLE_KEYWORD_NEEDLES = {
    # (title_substr_or_exact, needle_lower)
    ("Remote CHM File Download/Execution Via HH.EXE", "http://"),
    ("Remote CHM File Download/Execution Via HH.EXE", "https://"),
    ("Schtasks From Suspicious Folders", "powershell"),
    ("Schtasks From Suspicious Folders", "cmd /c"),
    ("Schtasks From Suspicious Folders", "cmd /k"),
    ("Operator Bloopers Cobalt Strike Commands", "c:\\windows\\system32\\cmd.exe"),
    ("Operator Bloopers Cobalt Strike Commands", "cmd.exe"),
    ("Potential Exploitation of GoAnywhere", "hidden"),
    ("Potential Exploitation of GoAnywhere", "bypass"),
    ("Windows Credential Guard", "delete"),
    ("Python One-Liners", "import"),
    ("Registry Export of Third-Party Credentials", "export"),
    ("VeeamBackup", "select"),
    ("Shadow Copies Deletion", "resize"),
    ("Shadow Copies Deletion", "catalog"),
    ("Suspicious Child Process of SolarWinds", "tomcat"),
    ("Suspicious Child Process of SolarWinds", "bitsadmin"),
    ("Suspicious Child Process of SolarWinds", "certutil"),
    ("Suspicious Child Process of Notepad++", "forfiles"),
    ("Uncommon One Time Only Scheduled Task", "wscript"),
}

# keywords 标题整组禁用（全部 needle 都噪声）
DISABLE_KEYWORD_TITLES = {
    # 暂不全组禁用，只砍裸 needle
}

# windows-system：按 id 禁用
DISABLE_WIN_IDS = {
    "sigma.966315efc5e1.reg",  # 仅 \Environment\
}

# windows-system：按 name + 含有的过宽 commandContainsAny 项收紧（删除宽项，全空则 disable）
STRIP_CMD_ANY = {
    "Schtasks From Suspicious Folders": {"powershell", "cmd /c", "cmd /k"},
    "Operator Bloopers Cobalt Strike Commands": {
        "c:\\windows\\system32\\cmd.exe",
        "cmd.exe",
    },
    "Remote CHM File Download/Execution Via HH.EXE": {"http://", "https://"},
}


def load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def save(p: Path, data: dict) -> None:
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def stamp(x: dict) -> None:
    x["enabled"] = False
    x["disabled_reason"] = NOTE
    x["disabled_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")


def disable_files() -> int:
    p = RULES / "rules-files.json"
    data = load(p)
    n = 0
    for x in data.get("suspiciousRules") or []:
        if not isinstance(x, dict) or x.get("enabled") is False:
            continue
        if str(x.get("id") or "") in DISABLE_FILE_IDS:
            stamp(x)
            n += 1
    save(p, data)
    return n


def disable_keywords() -> int:
    p = RULES / "rules-keywords.json"
    data = load(p)
    n = 0
    items = data.get("suspiciousCmds") or data.get("keywords") or []
    # 兼容列表字段名
    key = "suspiciousCmds" if "suspiciousCmds" in data else None
    if key is None:
        for k, v in data.items():
            if isinstance(v, list) and v and isinstance(v[0], dict) and "needle" in v[0]:
                key = k
                items = v
                break
    if not key:
        print("keywords list key not found")
        return 0

    for x in items:
        if not isinstance(x, dict) or x.get("enabled") is False:
            continue
        title = str(x.get("title") or x.get("name") or "")
        needle = str(x.get("needle") or "").lower()
        if title in DISABLE_KEYWORD_TITLES:
            stamp(x)
            n += 1
            continue
        for tsub, nsub in DISABLE_KEYWORD_NEEDLES:
            if tsub.lower() in title.lower() and needle == nsub.lower():
                stamp(x)
                n += 1
                break
    data[key] = items
    save(p, data)
    return n


def disable_win() -> int:
    p = RULES / "rules-windows-system.json"
    data = load(p)
    n = 0
    for section in ("registryRules", "taskRules", "serviceRules", "startupRules", "runRules"):
        for x in data.get(section) or []:
            if not isinstance(x, dict) or x.get("enabled") is False:
                continue
            rid = str(x.get("id") or "")
            name = str(x.get("name") or x.get("title") or "")
            if rid in DISABLE_WIN_IDS:
                stamp(x)
                n += 1
                continue
            for nsub, bad in STRIP_CMD_ANY.items():
                if nsub.lower() not in name.lower():
                    continue
                cmds = x.get("commandContainsAny")
                if not isinstance(cmds, list):
                    continue
                kept = [c for c in cmds if str(c).lower() not in {b.lower() for b in bad}]
                if len(kept) != len(cmds):
                    x["commandContainsAny"] = kept
                    x["fp_stripped"] = NOTE
                    if not kept:
                        stamp(x)
                    n += 1
    save(p, data)
    return n


def main() -> None:
    print("files disabled:", disable_files())
    print("keywords disabled:", disable_keywords())
    print("windows-system touched:", disable_win())


if __name__ == "__main__":
    main()
