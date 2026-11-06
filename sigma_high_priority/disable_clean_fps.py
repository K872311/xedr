# -*- coding: utf-8 -*-
"""按干净系统报告禁用过宽规则 + 生成 win11_baseline。"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Set

ROOT = Path(__file__).resolve().parent.parent
MD = Path(r"D:\360极速浏览器X下载\t1_2026-08-13_07-30-24+08-00.md")
REPORT = ROOT / "reports" / "t1_2026-08-13_07-30-24+08-00" / "report.json"
NOTE = "clean Win11 baseline FP 2026-08-13"


def parse_titles(md: Path) -> Set[str]:
    text = md.read_text(encoding="utf-8")
    titles: Set[str] = set()
    for m in re.finditer(
        r"### 4\.\d+ \[\w+\] [^—\n]+— (.+?) ×\d+",
        text,
    ):
        t = m.group(1).strip()
        if t:
            titles.add(t)
    return titles


def disable_rows(items: List[Any], titles: Set[str], name_keys=("name", "title", "id")) -> int:
    n = 0
    for x in items or []:
        if not isinstance(x, dict) or x.get("enabled") is False:
            continue
        label = ""
        for k in name_keys:
            label = str(x.get(k) or "").strip()
            if label:
                break
        if label in titles:
            x["enabled"] = False
            x["disabled_reason"] = NOTE
            x["disabled_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            n += 1
    return n


def _norm_path(p: str) -> str:
    s = str(p or "").strip().lower()
    s = s.replace("/", "\\")
    for a, b in (
        ("%systemroot%", "c:\\windows"),
        ("%windir%", "c:\\windows"),
        ("%programfiles%", "c:\\program files"),
        ("%programfiles(x86)%", "c:\\program files (x86)"),
        ("%programdata%", "c:\\programdata"),
    ):
        s = s.replace(a, b)
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    return s.strip()


def build_baseline(report: Dict[str, Any]) -> Dict[str, Any]:
    services = []
    seen_svc = set()
    for s in report.get("services") or []:
        if not isinstance(s, dict):
            continue
        name = str(s.get("name") or s.get("Name") or s.get("service_name") or "").strip()
        img = str(
            s.get("path")
            or s.get("image_path")
            or s.get("ImagePath")
            or s.get("bin_path")
            or s.get("binary_path")
            or ""
        ).strip()
        if not name:
            continue
        key = (name.lower(), _norm_path(img))
        if key in seen_svc:
            continue
        seen_svc.add(key)
        services.append({"name": name, "image_path": img, "image_path_norm": _norm_path(img)})

    tasks = []
    seen_task = set()
    for t in report.get("scheduled_tasks") or []:
        if not isinstance(t, dict):
            continue
        tname = str(t.get("task_name") or t.get("name") or t.get("TaskName") or "").strip()
        cmd = str(t.get("command") or t.get("actions") or t.get("Command") or "").strip()
        if isinstance(t.get("actions"), list):
            cmd = " | ".join(str(x) for x in t.get("actions") if x)
        if not tname:
            continue
        key = (tname.lower(), _norm_path(cmd)[:240])
        if key in seen_task:
            continue
        seen_task.add(key)
        tasks.append({"task_name": tname, "command": cmd, "command_norm": _norm_path(cmd)})

    startups = []
    seen_st = set()
    for s in report.get("startup_items") or []:
        if not isinstance(s, dict):
            continue
        name = str(s.get("name") or s.get("Name") or "").strip()
        cmd = str(s.get("command") or s.get("path") or s.get("Command") or "").strip()
        if not name and not cmd:
            continue
        key = (name.lower(), _norm_path(cmd)[:240])
        if key in seen_st:
            continue
        seen_st.add(key)
        startups.append({"name": name, "command": cmd, "command_norm": _norm_path(cmd)})

    return {
        "id": "win11_baseline",
        "name": "Win11 干净系统基线",
        "source_report": "t1_2026-08-13_07-30-24+08-00",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "note": "从干净 Win11 采集生成；匹配时优先过滤服务/计划任务/启动项",
        "services": services,
        "tasks": tasks,
        "startup": startups,
        "stats": {
            "services": len(services),
            "tasks": len(tasks),
            "startup": len(startups),
        },
    }


def main() -> None:
    titles = parse_titles(MD)
    print(f"FP titles from clean MD: {len(titles)}")

    # --- keywords ---
    kw_p = ROOT / "rules" / "rules-keywords.json"
    kw = json.loads(kw_p.read_text(encoding="utf-8"))
    # keywords 用 title 字段
    n_kw = 0
    for x in kw.get("suspiciousCmds") or []:
        if not isinstance(x, dict) or x.get("enabled") is False:
            continue
        label = str(x.get("title") or x.get("name") or "").strip()
        if label in titles:
            x["enabled"] = False
            x["disabled_reason"] = NOTE
            x["disabled_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            n_kw += 1
    kw_p.write_text(json.dumps(kw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"disabled keywords rows: {n_kw}")

    # --- windows-system ---
    win_p = ROOT / "rules" / "rules-windows-system.json"
    win = json.loads(win_p.read_text(encoding="utf-8"))
    n_win = 0
    for key in ("registryRules", "taskRules", "serviceRules", "startupRules"):
        c = disable_rows(win.get(key) or [], titles)
        n_win += c
        print(f"  disabled {key}: {c}")
    win_p.write_text(json.dumps(win, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"disabled windows-system rows: {n_win}")

    # --- eventlog noisy titles ---
    log_dir = ROOT / "log_rules" / "rules"
    disabled_titles = sorted(
        t
        for t in titles
        if any(
            k in t.lower()
            for k in (
                "logon",
                "logoff",
                "proc exec",
                "credential manager",
                "admin logon",
                "explicit logon",
            )
        )
        or t.endswith("(Noisy)")
    )
    # 用 MD 里 matcher=eventlog 的更准确
    text = MD.read_text(encoding="utf-8")
    ev_titles = []
    for m in re.finditer(
        r"### 4\.\d+ \[\w+\] ([^—\n]+)— (.+?) ×\d+\n- 来源: `eventlog`",
        text,
    ):
        ev_titles.append(m.group(2).strip())
    if ev_titles:
        disabled_titles = sorted(set(ev_titles))
    dis_path = log_dir / ".disabled_titles.json"
    dis_path.write_text(
        json.dumps(
            {
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "note": NOTE,
                "titles": disabled_titles,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"eventlog disabled titles: {len(disabled_titles)} -> {dis_path.name}")

    # --- baseline ---
    if not REPORT.is_file():
        print("WARN: clean report.json missing, skip baseline build")
        return
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    # normalize if wrapped
    if "hostname" not in report and isinstance(report.get("report"), dict):
        report = report["report"]
    bl = build_baseline(report)
    out_dir = ROOT / "baselines"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_p = out_dir / "win11_baseline.json"
    out_p.write_text(json.dumps(bl, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"baseline written: {out_p}")
    print("  stats", bl["stats"])


if __name__ == "__main__":
    main()
