# -*- coding: utf-8 -*-
"""Convert high-severity Sigma (file/process/registry/driver) into rules/*.json."""
from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
SRC = Path(r"D:\360极速浏览器X下载\sigma_all_rules")
CATALOG = ROOT / "sigma_high_priority" / "sigma_high_all.json"
MANIFEST = ROOT / "sigma_high_priority" / "imported_json.txt"
SOURCE_TAG = "sigma_high_priority"

COMMON_IMAGES = {
    "cmd.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe", "conhost.exe",
    "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
    "explorer.exe", "svchost.exe", "dllhost.exe", "taskhostw.exe", "sihost.exe",
    "runtimebroker.exe", "searchindexer.exe", "smartscreen.exe", "browser_broker.exe",
    "winlogon.exe", "csrss.exe", "lsass.exe", "services.exe", "smss.exe",
    "node.exe", "bun.exe", "curl.exe", "wget.exe", "python.exe", "pythonw.exe",
    "w3wp.exe", "chrome.exe", "msedge.exe", "firefox.exe", "code.exe",
}
COMMON_CMD_TOKENS = {
    "run", "start", "stop", "open", "close", "true", "false", "null", "none",
    "http", "https", "file", "path", "name", "type", "user", "admin", "system",
    "windows", "microsoft", "program", "files", "temp", "tmp", "appdata",
    "local", "roaming", "users", "public", "cmd", "exe", "dll", "bat", "ps1",
    "-c", "-f", "-w", "/c", "/k", "&&", "||",
}
NOISE_REG = {
    "software\\microsoft\\windows\\currentversion\\explorer\\runmru",
    "microsoft\\terminal server client\\default\\mru",
    "microsoft\\terminal server client\\servers\\",
}


def _vals(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if str(x).strip()]
    return [str(v)] if str(v).strip() else []


def _walk_det(det: Dict) -> List[Tuple[str, List[str], List[str]]]:
    out = []
    for k, v in (det or {}).items():
        kl = str(k).lower()
        if kl == "condition" or kl.startswith("filter"):
            continue
        items = v if isinstance(v, list) else [v]
        for it in items:
            if not isinstance(it, dict):
                continue
            for fk, fv in it.items():
                parts = str(fk).split("|")
                field = parts[0]
                mods = [m.lower() for m in parts[1:]]
                out.append((field, mods, _vals(fv)))
    return out


def _is_regexish(s: str) -> bool:
    return bool(re.search(r"[\[\]\{\}\(\)\|\?\+\*^$]", s))


def _norm_win_path(s: str) -> str:
    s = str(s or "").replace("/", "\\")
    while s.startswith("\\\\"):
        s = s[1:]
    # strip leading wildcards like *\
    while s.startswith("*"):
        s = s[1:]
    return s


def _basename(s: str) -> str:
    s = _norm_win_path(s).rstrip("\\")
    if "\\" in s:
        s = s.rsplit("\\", 1)[-1]
    return s


def _good_needle(s: str, min_len: int = 5) -> bool:
    t = str(s or "").strip().strip('"').strip("'")
    if len(t) < min_len:
        return False
    if t.lower() in COMMON_CMD_TOKENS:
        return False
    if _is_regexish(t) and ("[" in t or "{" in t or t.endswith("$")):
        return False
    return True


def _sid(sigma_id: str, title: str) -> str:
    base = (sigma_id or "").replace("-", "")[:12] or re.sub(r"[^a-zA-Z0-9]+", "", title)[:12] or "x"
    return f"sigma.{base}"


def load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def strip_imported(items: List[Dict]) -> List[Dict]:
    out = []
    for x in items or []:
        if not isinstance(x, dict):
            continue
        if str(x.get("source") or "") == SOURCE_TAG:
            continue
        if str(x.get("id") or "").startswith("sigma."):
            continue
        out.append(x)
    return out


def convert() -> Dict[str, int]:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    buckets = {"process_lolbin", "file_path_ioc", "registry_persist", "driver_ioc"}

    file_rules: List[Dict] = []
    kw_cmds: List[Dict] = []
    reg_rules: List[Dict] = []
    svc_rules: List[Dict] = []
    task_rules: List[Dict] = []

    seen_kw: Set[str] = set()
    seen_file: Set[str] = set()
    seen_reg: Set[str] = set()
    seen_svc: Set[str] = set()
    lines: List[str] = []

    for meta in catalog.get("rules") or []:
        bucket = meta.get("bucket")
        if bucket not in buckets:
            continue
        path = SRC / meta["file"]
        if not path.is_file():
            continue
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        title = str(doc.get("title") or meta.get("title") or path.stem)
        level = str(doc.get("level") or meta.get("level") or "high").lower()
        if level not in ("high", "critical"):
            continue
        sid = _sid(str(doc.get("id") or ""), title)
        det = doc.get("detection") or {}
        fields = _walk_det(det if isinstance(det, dict) else {})

        path_needles: List[str] = []
        name_needles: List[str] = []
        cmd_needles: List[str] = []
        img_needles: List[str] = []
        reg_needles: List[str] = []
        drv_needles: List[str] = []

        for field, mods, vs in fields:
            fl = field.lower()
            for raw in vs:
                s = str(raw).strip().strip('"')
                if not s:
                    continue
                if fl == "targetfilename":
                    if _is_regexish(s):
                        continue
                    ns = _norm_win_path(s)
                    bn = _basename(ns)
                    if "\\" in ns and len(ns) >= 6:
                        # keep distinctive directory/file fragment
                        frag = ns
                        if frag.lower().startswith("c:"):
                            pass
                        path_needles.append(frag)
                    elif bn and "." in bn and _good_needle(bn, 4):
                        name_needles.append(bn)
                elif fl in ("image", "parentimage", "originalfilename"):
                    bn = _basename(_norm_win_path(s)).lower()
                    if not bn.endswith((".exe", ".dll", ".sys", ".com", ".scr")):
                        if "endswith" in mods or fl == "originalfilename":
                            if not bn.endswith(".exe"):
                                bn = bn  # keep
                        else:
                            continue
                    if bn in COMMON_IMAGES:
                        continue
                    if _good_needle(bn, 4):
                        img_needles.append(bn if bn.startswith("\\") or "." in bn else bn)
                        # store without leading slash for contains
                        img_needles.append(bn.lstrip("\\"))
                elif fl in ("commandline", "parentcommandline"):
                    if _good_needle(s, 6):
                        # avoid ultra-generic paths alone
                        sl = s.lower()
                        if sl in ("\\windows\\system32\\", "c:\\windows\\system32\\", "appdata\\local\\temp"):
                            continue
                        cmd_needles.append(s)
                elif fl == "targetobject":
                    if _is_regexish(s):
                        continue
                    ns = _norm_win_path(s)
                    # strip hive prefixes for contains match
                    ns2 = re.sub(r"^(HKLM|HKCU|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\+", "", ns, flags=re.I)
                    if len(ns2) >= 12 and ns2.lower() not in NOISE_REG:
                        reg_needles.append(ns2)
                elif fl == "imageloaded":
                    bn = _basename(_norm_win_path(s))
                    if bn.lower().endswith(".sys") and _good_needle(bn, 4):
                        drv_needles.append(bn)
                    elif _good_needle(bn, 6) and bn.lower().endswith((".dll", ".sys")):
                        drv_needles.append(bn)

        # dedupe lists
        def uniq(xs: List[str]) -> List[str]:
            out = []
            seen = set()
            for x in xs:
                k = x.lower()
                if k in seen:
                    continue
                seen.add(k)
                out.append(x)
            return out

        path_needles = uniq(path_needles)[:8]
        name_needles = uniq(name_needles)[:8]
        cmd_needles = uniq(cmd_needles)[:10]
        img_needles = uniq([x for x in img_needles if x.lower() not in COMMON_IMAGES])[:8]
        reg_needles = uniq(reg_needles)[:8]
        drv_needles = uniq(drv_needles)[:8]

        # ---- files ----
        if bucket == "file_path_ioc" and (path_needles or name_needles):
            for i, frag in enumerate(path_needles[:3] or name_needles[:3]):
                key = frag.lower()
                if key in seen_file:
                    continue
                seen_file.add(key)
                rule = {
                    "id": f"{sid}.f{i}",
                    "name": title[:80],
                    "severity": level,
                    "reason": f"SigmaHQ {level}: {title}",
                    "source": SOURCE_TAG,
                    "enabled": True,
                    "sigStatus": "any",
                }
                if "\\" in frag or frag.lower().startswith("c:"):
                    rule["pathContains"] = frag
                    # guess extensions for exe-ish paths
                    if re.search(r"\.(exe|dll|sys|ps1|vbs|bat|cmd|scr|hta|js)$", frag, re.I):
                        rule["extensions"] = ["." + frag.rsplit(".", 1)[-1].lower()]
                    else:
                        rule["extensions"] = [".exe", ".dll", ".ps1", ".vbs", ".bat", ".scr", ".sys"]
                else:
                    rule["nameContains"] = frag
                file_rules.append(rule)
                lines.append(f"file\t{rule['id']}\t{title}")

        # ---- process → keywords + task ----
        if bucket == "process_lolbin":
            needles = []
            for x in cmd_needles:
                if _good_needle(x, 6):
                    needles.append(x)
            for x in img_needles:
                xl = x.lower().lstrip("\\")
                if xl not in COMMON_IMAGES and _good_needle(xl, 5):
                    needles.append(xl)
            needles = uniq(needles)[:6]
            if needles:
                # keyword entries (one per distinctive needle, capped)
                for n in needles[:4]:
                    nk = n.lower()
                    if nk in seen_kw:
                        continue
                    if nk in COMMON_IMAGES:
                        continue
                    # skip very common substrings
                    if nk in ("appdata\\local\\temp", "users\\public", "programdata\\"):
                        continue
                    seen_kw.add(nk)
                    kw_cmds.append({
                        "needle": n,
                        "title": title[:80],
                        "severity": level,
                        "id": sid,
                        "source": SOURCE_TAG,
                    })
                    lines.append(f"kw\t{sid}\t{n}\t{title}")
                task_rules.append({
                    "id": f"{sid}.task",
                    "name": title[:80],
                    "severity": level,
                    "reason": f"SigmaHQ {level}: {title}",
                    "source": SOURCE_TAG,
                    "portable": "partial",
                    "enabled": True,
                    "commandContainsAny": needles[:6],
                })
                # also useful on startup/registry command fields
                reg_rules.append({
                    "id": f"{sid}.run",
                    "name": title[:80],
                    "severity": level,
                    "reason": f"SigmaHQ {level} (startup/cmd): {title}",
                    "source": SOURCE_TAG,
                    "portable": "partial",
                    "enabled": True,
                    "commandContainsAny": needles[:6],
                })

        # ---- registry ----
        if bucket == "registry_persist" and reg_needles:
            key = "|".join(x.lower() for x in reg_needles[:3])
            if key not in seen_reg:
                seen_reg.add(key)
                reg_rules.append({
                    "id": f"{sid}.reg",
                    "name": title[:80],
                    "severity": level,
                    "reason": f"SigmaHQ {level}: {title}",
                    "source": SOURCE_TAG,
                    "portable": "partial",
                    "enabled": True,
                    "keyContainsAny": reg_needles[:6],
                })
                lines.append(f"reg\t{sid}\t{title}")

        # ---- drivers → services + files ----
        if bucket == "driver_ioc" and (drv_needles or img_needles):
            names = uniq(drv_needles + [x for x in img_needles if x.lower().endswith((".sys", ".dll"))])[:6]
            if names:
                sk = "|".join(x.lower() for x in names)
                if sk not in seen_svc:
                    seen_svc.add(sk)
                    svc_rules.append({
                        "id": f"{sid}.svc",
                        "name": title[:80],
                        "severity": level,
                        "reason": f"SigmaHQ {level}: {title}",
                        "source": SOURCE_TAG,
                        "portable": "yes",
                        "enabled": True,
                        "imagePathContainsAny": names,
                    })
                    for i, bn in enumerate(names[:3]):
                        file_rules.append({
                            "id": f"{sid}.d{i}",
                            "name": f"{title[:60]} · {bn}",
                            "severity": level,
                            "reason": f"SigmaHQ driver IOC: {bn}",
                            "source": SOURCE_TAG,
                            "enabled": True,
                            "sigStatus": "any",
                            "nameContains": bn.lstrip("\\"),
                        })
                    lines.append(f"drv\t{sid}\t{title}")

    # write files
    files_path = RULES / "rules-files.json"
    win_path = RULES / "rules-windows-system.json"
    kw_path = RULES / "rules-keywords.json"

    bak_dir = RULES / ".bak"
    bak_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    for p in (files_path, win_path):
        if p.is_file():
            shutil.copy2(p, bak_dir / f"{p.name}.{stamp}.pre_sigma.bak")

    files = load_json(files_path)
    files["suspiciousRules"] = strip_imported(list(files.get("suspiciousRules") or [])) + file_rules
    save_json(files_path, files)

    win = load_json(win_path)
    win["registryRules"] = strip_imported(list(win.get("registryRules") or [])) + reg_rules
    win["serviceRules"] = strip_imported(list(win.get("serviceRules") or [])) + svc_rules
    win["taskRules"] = strip_imported(list(win.get("taskRules") or [])) + task_rules
    meta = win.get("meta") if isinstance(win.get("meta"), dict) else {}
    meta["sigmaImportedAt"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    meta["sigmaImport"] = {
        "registryRules": len(reg_rules),
        "serviceRules": len(svc_rules),
        "taskRules": len(task_rules),
    }
    win["meta"] = meta
    save_json(win_path, win)

    kw_doc = {
        "meta": {
            "id": "keywords",
            "name": "可疑命令 / 关键字",
            "version": "1.0",
            "description": "内置特征 + SigmaHQ 高危进程/命令行 IOC",
            "source": SOURCE_TAG,
            "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%S"),
        },
        "suspiciousCmds": kw_cmds,
        "builtinPatterns": [],
    }
    if kw_path.is_file():
        old = load_json(kw_path)
        kept = [x for x in (old.get("suspiciousCmds") or []) if isinstance(x, dict) and str(x.get("source") or "") != SOURCE_TAG]
        kw_doc["suspiciousCmds"] = kept + kw_cmds
        if isinstance(old.get("builtinPatterns"), list):
            kw_doc["builtinPatterns"] = old.get("builtinPatterns") or []
    save_json(kw_path, kw_doc)

    MANIFEST.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return {
        "file_rules": len(file_rules),
        "keywords": len(kw_cmds),
        "registry": len(reg_rules),
        "service": len(svc_rules),
        "task": len(task_rules),
        "lines": len(lines),
    }


if __name__ == "__main__":
    stats = convert()
    print(json.dumps(stats, ensure_ascii=False, indent=2))
