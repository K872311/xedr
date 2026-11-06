# -*- coding: utf-8 -*-
"""Import high-severity eventlog Sigma candidates into log_rules/rules (one rule per file)."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = Path(r"D:\360极速浏览器X下载\sigma_all_rules")
DST = ROOT / "log_rules" / "rules"
CANDS = ROOT / "sigma_high_priority" / "eventlog_candidates.txt"
MANIFEST = ROOT / "sigma_high_priority" / "imported_eventlog.txt"


def main() -> int:
    cands = [x.strip() for x in CANDS.read_text(encoding="utf-8").splitlines() if x.strip()]
    DST.mkdir(parents=True, exist_ok=True)

    old = list(DST.glob("SigmaHQ_*.yml"))
    for p in old:
        p.unlink()

    copied = []
    skipped = []
    errors = []
    used = {p.name.lower() for p in DST.glob("*.yml")} | {p.name.lower() for p in DST.glob("*.yaml")}

    for rel in cands:
        sp = SRC_ROOT / rel
        if not sp.is_file():
            skipped.append((rel, "missing"))
            continue
        try:
            doc = yaml.safe_load(sp.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            errors.append((rel, str(e)))
            continue
        if not isinstance(doc, dict):
            skipped.append((rel, "not_dict"))
            continue
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", sp.stem)
        name = f"SigmaHQ_{stem}.yml"
        if name.lower() in used:
            rid = str(doc.get("id") or "")[:8]
            name = f"SigmaHQ_{stem}_{rid}.yml"
        level = doc.get("level")
        rid = doc.get("id")
        header = f"# imported from sigma_all_rules/{rel}\n# level={level} id={rid}\n"
        raw = sp.read_text(encoding="utf-8", errors="replace")
        (DST / name).write_text(header + raw, encoding="utf-8")
        used.add(name.lower())
        copied.append(f"{name}\t{rel}")

    MANIFEST.write_text("\n".join(copied) + ("\n" if copied else ""), encoding="utf-8")
    print("copied", len(copied), "skipped", len(skipped), "errors", len(errors), "removed_old", len(old))
    if skipped[:5]:
        print("skip sample", skipped[:5])
    if errors[:5]:
        print("err sample", errors[:5])

    sys.path.insert(0, str(ROOT))
    from backend.eventlog_rules import reload_eventlog_rules

    pack = reload_eventlog_rules()
    print("loaded", pack.get("count"), "errors", pack.get("errors"))
    sh = sum(1 for r in pack["rules"] if "SigmaHQ_" in str(r.get("path") or ""))
    print("SigmaHQ_in_compiled", sh)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
