#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""构建 Elastic protections-artifacts 精选包并写入 config/ + agent/memory-yara。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend import protections_import as pi  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Build protections-artifacts curated bundle")
    ap.add_argument("--dry-run", action="store_true", help="只统计不写入")
    ap.add_argument("--min-score", type=int, default=0, help="覆盖 policy 中的 evm.min_score")
    ap.add_argument("--max-evm", type=int, default=0, help="覆盖 policy 中的 evm.max_rules")
    args = ap.parse_args()

    if args.min_score or args.max_evm:
        doc = pi.build_evm_document(
            min_score=args.min_score or None,
            max_rules=args.max_evm or None,
        )
        print(json.dumps({"evm_preview_count": len(doc.get("rules") or []), "sample_ids": doc.get("rule_ids", [])[:10]}, ensure_ascii=False, indent=2))
        if args.dry_run:
            yar = pi.pick_yara_files()
            print(json.dumps({"yara_count": len(yar), "sample": [p.name for p in yar[:10]]}, ensure_ascii=False, indent=2))
            return 0

    out = pi.apply_bundle(write=not args.dry_run, dry_run=args.dry_run)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
