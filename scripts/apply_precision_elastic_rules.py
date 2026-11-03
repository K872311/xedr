#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""重写 elastic_evm_import.json 为高精准子集，并清理 agent-live-rules 中的 Elastic 快照规则。"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend import elastic_precision as ep  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Apply high-precision Elastic EVM rules")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--disable", action="store_true", help="写入规则但默认 enabled=false")
    args = p.parse_args()
    enabled = not args.disable
    doc = ep.build_precision_evm_document(enabled=enabled)
    print(f"precision rules: {len(doc.get('rules') or [])}")
    for r in doc.get("rules") or []:
        print(f"  - {r.get('id')} score={r.get('precision_score')} {r.get('title', '')[:50]}")
    if args.dry_run:
        return 0
    out = ep.apply_precision_evm(enabled=enabled, write=True)
    pr = ep.prune_agent_live_elastic(write=True)
    print("evm written:", out)
    print("agent-live elastic removed:", pr.get("removed"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
