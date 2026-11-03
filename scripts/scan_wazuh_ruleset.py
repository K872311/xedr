#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描 rules/ruleset/sca 并生成 catalog / Agent SCA bundle。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend import wazuh_ruleset as wr  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--scan", action="store_true", help="写入 rules/published/wazuh-sca-catalog.json")
    p.add_argument("--build-bundle", action="store_true", help="写入 config/agent_sca_bundle.json")
    p.add_argument("--platform", default="", help="空=全部 OS 目录")
    p.add_argument("--policies", default="cis_win10_enterprise,cis_win11_enterprise")
    p.add_argument("--max-checks", type=int, default=0, help="每策略最多检查条数，0=不限")
    args = p.parse_args()
    if args.scan:
        cat = wr.scan_catalog(platform=args.platform)
        path = wr.save_catalog(cat)
        print(json.dumps({"saved": str(path), "stats": cat.get("stats")}, ensure_ascii=False, indent=2))
    if args.build_bundle:
        ids = [x.strip() for x in args.policies.split(",") if x.strip()]
        doc = wr.build_agent_bundle(ids, platform=args.platform, max_checks_per_policy=args.max_checks)
        path = wr.save_agent_bundle(doc)
        n = sum(len(x.get("checks") or []) for x in doc.get("policies") or [])
        print(json.dumps({"saved": str(path), "checks": n}, ensure_ascii=False, indent=2))
    if not args.scan and not args.build_bundle:
        p.print_help()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
