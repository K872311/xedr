#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描 rules/**.toml 并生成 catalog / 可选导入 Agent 规则。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend import elastic_detection_import as edi  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Elastic detection-rules 导入工具")
    p.add_argument("--scan", action="store_true", help="全量扫描并写入 published catalog")
    p.add_argument("--platform", default="", help="windows|linux|cross-platform")
    p.add_argument("--max-files", type=int, default=0, help="调试：最多扫描文件数")
    p.add_argument("--import-ids", default="", help="逗号分隔 elastic-xxx 规则 ID")
    p.add_argument("--apply", action="store_true", help="写入 agent-live-rules / elastic_evm_import")
    p.add_argument("--enable", action="store_true", help="导入后默认启用（否则 false）")
    p.add_argument("--mode", default="both", choices=("both", "agent", "evm"))
    args = p.parse_args()

    if args.scan:
        cat = edi.scan_catalog(platform=args.platform, max_files=args.max_files or 0)
        path = edi.save_catalog(cat)
        print(json.dumps({"saved": str(path), "stats": cat.get("stats")}, ensure_ascii=False, indent=2))
        return 0

    ids = [x.strip() for x in args.import_ids.split(",") if x.strip()]
    if not ids:
        p.print_help()
        return 1
    out = edi.import_rules(
        ids,
        enable=bool(args.enable),
        mode=args.mode,
        dry_run=not args.apply,
    )
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
