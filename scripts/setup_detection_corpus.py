#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地一次性初始化检测语料（Elastic + Wazuh），无需先起 8100。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.detection_corpus_bootstrap import corpus_status, ensure_detection_corpus  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="初始化 Elastic/Wazuh 检测语料与入门 EVM")
    p.add_argument("--force", action="store_true", help="强制重扫并重导入门规则")
    p.add_argument("--skip-elastic-import", action="store_true")
    p.add_argument("--status", action="store_true", help="仅打印 corpus 状态")
    args = p.parse_args()
    if args.status:
        print(json.dumps(corpus_status(), ensure_ascii=False, indent=2))
        return 0
    out = ensure_detection_corpus(force=args.force, skip_elastic_import=args.skip_elastic_import)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    print(json.dumps(corpus_status(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
