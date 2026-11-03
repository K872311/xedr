#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一次性：ES 端点索引 + 发布 EQL 规则元数据 + 可选试跑一轮检测。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.detection_corpus_bootstrap import ensure_detection_corpus, ensure_elasticsearch_edr  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--corpus", action="store_true", help="同时跑全量语料 bootstrap")
    p.add_argument("--run-once", action="store_true", help="试跑一轮 EQL 检测")
    p.add_argument("--max-rules", type=int, default=800)
    args = p.parse_args()
    if args.corpus:
        print(json.dumps(ensure_detection_corpus(force=False), ensure_ascii=False, indent=2))
    out = ensure_elasticsearch_edr(publish_max=args.max_rules, run_once=args.run_once)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
