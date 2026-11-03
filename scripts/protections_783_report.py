#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""783 条 protections 行为规则 → Agent 可落地覆盖率报告。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend import protections_import as pi  # noqa: E402


def main() -> int:
    cat = pi.scan_behavior_catalog()
    stats = cat.get("stats") or {}
    evm = pi.build_evm_document()
    api = pi.build_api_rules_document()
    ptm = pi.build_ptm_from_sequences(max_rules=999)
    lib = pi.build_library_evm_rules(max_rules=999)

    evm_rules = evm.get("rules") or []
    evm_lib = len([r for r in evm_rules if r.get("etype") == "image_load_etw"])
    evm_file = len([r for r in evm_rules if r.get("etype") == "file_create"])
    evm_proc = len([r for r in evm_rules if r.get("etype") in ("process_create", "registry_set")])
    evm_signed = len([r for r in evm_rules if r.get("signed_filter") == "unsigned"])
    api_call = len([r for r in api.get("rules") or [] if r.get("kind") == "api_call"])
    amsi = len([r for r in api.get("rules") or [] if r.get("kind") == "amsi_buffer"])

    yar = pi.pick_yara_files()

    report = {
        "behavior_toml_total": stats.get("total"),
        "catalog_evm_candidates_ge50": stats.get("scored_ok"),
        "catalog_reference": stats.get("reference"),
        "deployed": {
            "yara_files": len(yar),
            "evm_process_registry": evm_proc,
            "evm_image_load_library": evm_lib,
            "evm_file_create": evm_file,
            "evm_unsigned_filter": evm_signed,
            "evm_total": len(evm_rules),
            "api_rules_total": len(api.get("rules") or []),
            "api_call": api_call,
            "amsi_buffer": amsi,
            "ptm_sequences_importable": len(ptm),
            "library_toml_importable_standalone": len(lib),
        },
        "notes": [
            "783 为 Defend EQL，不能原样在 Agent 执行；上表为精选/transpile 后可 sync 的条数。",
            "reference 条目仍可在 protections-behavior-catalog.json 中检索与狩猎。",
        ],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
