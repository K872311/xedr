"""RMM / 兴趣程序 — 已下线（误报高）。保留空实现以免旧调用报错。"""
from __future__ import annotations
from typing import Dict, List, Set, Tuple

from ..models import Finding
from ..rules_loader import RuleStore


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    return [], {"matched_rmm": [], "matched_suspicious": [], "matched_encryption": [], "matched_files": []}
