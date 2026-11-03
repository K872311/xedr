"""规则家族：发布文件名 / 版本名 与分析入口规范名对齐。

分析管线认的是不带版本后缀的规范名（如 rules-linux-process.json）。
后台发布经常落成 rules-linux-process-v2.2.json 这类变体。
发布时写规范别名，加载时再按家族兜底版本后缀。
"""
from __future__ import annotations

from typing import List, Tuple

WINDOWS_SYSTEM_CANONICAL = "rules-windows-system.json"
WINDOWS_SYSTEM_ALIASES: Tuple[str, ...] = (
    "rules-windows-system.json",
    "rules-windows-system-v3.json",
)

LINUX_PACK_CANONICAL: Tuple[str, ...] = (
    "rules-linux-system.json",
    "rules-linux-sigma.json",
    "rules-linux-signatures.json",
    "rules-linux-process.json",
    "rules-linux-network.json",
    "rules-linux-kernel.json",
    "rules-linux-persistence.json",
    "rules-linux-0707.json",
    "rules-tools_rules.json",
)

_VERSION_SUFFIXES: Tuple[str, ...] = ("-v3", "-v2.2", "-v2")


def _stem(name: str) -> str:
    n = str(name or "").strip().replace("\\", "/").split("/")[-1]
    if n.endswith(".json"):
        return n[:-5]
    return n


def _families() -> List[Tuple[str, str]]:
    rows = [(WINDOWS_SYSTEM_CANONICAL, "rules-windows-system")]
    for canon in LINUX_PACK_CANONICAL:
        rows.append((canon, _stem(canon)))
    rows.sort(key=lambda x: len(x[1]), reverse=True)
    return rows


# 磁盘实名 → 管线规范名（persist-backdoor 即 persistence 包）
_LINUX_FILE_ALIASES = {
    "rules-linux-persist-backdoor.json": "rules-linux-persistence.json",
}


def canonical_for(name: str) -> str:
    n = str(name or "").strip().replace("\\", "/").split("/")[-1]
    if n in _LINUX_FILE_ALIASES:
        return _LINUX_FILE_ALIASES[n]
    stem = _stem(name)
    if not stem.startswith("rules-"):
        return ""
    for canon, prefix in _families():
        if stem == prefix or stem.startswith(prefix + "-"):
            return canon
    return ""


def is_windows_system_family(name: str) -> bool:
    return canonical_for(name) == WINDOWS_SYSTEM_CANONICAL


def publish_aliases(name: str) -> List[str]:
    """发布源文件之外，还要落到分析入口认的规范名。"""
    n = str(name or "").strip().replace("\\", "/").split("/")[-1]
    canon = canonical_for(n)
    if not canon:
        return []
    if canon == WINDOWS_SYSTEM_CANONICAL:
        aliases = list(WINDOWS_SYSTEM_ALIASES)
    else:
        aliases = [canon]
    return [a for a in aliases if a != n]


def versioned_filenames(name: str) -> List[str]:
    """加载器在规范名之外继续尝试的版本文件名。"""
    canon = canonical_for(name) or str(name or "").strip().replace("\\", "/").split("/")[-1]
    if not canon.endswith(".json"):
        return []
    stem = canon[:-5]
    out: List[str] = []
    for suf in _VERSION_SUFFIXES:
        cand = f"{stem}{suf}.json"
        if cand not in out and cand != canon:
            out.append(cand)
    return out
