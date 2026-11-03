"""规则解释器：按 JSON 中 type=exact|substring|regex 正确匹配，并支持 directoryRules"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple

from .util import pat_hit, basename, strip_ext


def _dir_fingerprint(directory: str) -> str:
    """与 path_has_directory 相同的目录指纹（小写）。"""
    if not directory:
        return ""
    d = directory.replace("/", "\\").lower()
    for env in ("%appdata%", "%localappdata%", "%programdata%", "%programfiles%",
                "%programfiles(x86)%", "%systemroot%", "%userprofile%"):
        d = d.replace(env, "")
    d = d.strip("\\").replace(".*", "").replace("*", "")
    if not d:
        return ""
    skip = {"users", "appdata", "roaming", "local", "program files", "program files (x86)", "programdata"}
    parts = [x for x in d.split("\\") if x and x not in skip]
    if not parts:
        return ""
    fingerprint = "\\".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
    if len(fingerprint) < 5:
        fingerprint = parts[-1]
        if len(fingerprint) < 5:
            return ""
    return fingerprint.lower()


class FastRmmIndex:
    """RMM 规则快速索引：先用针词/目录指纹过滤，再精匹配。避免 2 万+ 文件 × 全规则正则。"""

    __slots__ = ("rules", "needles", "by_needle", "regexes", "dirs")

    def __init__(self, rules: List[Dict[str, Any]], dir_rules: Optional[List[Dict]] = None):
        self.rules = list(rules or [])
        self.by_needle: Dict[str, List[Dict[str, Any]]] = {}
        self.regexes: List[Tuple[re.Pattern, Dict[str, Any]]] = []
        self.dirs: List[Tuple[str, str, Optional[Dict[str, Any]]]] = []  # fp, tool, rule

        for rule in self.rules:
            tool = rule.get("tool") or "RMM"
            for p in rule.get("patterns") or []:
                pl = strip_ext(str(p)).lower().strip()
                if len(pl) >= 3:
                    self.by_needle.setdefault(pl, []).append(rule)
            for rp in rule.get("regexPatterns") or rule.get("regex") or []:
                try:
                    self.regexes.append((re.compile(str(rp), re.I), rule))
                except re.error:
                    continue
            fp = _dir_fingerprint(rule.get("directory") or "")
            if fp:
                self.dirs.append((fp, tool, rule))

        for dr in dir_rules or []:
            tool = dr.get("tool") or "RMM"
            for pth in dr.get("paths") or []:
                fp = _dir_fingerprint(pth)
                if fp:
                    self.dirs.append((fp, tool, None))

        # 长针优先，减少误触发后的二次匹配次数
        self.needles = sorted(self.by_needle.keys(), key=len, reverse=True)

    def _dir_hit(self, text_l: str) -> Optional[str]:
        padded = "\\" + text_l.replace("/", "\\") + "\\"
        for fp, tool, _rule in self.dirs:
            if ("\\" + fp + "\\") in padded or text_l.endswith("\\" + fp):
                return tool
        return None

    def _candidate_rules(self, text_l: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen: set = set()
        for n in self.needles:
            if n in text_l:
                for rule in self.by_needle[n]:
                    rid = id(rule)
                    if rid not in seen:
                        seen.add(rid)
                        out.append(rule)
        return out

    def match(self, text: str, is_path: bool = False) -> Optional[Dict[str, Any]]:
        if not text:
            return None
        text_l = text.lower()
        for rule in self._candidate_rules(text_l):
            if match_rmm_rule(text, rule, is_path=is_path):
                return rule
        for cre, rule in self.regexes:
            if cre.search(text):
                return rule
        if is_path or "\\" in text or "/" in text:
            tool = self._dir_hit(text_l.replace("/", "\\"))
            if tool:
                return {"tool": tool}
        return None

    def match_file(self, name: str, full: str, exe_like: bool) -> Optional[str]:
        """文件扫描专用：返回 tool 名。非可执行且无针词时只做目录指纹。"""
        full_n = (full or "").replace("/", "\\")
        full_l = full_n.lower()
        name = name or ""
        name_l = name.lower()
        blob = name_l + "|" + full_l
        has_needle = any(n in blob for n in self.needles)

        if not exe_like and not has_needle:
            return self._dir_hit(full_l)

        if exe_like and name:
            for rule in self._candidate_rules(name_l):
                if match_rmm_rule(name, rule):
                    return rule.get("tool") or "RMM"
            for cre, rule in self.regexes:
                if cre.search(name):
                    return rule.get("tool") or "RMM"

        if full_n and (exe_like or has_needle):
            for rule in self._candidate_rules(full_l):
                if not match_rmm_rule(full_n, rule, is_path=True):
                    continue
                tool = rule.get("tool") or "RMM"
                if not exe_like:
                    pats = [str(p).lower() for p in (rule.get("patterns") or [])]
                    soft = bool(pats) and all(
                        (p.endswith((".log", ".txt", ".trace", ".conf", ".config", ".db", ".xml", ".lnk"))
                         or not p.endswith(".exe"))
                        for p in pats
                    )
                    if soft:
                        if rule.get("directory") and path_has_directory(full_n, rule.get("directory")):
                            return tool
                        t0 = tool.lower().replace("/", " ").split()[0]
                        if t0 and (("\\" + t0 + "\\") in full_l):
                            return tool
                        continue
                return tool
            for cre, rule in self.regexes:
                if cre.search(full_n):
                    return rule.get("tool") or "RMM"

        return self._dir_hit(full_l)


def match_pattern(text: str, pattern: str, mtype: str = "substring") -> bool:
    t = text or ""
    p = pattern or ""
    if not t or not p:
        return False
    mt = (mtype or "substring").lower()
    if mt == "exact":
        base = strip_ext(basename(t)).lower()
        target = strip_ext(p).lower()
        return base == target or t.lower() == p.lower()
    if mt == "regex" or mt == "regex_substring":
        try:
            return re.search(p, t, re.I) is not None
        except re.error:
            return pat_hit(t, p)
    # substring / default — 用边界命中，避免短串误报
    return pat_hit(t, p)


def match_any_pattern(text: str, patterns: List[str], mtype: str = "substring") -> Optional[str]:
    for p in patterns or []:
        if match_pattern(text, p, mtype):
            return p
    return None


def match_regex_list(text: str, regexes: List[str]) -> Optional[str]:
    for rp in regexes or []:
        try:
            if re.search(rp, text or "", re.I):
                return rp
        except re.error:
            continue
    return None


def path_has_directory(full: str, directory: str) -> bool:
    if not directory or not full:
        return False
    fl = full.replace("/", "\\").lower()
    fingerprint = _dir_fingerprint(directory)
    if not fingerprint:
        return False
    return ("\\" + fingerprint + "\\") in ("\\" + fl + "\\") or fl.endswith("\\" + fingerprint)


def match_rmm_rule(text: str, rule: Dict[str, Any], is_path: bool = False) -> bool:
    """对单条 RMM 规则做 patterns / regex / directory 匹配"""
    if not text:
        return False
    if match_any_pattern(text, rule.get("patterns") or [], "substring"):
        return True
    if match_regex_list(text, rule.get("regexPatterns") or rule.get("regex") or []):
        return True
    d = rule.get("directory") or ""
    if d and (is_path or "\\" in text or "/" in text):
        if path_has_directory(text, d):
            return True
    return False


def match_named_rule(text: str, rule: Dict[str, Any]) -> bool:
    """cloudStorage / encryption 等单 pattern 规则"""
    if not rule or rule.get("enabled") is False:
        return False
    pat = rule.get("pattern") or ""
    mtype = rule.get("type") or "substring"
    return match_pattern(text, pat, mtype)
