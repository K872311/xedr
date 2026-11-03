"""可疑文件路径 — rules-files.json（启用 excludePatterns，噪声降级）"""
from __future__ import annotations
import re
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple

from ..models import Finding
from ..rules_loader import RuleStore

NOISE_DOWNGRADE = {"Temp目录可疑文件", "桌面可疑文件", "下载目录可疑文件", "隐藏目录", "大文件"}
# 同一目录被多条 folderRule 命中时用于取最高严重级，避免高危/中危重复输出
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
FOLDER_PE_EXTS = {".exe", ".dll", ".sys", ".bin", ".scr", ".ocx"}
FOLDER_SCAN_EXTS = [".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".bin", ".scr", ".lnk", ".sfx", ".dat"]
FOLDER_PATH_HINTS = [
    "\\appdata\\",
    "\\programdata\\",
    "\\program files",
    "\\startup\\",
    "\\users\\public\\",
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\drivers\\",
]


_MULTI_SEP_RE = re.compile(r"\\+")


def _norm_path(p: str) -> str:
    """统一成单反斜杠小写路径，避免 JSON 双重转义导致 pathContains 失配。"""
    s = (p or "").replace("/", "\\")
    s = _MULTI_SEP_RE.sub(r"\\", s)
    return s.lower()


# 规则里的 pathContains 等字面量来自固定规则集，取值高度重复；
# 文件侧路径每个都不同，缓存无益，所以只在规则侧用。
_norm_rule_path = lru_cache(maxsize=4096)(_norm_path)


def _file_sig_bucket(f: Dict) -> str:
    """signed / unsigned / invalid / unknown — 与采集端 Authenticode Status 对齐。"""
    st = str(f.get("sig_status") or f.get("SigStatus") or "").strip().lower()
    st = st.replace(" ", "").replace("-", "")
    if f.get("signed") is True or st in ("valid", "signed"):
        return "signed"
    if st in ("unchecked", "skipped", "notchecked"):
        return "unknown"
    if st in ("", "-", "notsigned", "unsigned", "missing", "unknown", "none"):
        return "unsigned"
    if f.get("signed") is False and not st:
        return "unsigned"
    return "invalid"


def _file_explicitly_unsigned(f: Dict) -> bool:
    """目录规则 minUnsignedPe 仅计 Authenticode 明确未签；未校验/漏检不计。"""
    if not isinstance(f, dict):
        return False
    if f.get("signed") is True:
        return False
    st = str(f.get("sig_status") or f.get("SigStatus") or "").strip().lower()
    st = st.replace(" ", "").replace("-", "")
    if st in ("valid", "signed") or ("valid" in st and "invalid" not in st):
        return False
    if st in ("unchecked", "skipped", "notchecked", "missing", "unknown", "", "-", "—"):
        return False
    if st in (
        "notsigned", "unsigned", "none", "invalid",
        "hashmismatch", "nottrusted", "untrusted", "bad", "expired",
    ):
        return True
    if f.get("signed") is False and st in ("notsigned", "unsigned"):
        return True
    return False


def _file_text_blob(f: Dict) -> str:
    """脚本/正文候选：采集端 content，或兼容 text/script_text/snippet。"""
    if not isinstance(f, dict):
        return ""
    for k in ("content", "text", "script_text", "snippet"):
        v = f.get(k)
        if isinstance(v, str) and v.strip():
            return v
        if isinstance(v, (bytes, bytearray)) and v:
            try:
                return bytes(v).decode("utf-8", errors="replace")
            except Exception:
                return ""
    return ""


def _content_regex_hit(f: Dict, pattern: str, *, strip_carets: bool = False) -> bool:
    """正文正则；strip_carets 时先去掉 ^（cmd caret 混淆）。无正文则不命中。"""
    raw = _file_text_blob(f)
    if not raw or not pattern:
        return False
    text = raw.replace("^", "") if strip_carets else raw
    try:
        return bool(re.search(str(pattern), text, re.I | re.S))
    except re.error:
        return False


def _looks_camel_product_dir(name: str) -> bool:
    """SogouExe / SetupHelper 类驼峰产品目录名；zGgCAI / 8oGt 仍算随机。"""
    s = str(name or "").strip()
    if not s or any(c.isdigit() for c in s):
        return False
    if not re.match(r"^[A-Za-z]+$", s):
        return False
    # 至少两段可读驼峰：Sogou+Exe、My+Tools
    return bool(re.match(r"^[A-Z][a-z]{2,}(?:[A-Z][a-z]{2,})+$", s))


def _excluded(full: str, excludes: List[str]) -> bool:
    fl = _norm_path(full)
    for ex in excludes or []:
        e = _norm_path(ex.strip())
        if not e:
            continue
        if e.startswith("*."):
            if fl.endswith(e[1:]):
                return True
        elif e in fl:
            return True
    return False


# 唯一权威清单：_file_rule_hit 真正会判定的匹配键。
# 任何「生产规则」的地方（简单规则 CRUD、rules_admin 表单、接口过滤）都必须
# 按这个清单透传，禁止再各自写一份白名单——那样加了新键就会被静默丢掉，
# 规则本身没错但永远不命中，排查成本极高（本仓库已发生过两次）。
FILE_RULE_MATCH_KEYS = (
    "pathContains",
    "path",              # pathContains 的别名
    "pathContainsAny",
    "pathNotContains",
    "pathImmediateUnder",
    "pathRegex",
    "extensions",
    "minSizeMB",
    "nameContains",
    "nameRegex",
    "isHidden",
    "sigStatus",
    "requireUnsigned",
    "requireExplicitUnsigned",
    "signerNotContainsAny",
    "companyNotContainsAny",
    "contentRegex",
    "stripCarets",
)


def _file_rule_hit(f: Dict, sr: Dict, _fl: str | None = None) -> bool:
    """_fl：调用方已算好的规范化路径。同一文件要过几十条规则，
    路径规范化每条重算一次会成为热点（实测 25 条规则 × 3 万文件 = 150 万次 re.sub）。"""
    if sr.get("enabled") is False:
        return False
    full = f.get("full_path") or ""
    fl = _fl if _fl is not None else _norm_path(full)
    name = f.get("name") or ""
    nl = name.lower()
    ext = (f.get("ext") or "").lower()
    if ext and not ext.startswith("."):
        ext = "." + ext
    size = f.get("size") or 0
    checks = 0
    path_hit = str(sr.get("pathContains") or sr.get("path") or "").strip()
    if path_hit:
        checks += 1
        if _norm_rule_path(path_hit) not in fl:
            return False
    path_any = sr.get("pathContainsAny")
    if path_any:
        checks += 1
        ok = False
        for p in path_any if isinstance(path_any, list) else [path_any]:
            if _norm_rule_path(str(p)) in fl:
                ok = True
                break
        if not ok:
            return False
    if "pathNotContains" in sr:
        checks += 1
        needles = sr["pathNotContains"]
        if isinstance(needles, str):
            needles = [needles]
        for n in needles:
            if _norm_rule_path(str(n)) in fl:
                return False
    imm = sr.get("pathImmediateUnder")
    if imm:
        checks += 1
        roots = imm if isinstance(imm, list) else [imm]
        parent = _norm_path(_parent_dir(full))
        ok = False
        for root in roots:
            r = _norm_rule_path(str(root)).rstrip("\\")
            if parent == r:
                ok = True
                break
        if not ok:
            return False
    if "pathRegex" in sr:
        checks += 1
        try:
            if not re.search(str(sr["pathRegex"]), full or "", re.I):
                return False
        except re.error:
            return False
    if "extensions" in sr:
        checks += 1
        exts = [e.lower() if str(e).startswith(".") else "." + str(e).lower() for e in sr.get("extensions", [])]
        if ext not in exts:
            return False
    if "minSizeMB" in sr:
        checks += 1
        if size < sr["minSizeMB"] * 1048576:
            return False
    if "nameContains" in sr:
        checks += 1
        if sr["nameContains"].lower() not in nl:
            return False
    if "nameRegex" in sr:
        checks += 1
        rx = sr["nameRegex"]
        if sr.get("name") == "双扩展名" or "\\.(.*?)\\.(exe|ps1|vbs|bat)" in rx.replace("\\\\", "\\"):
            rx = r"\.(txt|pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|zip|rar|7z|mp3|mp4)\.(exe|ps1|vbs|bat|cmd|scr)$"
        try:
            if not re.search(rx, name, re.I):
                return False
        except re.error:
            return False
    if sr.get("isHidden"):
        checks += 1
        if not name.startswith("."):
            return False
    want_sig = str(sr.get("sigStatus") or "").strip().lower()
    if want_sig and want_sig not in ("any", "none", ""):
        checks += 1
        if _file_sig_bucket(f) != want_sig:
            return False
    if sr.get("requireUnsigned") or sr.get("requireExplicitUnsigned"):
        checks += 1
        if not _file_explicitly_unsigned(f):
            return False
    signer_not = sr.get("signerNotContainsAny") or []
    if signer_not:
        checks += 1
        hay = " ".join(
            str(x or "") for x in (
                f.get("signer"), f.get("Signer"), f.get("company"), f.get("Company"),
            )
        ).lower()
        if any(str(n).lower() in hay for n in signer_not if str(n).strip()):
            return False
    company_not = sr.get("companyNotContainsAny") or []
    if company_not:
        checks += 1
        hay = str(f.get("company") or f.get("Company") or "").lower()
        if any(str(n).lower() in hay for n in company_not if str(n).strip()):
            return False
    if sr.get("underDriversDatRoot") or sr.get("underDropperTreeRoot"):
        checks += 1
        roots = sr.get("_dropper_roots")
        if not isinstance(roots, set):
            roots = set()
        if not _under_dropper_tree(full, roots):
            return False
    crex = str(sr.get("contentRegex") or "").strip()
    if crex:
        checks += 1
        if not _content_regex_hit(f, crex, strip_carets=bool(sr.get("stripCarets"))):
            return False
    return checks > 0


def _parent_dir(full: str) -> str:
    s = (full or "").replace("/", "\\")
    s = re.sub(r"\\+", r"\\", s).rstrip("\\")
    if "\\" not in s:
        return ""
    return s.rsplit("\\", 1)[0]


_DROPPER_SKIP_ROOTS = {
    "windows", "program files", "program files (x86)", "programdata", "users",
    "perflogs", "$recycle.bin", "system volume information", "recovery",
    "documents and settings", "intel", "amd", "nvidia", "msocache",
}
_DROPPER_PE_EXTS = {".exe", ".dll", ".scr", ".bat", ".cmd"}


def build_dropper_tree_roots(files: List[Dict]) -> Set[str]:
    """根据内容识别投放树根（目录名不限 Drivers）：
    1) 含 drivers.dat / drivers.dat.N 的父目录
    2) 盘符根下一级目录中，≥2 个短随机子目录且含 PE
    3) 盘符根\\树根\\短随机\\短随机\\…\\PE（≥2 层连续短随机，如 C:\\bstlog\\lUgtB\\6T8YE\\bV8C\\x.exe）
    """
    roots: Set[str] = set()
    # root_norm -> set(short_subdir)
    pe_subs: Dict[str, Set[str]] = {}
    for f in files or []:
        if not isinstance(f, dict):
            continue
        full = str(f.get("full_path") or "").replace("/", "\\")
        nm = str(f.get("name") or "").strip().lower()
        if nm == "drivers.dat" or nm.startswith("drivers.dat."):
            p = _parent_dir(full)
            if p:
                roots.add(_norm_path(p))
        parts = [p for p in full.split("\\") if p]
        # C: \ Foo \ 8oGt \ SKJ.exe  或  C: \ bstlog \ lUgtB \ 6T8YE \ bV8C \ x.exe
        if len(parts) < 4:
            continue
        drive, top = parts[0], parts[1]
        if len(drive) != 2 or drive[1] != ":":
            continue
        if top.lower() in _DROPPER_SKIP_ROOTS:
            continue
        ext = _file_ext(f)
        if ext not in _DROPPER_PE_EXTS:
            # 也看文件名后缀
            low = nm if nm else parts[-1].lower()
            if not any(low.endswith(e) for e in _DROPPER_PE_EXTS):
                continue
        root = _norm_path(f"{drive}\\{top}")
        mid = parts[2:-1]  # 树根与 PE 之间的目录段
        if not mid:
            continue
        # 连续短随机段（从紧邻树根开始计）
        streak = 0
        for seg in mid:
            if _dir_name_kind_ok(seg, "random_short_alnum_2_8"):
                streak += 1
            else:
                break
        if streak >= 2:
            # 深层嵌套随机链：单条路径即可确认树根
            roots.add(root)
        if _dir_name_kind_ok(mid[0], "random_short_alnum_2_8"):
            pe_subs.setdefault(root, set()).add(mid[0].lower())
    for root, subs in pe_subs.items():
        if len(subs) >= 2:
            roots.add(root)
    return roots


def _under_dropper_tree(full: str, roots: Set[str]) -> bool:
    """文件或其父/祖父目录是否落在投放树根下。"""
    if not roots:
        return False
    pl = _norm_path(full)
    parent = _norm_path(_parent_dir(full))
    grand = _norm_path(_parent_dir(_parent_dir(full)))
    for cand in (pl, parent, grand):
        if cand and cand in roots:
            return True
    # 路径前缀：c:\foo\...
    for r in roots:
        if r and (pl == r or pl.startswith(r + "\\")):
            return True
    return False


def _slim_file(f: Dict) -> Dict:
    """详情弹窗用的精简文件元数据（含哈希，供告警「文件属性」展示）。"""
    out = {
        "name": f.get("name") or "",
        "full_path": (f.get("full_path") or "").replace("/", "\\"),
        "path": f.get("path") or "",
        "ext": f.get("ext") or "",
        "size": f.get("size") or 0,
        "company": f.get("company") or "",
        "product": f.get("product") or "",
        "description": f.get("description") or "",
        "file_version": f.get("file_version") or "",
        "signed": bool(f.get("signed")),
        "signer": f.get("signer") or "",
        "sig_status": f.get("sig_status") or "",
        "sig_type": f.get("sig_type") or "",
        "hidden": bool(f.get("hidden")),
        "system": bool(f.get("system")),
        "magic_hex": f.get("magic_hex") or "",
        "md5": f.get("md5") or f.get("MD5") or "",
        "sha1": f.get("sha1") or f.get("SHA1") or "",
        "sha256": f.get("sha256") or f.get("SHA256") or "",
    }
    # SiPolicy 等：采集端还原的策略 XML / 脚本正文，带到告警详情供应急审阅
    blob = _file_text_blob(f)
    if blob:
        out["content"] = blob[:180_000]
    return out


def _file_ext(f: Dict) -> str:
    ext = (f.get("ext") or "").lower().strip()
    if not ext:
        name = str(f.get("name") or "")
        if "." in name:
            ext = "." + name.rsplit(".", 1)[-1].lower()
        else:
            return ""
    if ext and not ext.startswith("."):
        ext = "." + ext
    return ext


def _dir_name_kind_ok(dirname: str, kind: str) -> bool:
    if not kind:
        return True
    name = dirname or ""
    n = len(name)
    has_upper = any("A" <= c <= "Z" for c in name)
    has_lower = any("a" <= c <= "z" for c in name)
    has_digit = any("0" <= c <= "9" for c in name)
    all_alnum = all(("A" <= c <= "Z") or ("a" <= c <= "z") or ("0" <= c <= "9") for c in name)
    letters_only = all(("A" <= c <= "Z") or ("a" <= c <= "z") for c in name)
    if kind == "random_mixed_alnum_10_30":
        if n < 10 or n > 30 or not all_alnum:
            return False
        return (has_upper and has_lower) or ((has_upper or has_lower) and has_digit)
    if kind == "random_mixed_letters_5_15":
        if n < 5 or n > 15 or not letters_only:
            return False
        return has_upper and has_lower
    if kind == "random_mixed_alnum_4_20":
        if n < 4 or n > 20 or not all_alnum:
            return False
        return has_upper and has_lower
    if kind == "random_short_alnum_2_8":
        # Drivers 投放子目录：7b / 8oGt / 8ST / yeW / eI1N / zGgCAI
        if n < 2 or n > 8 or not all_alnum:
            return False
        # 纯字典短词排除：tmp/bin/src 等常见名
        if name.lower() in {
            "bin", "src", "lib", "tmp", "temp", "log", "logs", "data", "cfg",
            "inc", "dll", "exe", "x86", "x64", "arm", "new", "old", "bak",
        }:
            return False
        # 驼峰产品名（SogouExe / ChromeSetup）不当随机投放目录
        if _looks_camel_product_dir(name):
            return False
        return has_digit or (has_upper and has_lower) or (n <= 4 and (has_upper or has_digit))
    if kind == "random_lower_alnum":
        # 全小写+数字随机串，如 pz1k1po / h7x3mq，4-20 字符
        if n < 4 or n > 20 or not all_alnum or has_upper:
            return False
        return has_lower and has_digit
    if kind == "has_mixed_or_digit":
        if not all(c.isalnum() or c in "_-" for c in name):
            return False
        return (has_upper and has_lower) or has_digit
    return True


def _folder_rule_match(
    parent: str,
    dirname: str,
    members: List[Dict],
    rule: Dict,
    subtree: Optional[Dict[str, int]] = None,
    drivers_dat_roots: Optional[Set[str]] = None,
) -> bool:
    if rule.get("enabled") is False:
        return False
    pl = _norm_path(parent)
    dl = (dirname or "").lower()

    for w in rule.get("whitelistDirNames") or []:
        ww = str(w or "").strip().lower()
        if ww and ww == dl:
            return False

    if rule.get("underDriversDatRoot") or rule.get("underDropperTreeRoot"):
        roots = drivers_dat_roots or set()
        if not _under_dropper_tree(parent, roots):
            return False

    if "parentPathContains" in rule:
        if _norm_path(str(rule["parentPathContains"])) not in pl:
            return False
    if "parentPathContainsAny" in rule:
        ok = False
        for p in rule.get("parentPathContainsAny") or []:
            if _norm_path(str(p)) in pl:
                ok = True
                break
        if not ok:
            return False
    if "parentPathNotContains" in rule:
        needles = rule["parentPathNotContains"]
        if isinstance(needles, str):
            needles = [needles]
        for n in needles:
            if _norm_path(str(n)) in pl:
                return False

    imm = str(rule.get("immediateUnder") or "").strip()
    if imm:
        want = _norm_path(imm).rstrip("\\")
        # 目录本身是 want 的直接子目录：父路径的上一级以 want 结尾
        up = _norm_path(_parent_dir(parent))
        if not (up == want or up.endswith(want)):
            return False

    imm_c = str(rule.get("immediateUnderContains") or "").strip()
    if imm_c:
        want = _norm_path(imm_c).rstrip("\\")
        up = _norm_path(_parent_dir(parent))
        if not (up == want or up.endswith(want)):
            return False

    imm_any = rule.get("immediateUnderContainsAny") or []
    if imm_any:
        # 只校验「基准路径的直接子目录」，不递归匹配更深层级（递归会大幅抬高误报）
        up = _norm_path(_parent_dir(parent))
        ok = False
        for cand in imm_any:
            want = _norm_path(str(cand)).rstrip("\\")
            if want and (up == want or up.endswith(want)):
                ok = True
                break
        if not ok:
            return False

    rx = str(rule.get("dirNameRegex") or "").strip()
    if rx:
        try:
            if not re.search(rx, dirname or "", re.I):
                return False
        except re.error:
            return False

    kind = str(rule.get("dirNameKind") or "").strip()
    if kind and not _dir_name_kind_ok(dirname or "", kind):
        return False

    n = len(members)
    # minFileCount 判「直接子文件」：白加黑捆绑包本身必须摆在这一层。
    if "minFileCount" in rule and n < int(rule.get("minFileCount") or 0):
        return False
    # maxFileCount 判「整棵子树」：只看直接子文件的话，
    # 直接放 3 个文件、子目录里塞几十个的大软件树会被当成小型白加黑目录命中。
    # 拿不到子树统计（无 DB / file_scans 直传）时退回直接子文件数，行为不变。
    sub_files = int((subtree or {}).get("subtree_files") or 0)
    n_eff = max(n, sub_files) if sub_files else n
    if "maxFileCount" in rule and n_eff > int(rule.get("maxFileCount") or 0):
        return False
    if "maxSubtreeFileCount" in rule and sub_files > int(rule.get("maxSubtreeFileCount") or 0):
        return False
    if "maxSubdirCount" in rule:
        subdirs = int((subtree or {}).get("subdirs") or 0)
        if subdirs > int(rule.get("maxSubdirCount") or 0):
            return False

    exts = [_file_ext(f) for f in members]
    ext_set = {e for e in exts if e}

    req_any = rule.get("requireExtsAny") or []
    if req_any:
        need = {(e.lower() if str(e).startswith(".") else "." + str(e).lower()) for e in req_any}
        if not (ext_set & need):
            return False

    req_all = rule.get("requireExtsAll") or []
    if req_all:
        need = {(e.lower() if str(e).startswith(".") else "." + str(e).lower()) for e in req_all}
        if not need.issubset(ext_set):
            return False

    only = rule.get("requireOnlyExts") or []
    if only:
        need = {(e.lower() if str(e).startswith(".") else "." + str(e).lower()) for e in only}
        if not ext_set or not ext_set.issubset(need):
            return False

    min_unsigned = int(rule.get("minUnsignedPe") or 0)
    if min_unsigned > 0:
        unsigned_n = 0
        for f in members:
            ext = _file_ext(f)
            if ext not in FOLDER_PE_EXTS:
                continue
            if _file_explicitly_unsigned(f):
                unsigned_n += 1
        if unsigned_n < min_unsigned:
            return False

    # 指定扩展名必须存在明确未签成员（如 exe+dll 目录要求 dll 未签）
    req_unsigned_exts = rule.get("requireUnsignedExts") or []
    if req_unsigned_exts:
        need = {
            (e.lower() if str(e).startswith(".") else "." + str(e).lower())
            for e in req_unsigned_exts
            if str(e).strip()
        }
        for want_ext in need:
            ok = False
            for f in members:
                if _file_ext(f) != want_ext:
                    continue
                if _file_explicitly_unsigned(f):
                    ok = True
                    break
            if not ok:
                return False

    want_sig = str(rule.get("sigStatus") or "").strip().lower()
    if want_sig and want_sig not in ("any", "none", ""):
        if not any(_file_sig_bucket(f) == want_sig for f in members):
            return False

    req_names = rule.get("requireFileNameAny") or rule.get("requireFileNamesAny") or []
    if req_names:
        member_names = {str(f.get("name") or "").strip().lower() for f in members}
        need = {str(x).strip().lower() for x in req_names if str(x).strip()}
        if not need or not (member_names & need):
            # 也允许 drivers.dat.N
            ok = False
            for mn in member_names:
                for pref in need:
                    if mn == pref or (pref.endswith(".dat") and mn.startswith(pref + ".")):
                        ok = True
                        break
                if ok:
                    break
            if not ok:
                return False

    req_name_rx = str(rule.get("requireFileNameRegex") or "").strip()
    if req_name_rx:
        try:
            rxn = re.compile(req_name_rx, re.I)
        except re.error:
            return False
        if not any(rxn.search(str(f.get("name") or "")) for f in members):
            return False

    # 多个正则均需至少命中一个文件名（AND），用于套件指纹
    req_name_rx_all = rule.get("requireFileNameRegexAll") or []
    if req_name_rx_all:
        names = [str(f.get("name") or "") for f in members]
        for raw in req_name_rx_all:
            pat = str(raw or "").strip()
            if not pat:
                continue
            try:
                rxn = re.compile(pat, re.I)
            except re.error:
                return False
            if not any(rxn.search(nm) for nm in names):
                return False

    # 至少命中一项实质性条件，避免空规则全量误报
    has_cond = any(
        k in rule
        for k in (
            "dirNameRegex", "dirNameKind", "requireExtsAny", "requireExtsAll",
            "requireOnlyExts", "minUnsignedPe", "requireUnsignedExts",
            "immediateUnder", "immediateUnderContains",
            "immediateUnderContainsAny", "maxFileCount",
            "maxSubtreeFileCount", "maxSubdirCount",
            "requireFileNameAny", "requireFileNamesAny", "requireFileNameRegex",
            "requireFileNameRegexAll",
            "underDriversDatRoot", "underDropperTreeRoot",
        )
    )
    return has_cond


def _gather_folder_candidates(report: Dict, rid: str, use_db: bool) -> List[Dict]:
    if not use_db:
        return [f for f in (report.get("file_scans") or []) if isinstance(f, dict)]
    from ..db_store import query_files, query_files_under_dir
    # 第一步：用宽泛 hint 查询发现候选目录集合（小 limit 只为收集 parent 路径）
    candidate_dirs: Set[str] = set()
    for hint in FOLDER_PATH_HINTS:
        try:
            lim = 1200 if "system32" in hint or "syswow64" in hint else 800
            rows = query_files(rid, path_contains=hint, exts=FOLDER_SCAN_EXTS, limit=lim)
        except Exception:
            rows = []
        for f in rows:
            p = _parent_dir(f.get("full_path") or "")
            if p:
                candidate_dirs.add(_norm_path(p))
    # 计划任务/服务/启动项解析路径补充：System32 随机子目录等
    for section in ("scheduled_tasks", "services", "startup_items"):
        for it in report.get(section) or []:
            if not isinstance(it, dict):
                continue
            for k in ("resolved_path", "path", "image_path", "ImagePath", "command"):
                p = str(it.get(k) or "").strip().strip('"')
                if not p or "\\" not in p:
                    continue
                parent = _parent_dir(p.split(" ", 1)[0])
                if not parent:
                    continue
                candidate_dirs.add(_norm_path(parent))
    # 第二步：对每个候选目录用 parent_path_norm 索引精确查全量成员（ORDER BY，无抽签偏差）
    out: List[Dict] = []
    seen: Set[str] = set()
    for dir_norm in candidate_dirs:
        try:
            result = query_files_under_dir(rid, dir_norm, limit=500)
            for f in result.get("items") or []:
                fp = f.get("full_path") or ""
                if not fp or fp in seen:
                    continue
                seen.add(fp)
                out.append(f)
        except Exception:
            pass
    return out


def _run_folder_rules(
    report: Dict,
    store: RuleStore,
    seen: Set[str],
    *,
    use_db: bool,
    rid: str,
) -> Tuple[List[Finding], List[Dict]]:
    rules = [r for r in (store.files.get("folderRules") or []) if isinstance(r, dict) and r.get("enabled") is not False]
    if not rules:
        return [], []
    files = _gather_folder_candidates(report, rid, use_db)
    if not files:
        return [], []

    # 投放树根：drivers.dat 或 ≥2 短随机 PE 子目录（目录名可不叫 Drivers）
    drivers_dat_roots: Set[str] = build_dropper_tree_roots(files)

    groups: Dict[str, List[Dict]] = {}
    for f in files:
        parent = _parent_dir(f.get("full_path") or "")
        if not parent:
            continue
        key = _norm_path(parent)
        if key not in groups:
            groups[key] = []
        # 保留原始大小写路径：用第一条的 parent
        groups[key].append(f)

    # parent 显示路径映射
    parent_disp: Dict[str, str] = {}
    for f in files:
        p = _parent_dir(f.get("full_path") or "")
        if p:
            parent_disp[_norm_path(p)] = p

    # 子树统计：maxFileCount / maxSubtreeFileCount / maxSubdirCount 用它把
    # 「直接 3 个文件 + 子目录几十个」的大软件树排除掉。无 DB 时为空 dict，规则退回旧口径。
    subtree_stats: Dict[str, Dict[str, int]] = {}
    if use_db and groups:
        try:
            from ..db_store import query_dir_subtree_stats
            subtree_stats = query_dir_subtree_stats(rid, list(groups.keys())) or {}
        except Exception as e:
            print(f"[files] subtree stats unavailable: {e}")
            subtree_stats = {}

    findings: List[Finding] = []
    matched: List[Dict] = []
    per_rule_cap = 30
    rule_counts: Dict[str, int] = {}

    for key, members in groups.items():
        parent = parent_disp.get(key) or key
        dirname = parent.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
        names = []
        for f in members[:12]:
            names.append(str(f.get("name") or ""))
        name_blob = ", ".join([x for x in names if x])
        if len(members) > 12:
            name_blob += f" …等{len(members)}个"

        # 同一目录可能同时命中「专用规则」和「通用规则」（如 AppData\Local 白加黑
        # 与通用未签名 PE），只保留严重级最高、分数最高的一条，避免同一路径在
        # 高危/中危里重复输出。
        # db_store 的归一化会去掉末尾反斜杠，这里 key 来自 _parent_dir 也已 rstrip，可直接对齐
        st = subtree_stats.get(key) or subtree_stats.get(key.rstrip("\\"))
        hits = [
            r for r in rules
            if _folder_rule_match(parent, dirname, members, r, st, drivers_dat_roots=drivers_dat_roots)
        ]
        if not hits:
            continue
        hits.sort(key=lambda r: (
            _SEV_RANK.get(str(r.get("severity") or "medium").lower(), 2),
            int(r.get("score") or 0),
        ), reverse=True)

        for rule in hits[:1]:
            rname = str(rule.get("name") or "可疑目录")
            if rule_counts.get(rname, 0) >= per_rule_cap:
                continue
            # 键不含规则名：同一目录只出一条目录聚合告警
            sk = f"可疑目录|{parent}|目录聚合"
            if sk in seen:
                continue
            seen.add(sk)
            rule_counts[rname] = rule_counts.get(rname, 0) + 1
            sev = rule.get("severity") or "medium"
            reason = rule.get("reason") or ""
            detail = f"{parent} — {reason}"
            if name_blob:
                detail += f"（文件: {name_blob}）"
            matched.append({"name": rname, "path": parent, "reason": reason, "files": len(members)})
            members_slim = [_slim_file(f) for f in members[:120]]
            extra = {
                "kind": "folder",
                "path": parent,
                "file_count": len(members),
                "members": members_slim,
                "members_truncated": len(members) > len(members_slim),
            }
            if st:
                extra["subtree_files"] = int(st.get("subtree_files") or 0)
                extra["subdir_count"] = int(st.get("subdirs") or 0)
            findings.append(Finding(
                "可疑目录", sev, rname, detail, "目录聚合", rname, "files",
                extra=extra,
            ))
    return findings, matched


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    matched_files: List[Dict] = []
    sus_rules = store.files.get("suspiciousRules") or []
    excludes = [str(x).strip().lower() for x in (store.files.get("excludePatterns") or []) if str(x).strip()]
    # 预编译规则，避免每文件重复处理扩展名/正则
    compiled = []
    for sr in sus_rules:
        if sr.get("enabled") is False:
            continue
        item = dict(sr)
        path_raw = item.get("pathContains") or item.get("path")
        if path_raw:
            item["_path"] = _norm_path(str(path_raw))
        if "pathContainsAny" in item:
            raw = item["pathContainsAny"]
            if isinstance(raw, str):
                raw = [raw]
            item["_path_any"] = [_norm_path(str(x)) for x in raw if str(x).strip()]
        if "pathNotContains" in item:
            raw = item["pathNotContains"]
            if isinstance(raw, str):
                raw = [raw]
            item["_path_not"] = [_norm_path(str(x)) for x in raw if str(x).strip()]
        if "pathImmediateUnder" in item:
            raw = item["pathImmediateUnder"]
            if isinstance(raw, str):
                raw = [raw]
            item["_imm"] = [_norm_path(str(x)).rstrip("\\") for x in raw if str(x).strip()]
        if "pathRegex" in item:
            try:
                item["_path_rx"] = re.compile(str(item["pathRegex"]), re.I)
            except re.error:
                item["_path_rx"] = None
        if "extensions" in item:
            item["_exts"] = {
                (e.lower() if str(e).startswith(".") else "." + str(e).lower())
                for e in item.get("extensions", [])
            }
        if "nameContains" in item:
            item["_name"] = str(item["nameContains"]).lower()
        sig = str(item.get("sigStatus") or "").strip().lower()
        if sig and sig not in ("any", "none", ""):
            item["_sig"] = sig
        if "nameRegex" in item:
            rx = item["nameRegex"]
            if item.get("name") == "双扩展名" or "\\.(.*?)\\.(exe|ps1|vbs|bat)" in str(rx).replace("\\\\", "\\"):
                rx = r"\.(txt|pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|zip|rar|7z|mp3|mp4)\.(exe|ps1|vbs|bat|cmd|scr)$"
            try:
                item["_rx"] = re.compile(rx, re.I)
            except re.error:
                item["_rx"] = None
        crex = str(item.get("contentRegex") or "").strip()
        if crex:
            try:
                item["_content_rx"] = re.compile(crex, re.I | re.S)
            except re.error:
                item["_content_rx"] = None
        compiled.append(item)

    per_rule_cap = 80
    rule_counts: Dict[str, int] = {}

    def excluded(fl: str) -> bool:
        for e in excludes:
            ee = _norm_path(e)
            if ee.startswith("*."):
                if fl.endswith(ee[1:]):
                    return True
            elif ee and ee in fl:
                return True
        return False

    def hit(f: Dict, sr: Dict) -> bool:
        full = f.get("full_path") or ""
        fl = _norm_path(full)
        name = f.get("name") or ""
        nl = name.lower()
        ext = (f.get("ext") or "").lower()
        if ext and not ext.startswith("."):
            ext = "." + ext
        size = f.get("size") or 0
        checks = 0
        if "_path" in sr:
            checks += 1
            if sr["_path"] not in fl:
                return False
        if "_path_any" in sr:
            checks += 1
            if not any(p in fl for p in sr["_path_any"]):
                return False
        if "_path_not" in sr:
            checks += 1
            for n in sr["_path_not"]:
                if n in fl:
                    return False
        if "_imm" in sr:
            checks += 1
            parent = _norm_path(_parent_dir(full))
            if parent not in sr["_imm"]:
                return False
        if "_path_rx" in sr:
            checks += 1
            rx = sr.get("_path_rx")
            if not rx or not rx.search(full or ""):
                return False
        if "_exts" in sr:
            checks += 1
            if ext not in sr["_exts"]:
                return False
        if "minSizeMB" in sr:
            checks += 1
            if size < sr["minSizeMB"] * 1048576:
                return False
        if "_name" in sr:
            checks += 1
            if sr["_name"] not in nl:
                return False
        if "nameRegex" in sr:
            checks += 1
            rx = sr.get("_rx")
            if not rx or not rx.search(name):
                return False
        if sr.get("isHidden"):
            checks += 1
            if not name.startswith("."):
                return False
        want_sig = sr.get("_sig") or ""
        if want_sig:
            checks += 1
            if _file_sig_bucket(f) != want_sig:
                return False
        if sr.get("requireUnsigned") or sr.get("requireExplicitUnsigned"):
            checks += 1
            if not _file_explicitly_unsigned(f):
                return False
        signer_not = sr.get("signerNotContainsAny") or []
        if signer_not:
            checks += 1
            hay = " ".join(
                str(x or "") for x in (f.get("signer"), f.get("Signer"), f.get("company"), f.get("Company"))
            ).lower()
            if any(str(n).lower() in hay for n in signer_not if str(n).strip()):
                return False
        company_not = sr.get("companyNotContainsAny") or []
        if company_not:
            checks += 1
            hay = str(f.get("company") or f.get("Company") or "").lower()
            if any(str(n).lower() in hay for n in company_not if str(n).strip()):
                return False
        if sr.get("underDriversDatRoot") or sr.get("underDropperTreeRoot"):
            checks += 1
            if not _under_dropper_tree(full, sr.get("_dropper_roots") or set()):
                return False
        if "_content_rx" in sr or sr.get("contentRegex"):
            checks += 1
            rx = sr.get("_content_rx")
            blob = _file_text_blob(f)
            if not blob:
                return False
            if sr.get("stripCarets"):
                blob = blob.replace("^", "")
            if rx is not None:
                if not rx.search(blob):
                    return False
            elif not _content_regex_hit(f, str(sr.get("contentRegex") or ""), strip_carets=bool(sr.get("stripCarets"))):
                return False
        return checks > 0

    def add_hit(f: Dict, sr: Dict) -> bool:
        name = sr.get("name") or "可疑路径"
        if rule_counts.get(name, 0) >= per_rule_cap:
            return False
        full = (f.get("full_path") or "").replace("/", "\\")
        full = re.sub(r"\\+", r"\\", full)
        if excluded(_norm_path(full)):
            return False
        if not hit(f, sr):
            return False
        sev = sr.get("severity", "medium")
        if name in NOISE_DOWNGRADE:
            sev = "low"
        key = f"可疑文件|{name}|{full}|文件扫描"
        if key in seen:
            return False
        seen.add(key)
        rule_counts[name] = rule_counts.get(name, 0) + 1
        matched_files.append({"name": name, "path": full, "reason": sr.get("reason")})
        evidence = f"{full} — {sr.get('reason', '')}"
        # SiPolicy：把还原摘要/XML 前缀挂进证据，应急不用另下脚本
        if str(sr.get("id") or "") == "file.apt.sipolicy_wdac_kill" or (
            "sipolicy" in full.lower() and "codeintegrity" in full.lower()
        ):
            desc = str(f.get("description") or "").strip()
            blob = _file_text_blob(f)
            if desc:
                evidence = f"{evidence}\n{desc}"
            if blob:
                preview = blob if len(blob) <= 6000 else (blob[:6000] + "\n…(详见文件详情「策略内容」)")
                evidence = f"{evidence}\n\n{preview}"
        findings.append(Finding(
            "可疑文件", sev, name,
            evidence, "文件扫描", name, "files",
            extra={
                "kind": "file",
                "path": full,
                "file": _slim_file(f),
                "file_count": 1,
            },
        ))
        return True

    from ..db_store import files_rid, query_files, query_files_under_dir
    rid = files_rid(report)
    scans = report.get("file_scans") or []
    use_db = bool(rid) and (report.get("_files_ingested") or not scans)

    # 投放树根（按内容，不按目录名）注入需 underDriversDatRoot 的规则
    root_src: List[Dict] = [f for f in scans if isinstance(f, dict)]
    if use_db and rid:
        try:
            root_src = root_src + list(query_files(rid, name_contains="drivers.dat", limit=300) or [])
            root_src = root_src + list(query_files(rid, path_contains="\\", exts=list(_DROPPER_PE_EXTS), limit=4000) or [])
        except Exception:
            pass
    dropper_roots = build_dropper_tree_roots(root_src)
    for sr in compiled:
        if sr.get("underDriversDatRoot") or sr.get("underDropperTreeRoot"):
            sr["_dropper_roots"] = dropper_roots

    if use_db:
        for sr in compiled:
            name = sr.get("name") or "可疑路径"
            kw: Dict = {"limit": per_rule_cap * 4}
            rows: List[Dict] = []
            # 直接子目录规则：走 parent_path_norm，避免 \\Windows\\ + .sys 被海量 Drivers 挤掉
            if sr.get("_imm") and rid:
                want_exts = {e.lower() for e in (sr.get("_exts") or [])}
                for imm in sr["_imm"]:
                    try:
                        got = query_files_under_dir(rid, imm, limit=500) or {}
                    except Exception:
                        got = {}
                    for f in got.get("items") or []:
                        if not isinstance(f, dict):
                            continue
                        if want_exts:
                            ext = str(f.get("ext") or "").lower()
                            if ext and not ext.startswith("."):
                                ext = "." + ext
                            if not ext:
                                nm = str(f.get("name") or "").lower()
                                ext = ("." + nm.rsplit(".", 1)[-1]) if "." in nm else ""
                            if ext not in want_exts:
                                continue
                        rows.append(f)
            else:
                if sr.get("_exts"):
                    kw["exts"] = list(sr["_exts"])
                if sr.get("_path"):
                    kw["path_contains"] = sr["_path"]
                elif sr.get("_path_any"):
                    kw["path_contains"] = sr["_path_any"][0]
                elif sr.get("_path_rx"):
                    # pathRegex 规则若无 pathContains，从正则抽出字面路径片段做预过滤，
                    # 避免仅按扩展名 limit 截断后漏掉 Temp\.cfg 等稀疏命中。
                    rx_src = str(sr.get("pathRegex") or "")
                    lit = re.findall(
                        r"(?i)\\+(temp|appdata|programdata|users\\public|windows\\temp|windows\\system32\\drivers|windows)\\+",
                        rx_src.replace("\\\\", "\\"),
                    )
                    if lit:
                        kw["path_contains"] = "\\" + lit[0] + "\\"
                if sr.get("_name"):
                    kw["name_contains"] = sr["_name"]
                if "minSizeMB" in sr:
                    kw["min_size"] = int(sr.get("minSizeMB") or 0) * 1048576
                # 仅双扩展类规则用 %.%.%；纯 nameRegex（如 chromestp.exe）不能套双扩展预过滤
                if not kw.get("exts") and not kw.get("path_contains") and not kw.get("name_contains"):
                    rname = str(sr.get("name") or "")
                    if "双扩展" in rname:
                        kw["name_like"] = "%.%.%"
                    elif sr.get("_rx") or sr.get("_path_rx"):
                        # 从正则尽量抽出扩展名，缩小候选；否则放宽 name_like
                        rx_src = str(sr.get("nameRegex") or sr.get("pathRegex") or "")
                        exts_from_rx = re.findall(r"\.(exe|dll|sys|ps1|vbs|bat|cmd|scr|lnk|iso|vhd|vhdx)\b", rx_src, re.I)
                        if exts_from_rx:
                            kw["exts"] = ["." + e.lower() for e in sorted(set(exts_from_rx))]
                        else:
                            kw["name_like"] = "%.%"
                # pathRegex / Drivers 稀疏命中：提高候选上限
                if (sr.get("_path_rx") or "\\drivers\\" in str(kw.get("path_contains") or "").lower()) and kw.get("path_contains"):
                    kw["limit"] = max(int(kw.get("limit") or 0), 2000)
                try:
                    rows = list(query_files(rid, **kw) or [])
                except Exception:
                    rows = []
            for f in rows:
                if rule_counts.get(name, 0) >= per_rule_cap:
                    break
                add_hit(f, sr)
    else:
        for f in scans:
            fl = _norm_path(f.get("full_path") or "")
            if excluded(fl):
                continue
            for sr in compiled:
                name = sr.get("name") or "可疑路径"
                if rule_counts.get(name, 0) >= per_rule_cap:
                    continue
                if add_hit(f, sr):
                    break
            if compiled and all(
                rule_counts.get(sr.get("name") or "可疑路径", 0) >= per_rule_cap for sr in compiled
            ):
                break

    folder_findings, matched_folders = _run_folder_rules(
        report, store, seen, use_db=use_db, rid=rid,
    )
    findings.extend(folder_findings)
    return findings, {"matched_files": matched_files, "matched_folders": matched_folders}
