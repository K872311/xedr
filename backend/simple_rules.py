"""简单自定义规则：读写 rules/rules-simple.json（不进业务库）。"""
from __future__ import annotations
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

SIMPLE_FILE = "rules-simple.json"
_SEVERITIES = frozenset({"high", "medium", "low", "critical", "info"})
_SIG_STATUSES = frozenset({"any", "unsigned", "signed", "invalid"})
_SIG_ALIASES = {
    "": "any", "any": "any", "all": "any", "none": "any", "不限": "any",
    "unsigned": "unsigned", "notsigned": "unsigned", "not_signed": "unsigned",
    "missing": "unsigned", "未签名": "unsigned", "无签名": "unsigned",
    "signed": "signed", "valid": "signed", "已签名": "signed",
    "invalid": "invalid", "error": "invalid", "untrusted": "invalid",
    "签名无效": "invalid", "无效": "invalid",
}


def normalize_sig_status(raw: Any) -> str:
    s = str(raw or "").strip().lower().replace(" ", "").replace("-", "")
    return _SIG_ALIASES.get(s, "any" if not s else ("invalid" if s not in _SIG_STATUSES else s))


def simple_path() -> Path:
    return Path(config.RULES_DIR) / SIMPLE_FILE


def _default_doc() -> Dict[str, Any]:
    return {
        "meta": {
            "id": "simple-file-rules",
            "name": "简单自定义规则",
            "version": "1.0",
            "description": "表单创建的路径/扩展名可疑文件规则",
        },
        "suspiciousRules": [],
    }


def load_doc() -> Dict[str, Any]:
    path = simple_path()
    if not path.exists():
        return _default_doc()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return _default_doc()
        if not isinstance(data.get("suspiciousRules"), list):
            data["suspiciousRules"] = []
        if not isinstance(data.get("meta"), dict):
            data["meta"] = _default_doc()["meta"]
        return data
    except Exception as e:
        print(f"[simple_rules] load {path}: {e}")
        return _default_doc()


def _atomic_write(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def save_doc(doc: Dict[str, Any]) -> None:
    _atomic_write(simple_path(), doc)


def normalize_extensions(raw: Any) -> List[str]:
    if raw is None:
        return []
    parts: List[str] = []
    if isinstance(raw, str):
        parts = re.split(r"[,;\s]+", raw.strip())
    elif isinstance(raw, (list, tuple)):
        for x in raw:
            parts.extend(re.split(r"[,;\s]+", str(x).strip()))
    out: List[str] = []
    seen = set()
    for p in parts:
        e = (p or "").strip().lower()
        if not e:
            continue
        if not e.startswith("."):
            e = "." + e
        if e == "." or e in seen:
            continue
        seen.add(e)
        out.append(e)
    return out


def normalize_path_contains(raw: Any) -> str:
    s = str(raw or "").strip().replace("/", "\\")
    if not s:
        return ""
    # 用户填 Public → \Public\，便于命中路径片段
    if "\\" not in s and not s.startswith("."):
        s = "\\" + s + "\\"
    return s


def match_keys() -> tuple:
    """匹配键以 matchers.files 为唯一权威，这里不再自己维护白名单。

    延迟导入：matchers.files → rules_loader，模块级导入会和 rules_loader
    里对 simple_rules 的引用形成环。
    """
    from .matchers.files import FILE_RULE_MATCH_KEYS
    return FILE_RULE_MATCH_KEYS


# 需要按类型规范化的高级键（其余键原样透传）
_PATH_LIST_KEYS = ("pathContainsAny", "pathNotContains")
_RAW_LIST_KEYS = ("pathImmediateUnder",)
_REGEX_KEYS = ("pathRegex", "nameRegex")
_REGEX_LABEL = {"pathRegex": "路径正则", "nameRegex": "文件名正则"}
_ADV_KEYS = _PATH_LIST_KEYS + _RAW_LIST_KEYS + _REGEX_KEYS + ("minSizeMB", "isHidden")


def _split_list(raw: Any) -> List[str]:
    if raw is None:
        return []
    items = raw if isinstance(raw, (list, tuple)) else re.split(r"[,;\n]+", str(raw))
    out: List[str] = []
    seen = set()
    for x in items:
        s = str(x or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def normalize_advanced(data: Dict[str, Any]) -> Dict[str, Any]:
    """规范化高级匹配键；只处理 data 里真正出现的键，缺省不补。"""
    out: Dict[str, Any] = {}
    for k in _PATH_LIST_KEYS:
        if k in data:
            # 与 pathContains 同语义：Public → \Public\
            vals = [normalize_path_contains(x) for x in _split_list(data[k])]
            vals = [v for v in vals if v]
            if vals:
                out[k] = vals
    for k in _RAW_LIST_KEYS:
        if k in data:
            # 与父目录整段比较，不能补首尾反斜杠
            vals = [str(x).strip().replace("/", "\\").rstrip("\\") for x in _split_list(data[k])]
            vals = [v for v in vals if v]
            if vals:
                out[k] = vals
    for k in _REGEX_KEYS:
        if k in data:
            rx = str(data[k] or "").strip()
            if rx:
                try:
                    re.compile(rx)
                except re.error as e:
                    raise ValueError(f"{_REGEX_LABEL[k]}无效: {e}") from e
                out[k] = rx
    if "minSizeMB" in data:
        raw = data["minSizeMB"]
        if raw not in (None, "", 0, "0"):
            try:
                v = float(raw)
            except (TypeError, ValueError) as e:
                raise ValueError("最小体积必须是数字") from e
            if v > 0:
                out["minSizeMB"] = int(v) if v == int(v) else v
    if "isHidden" in data:
        raw = data["isHidden"]
        flag = raw is True or str(raw or "").strip().lower() in ("1", "true", "yes", "on")
        if flag:
            out["isHidden"] = True
    return out


def enabled_rules_for_matcher(doc: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """供 RuleStore 合并：仅启用项，去掉 UI 专用字段后的匹配结构。

    匹配键按 matchers.files.FILE_RULE_MATCH_KEYS 全量透传。原先这里手写了
    pathContains/extensions/nameContains/sigStatus 四项白名单，写进 JSON 的
    pathContainsAny、nameRegex 等键会在合并时被丢掉——规则看着是启用的，
    实际永远不参与判定。
    """
    doc = doc or load_doc()
    keys = match_keys()
    out = []
    for r in doc.get("suspiciousRules") or []:
        if not isinstance(r, dict):
            continue
        if r.get("enabled") is False:
            continue
        item = {
            "name": r.get("name") or "简单规则",
            "severity": r.get("severity") or "medium",
            "reason": r.get("reason") or "",
            "source": "simple",
        }
        if r.get("id"):
            item["id"] = r["id"]
        for k in keys:
            if k == "sigStatus":
                continue
            v = r.get(k)
            if v in (None, "", [], {}, 0, False):
                continue
            item[k] = list(v) if isinstance(v, (list, tuple)) else v
        sig = normalize_sig_status(r.get("sigStatus") or r.get("signature") or r.get("signed"))
        if sig and sig != "any":
            item["sigStatus"] = sig
        out.append(item)
    return out


def list_rules() -> List[Dict[str, Any]]:
    return [dict(r) for r in (load_doc().get("suspiciousRules") or []) if isinstance(r, dict)]


def get_rule(rid: str) -> Optional[Dict[str, Any]]:
    rid = (rid or "").strip()
    for r in list_rules():
        if str(r.get("id") or "") == rid:
            return r
    return None


def _validate_payload(data: Dict[str, Any], *, partial: bool = False) -> Dict[str, Any]:
    name = str(data.get("name") or "").strip()
    if not partial and not name:
        raise ValueError("请填写规则名称")
    path = normalize_path_contains(data.get("pathContains") if "pathContains" in data else data.get("path") or "")
    exts = normalize_extensions(data.get("extensions"))
    if "extensions" not in data and "ext" in data:
        exts = normalize_extensions(data.get("ext"))
    severity = str(data.get("severity") or data.get("level") or "medium").strip().lower()
    if severity not in _SEVERITIES:
        severity = "medium"
    reason = str(data.get("reason") or data.get("description") or "").strip()
    enabled = data.get("enabled")
    if enabled is None:
        enabled = True
    else:
        enabled = bool(enabled) if not isinstance(enabled, str) else enabled.strip().lower() not in ("0", "false", "no", "off")
    name_contains = str(data.get("nameContains") or "").strip()
    sig_raw = data.get("sigStatus") if "sigStatus" in data else data.get("signature", data.get("signed", "any"))
    sig = normalize_sig_status(sig_raw)

    adv = normalize_advanced(data)

    if not partial:
        if not path and not exts and not name_contains and sig == "any" and not adv:
            raise ValueError("请至少填写「路径包含」「扩展名」「文件名」「正则」「体积」或「签名状态」之一")
        if not reason:
            reason = name or "简单规则命中"

    out: Dict[str, Any] = {}
    # 高级键：出现即透传（值为空则显式置空，便于 update 清除）
    for k in _ADV_KEYS:
        if k in adv:
            out[k] = adv[k]
        elif k in data:
            out[k] = None
    if name or not partial:
        out["name"] = name or "简单规则"
    if "pathContains" in data or "path" in data or not partial:
        out["pathContains"] = path
    if "extensions" in data or "ext" in data or not partial:
        out["extensions"] = exts
    if "severity" in data or "level" in data or not partial:
        out["severity"] = severity
    if "reason" in data or "description" in data or not partial:
        out["reason"] = reason
    if "enabled" in data or not partial:
        out["enabled"] = enabled
    if "nameContains" in data:
        out["nameContains"] = name_contains
    if "sigStatus" in data or "signature" in data or "signed" in data or not partial:
        out["sigStatus"] = sig
    return out


def _apply_adv(target: Dict[str, Any], fields: Dict[str, Any]) -> Dict[str, Any]:
    """把校验后的高级键写回规则；None 表示本次要清除该键。"""
    for k in _ADV_KEYS:
        if k not in fields:
            continue
        v = fields[k]
        if v in (None, "", [], False):
            target.pop(k, None)
        else:
            target[k] = v
    return target


def create_rule(data: Dict[str, Any]) -> Dict[str, Any]:
    fields = _validate_payload(data, partial=False)
    rid = str(data.get("id") or "").strip() or ("simple_" + uuid.uuid4().hex[:12])
    now = time.time()
    rule = {
        "id": rid,
        "name": fields["name"],
        "pathContains": fields.get("pathContains") or "",
        "extensions": fields.get("extensions") or [],
        "severity": fields["severity"],
        "reason": fields["reason"],
        "enabled": fields.get("enabled", True),
        "sigStatus": fields.get("sigStatus") or "any",
        "source": "simple",
        "created_at": now,
        "updated_at": now,
    }
    if fields.get("nameContains"):
        rule["nameContains"] = fields["nameContains"]
    _apply_adv(rule, fields)
    doc = load_doc()
    rules = [r for r in (doc.get("suspiciousRules") or []) if isinstance(r, dict)]
    if any(str(r.get("id")) == rid for r in rules):
        raise ValueError(f"规则 id 已存在: {rid}")
    rules.append(rule)
    doc["suspiciousRules"] = rules
    save_doc(doc)
    return rule


def update_rule(rid: str, data: Dict[str, Any]) -> Dict[str, Any]:
    rid = (rid or "").strip()
    if not rid:
        raise ValueError("缺少规则 id")
    doc = load_doc()
    rules = [r for r in (doc.get("suspiciousRules") or []) if isinstance(r, dict)]
    idx = next((i for i, r in enumerate(rules) if str(r.get("id")) == rid), -1)
    if idx < 0:
        raise ValueError("规则不存在")
    cur = dict(rules[idx])
    # 合并后再完整校验
    merged = {
        "name": data.get("name", cur.get("name")),
        "pathContains": data.get("pathContains", data.get("path", cur.get("pathContains"))),
        "extensions": data.get("extensions", data.get("ext", cur.get("extensions"))),
        "severity": data.get("severity", data.get("level", cur.get("severity"))),
        "reason": data.get("reason", data.get("description", cur.get("reason"))),
        "enabled": data.get("enabled", cur.get("enabled", True)),
        "nameContains": data.get("nameContains", cur.get("nameContains", "")),
        "sigStatus": data.get("sigStatus", data.get("signature", cur.get("sigStatus", "any"))),
    }
    # 高级键同样要参与合并，否则改一次名称就把 pathContainsAny / nameRegex 冲掉了
    for k in _ADV_KEYS:
        if k in data:
            merged[k] = data[k]
        elif k in cur:
            merged[k] = cur[k]
    fields = _validate_payload(merged, partial=False)
    cur.update({
        "name": fields["name"],
        "pathContains": fields.get("pathContains") or "",
        "extensions": fields.get("extensions") or [],
        "severity": fields["severity"],
        "reason": fields["reason"],
        "enabled": fields.get("enabled", True),
        "sigStatus": fields.get("sigStatus") or "any",
        "source": "simple",
        "updated_at": time.time(),
    })
    if fields.get("nameContains"):
        cur["nameContains"] = fields["nameContains"]
    elif "nameContains" in cur and not fields.get("nameContains"):
        cur.pop("nameContains", None)
    _apply_adv(cur, fields)
    rules[idx] = cur
    doc["suspiciousRules"] = rules
    save_doc(doc)
    return cur


def delete_rule(rid: str) -> bool:
    rid = (rid or "").strip()
    if not rid:
        raise ValueError("缺少规则 id")
    doc = load_doc()
    rules = [r for r in (doc.get("suspiciousRules") or []) if isinstance(r, dict)]
    new_rules = [r for r in rules if str(r.get("id")) != rid]
    if len(new_rules) == len(rules):
        raise ValueError("规则不存在")
    doc["suspiciousRules"] = new_rules
    save_doc(doc)
    return True


def preview_rule(data: Dict[str, Any]) -> Dict[str, Any]:
    """表单预览：不落盘。"""
    fields = _validate_payload(data, partial=False)
    out = {
        "id": str(data.get("id") or "simple_preview"),
        "name": fields["name"],
        "pathContains": fields.get("pathContains") or "",
        "extensions": fields.get("extensions") or [],
        "severity": fields["severity"],
        "reason": fields["reason"],
        "enabled": fields.get("enabled", True),
        "sigStatus": fields.get("sigStatus") or "any",
        "source": "simple",
    }
    if fields.get("nameContains"):
        out["nameContains"] = fields["nameContains"]
    # 预览必须带上高级键，否则「预览命中 0 条」会被误当成规则写错了
    return _apply_adv(out, fields)
