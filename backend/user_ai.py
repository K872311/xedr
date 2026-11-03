"""每用户大模型配置（支持多套，点选启用）。

为防模型 Key 被共用滥用：调用大模型时只认当前账号自己的「当前启用」配置，
不再回退到全局 ai_config / 环境变量。

存储格式（新）：
{
  "active_id": "p1",
  "profiles": [
    {"id":"p1","name":"...","base_url":"...","model":"...","api_key_enc":"...","timeout":60,"enabled":true}
  ]
}

旧格式（单套无 profiles）读取时自动迁移为一条「默认」配置。
"""
from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

_ID_RX = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")


def _dir() -> Path:
    d = config.CONFIG_DIR / "user_ai"
    d.mkdir(parents=True, exist_ok=True)
    return d


def user_ai_path(user_id: str) -> Path:
    uid = "".join(c for c in str(user_id or "").strip() if c.isalnum() or c in "-_")[:64]
    if not uid:
        raise ValueError("无效用户")
    return _dir() / f"{uid}.json"


def _new_id() -> str:
    return "p" + uuid.uuid4().hex[:10]


def _decode_key(data: Dict[str, Any]) -> str:
    key = str(data.get("api_key") or "").strip()
    enc = str(data.get("api_key_enc") or "").strip()
    if enc:
        try:
            from .platform_store import decrypt_secret
            key = decrypt_secret(enc)
        except Exception:
            key = ""
    return str(key or "").strip()


def _encode_api_key(api_key: str) -> Dict[str, str]:
    key = str(api_key or "").strip()
    if not key:
        return {"api_key_enc": "", "api_key": ""}
    try:
        from .platform_store import encrypt_secret
        return {"api_key_enc": encrypt_secret(key), "api_key": ""}
    except Exception:
        return {"api_key": key, "api_key_enc": ""}


def _normalize_base_url(base_url: str) -> str:
    u = str(base_url or "").strip().rstrip("/") or "https://api.deepseek.com"
    low = u.lower()
    if "api.deepseek.com" in low and "/anthropic" in low:
        return "https://api.deepseek.com"
    return u


def _is_local_or_private_url(base_url: str) -> bool:
    """内网 IP / localhost / 未带公网云域名 → 允许无 Key。"""
    try:
        import ipaddress
        from urllib.parse import urlsplit
        u = urlsplit(_normalize_base_url(base_url))
        host = (u.hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        # 主机名：常见内网后缀
        return host.endswith((".lan", ".intranet", ".corp", ".internal"))


_LOCAL_KEY_PLACEHOLDERS = frozenset({
    "", "local", "none", "null", "-", "ollama", "no-key", "nokey",
})


def _effective_api_key(raw_key: str, base_url: str) -> str:
    """本地/内网无 Key 时用占位，便于标记「已配置」并放行调用。"""
    key = str(raw_key or "").strip()
    if key and key.lower() not in _LOCAL_KEY_PLACEHOLDERS:
        return key
    if _is_local_or_private_url(base_url):
        return "local"
    return key


def _mask(key: str) -> str:
    key = str(key or "")
    if not key:
        return ""
    return ("*" * max(0, len(key) - 4)) + key[-4:]


def _profile_public(p: Dict[str, Any], *, active: bool = False) -> Dict[str, Any]:
    base = str(p.get("base_url") or "")
    key = _decode_key(p)
    eff = _effective_api_key(key, base)
    configured = bool(eff)
    local = _is_local_or_private_url(base)
    masked = ""
    if key and key.lower() not in _LOCAL_KEY_PLACEHOLDERS:
        masked = _mask(key)
    elif configured and local:
        masked = "(内网/本地 · 可无 Key)"
    return {
        "id": str(p.get("id") or ""),
        "name": str(p.get("name") or p.get("model") or "未命名"),
        "base_url": base,
        "model": str(p.get("model") or ""),
        "timeout": float(p.get("timeout") or 60),
        "configured": configured,
        "api_key_masked": masked,
        "active": bool(active),
        "enabled": configured,
        "local": local,
    }


def _legacy_to_doc(data: Dict[str, Any]) -> Dict[str, Any]:
    """旧单套格式 → 多套文档。"""
    pid = "default"
    name = str(data.get("model") or "默认").strip() or "默认"
    profile = {
        "id": pid,
        "name": name,
        "base_url": _normalize_base_url(data.get("base_url") or ""),
        "model": str(data.get("model") or "deepseek-chat").strip(),
        "timeout": float(data.get("timeout") or 60),
        "enabled": bool(_decode_key(data)),
        "api_key_enc": str(data.get("api_key_enc") or ""),
        "api_key": str(data.get("api_key") or ""),
    }
    return {"active_id": pid, "profiles": [profile], "updated_at": int(time.time())}


def _load_raw(user_id: str) -> Dict[str, Any]:
    try:
        p = user_ai_path(user_id)
    except ValueError:
        return {"active_id": "", "profiles": []}
    if not p.exists():
        return {"active_id": "", "profiles": []}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"active_id": "", "profiles": []}
    except Exception:
        return {"active_id": "", "profiles": []}

    if isinstance(data.get("profiles"), list):
        profiles = [x for x in data["profiles"] if isinstance(x, dict) and x.get("id")]
        active = str(data.get("active_id") or "")
        if profiles and active not in {str(x.get("id")) for x in profiles}:
            active = str(profiles[0].get("id") or "")
        return {
            "active_id": active,
            "profiles": profiles,
            "updated_at": data.get("updated_at") or 0,
        }

    # 旧格式：顶层有 base_url / model / api_key*
    if data.get("base_url") or data.get("model") or data.get("api_key") or data.get("api_key_enc"):
        return _legacy_to_doc(data)
    return {"active_id": "", "profiles": []}


def _persist(user_id: str, doc: Dict[str, Any]) -> None:
    p = user_ai_path(user_id)
    profiles_out: List[Dict[str, Any]] = []
    for raw in doc.get("profiles") or []:
        if not isinstance(raw, dict):
            continue
        pid = str(raw.get("id") or "").strip()
        if not pid:
            continue
        enc = _encode_api_key(_decode_key(raw))
        profiles_out.append({
            "id": pid,
            "name": str(raw.get("name") or raw.get("model") or "未命名").strip()[:64],
            "base_url": _normalize_base_url(raw.get("base_url") or ""),
            "model": str(raw.get("model") or "deepseek-chat").strip()[:128],
            "timeout": float(raw.get("timeout") or 60),
            "enabled": bool(_decode_key({**raw, **enc})),
            "api_key_enc": enc.get("api_key_enc") or "",
            # 仅在加密失败时回退明文（与旧逻辑一致）
            "api_key": enc.get("api_key") or "",
        })
    active = str(doc.get("active_id") or "")
    ids = {x["id"] for x in profiles_out}
    if profiles_out and active not in ids:
        active = profiles_out[0]["id"]
    if not profiles_out:
        active = ""
    payload = {
        "active_id": active,
        "profiles": [
            {
                "id": x["id"],
                "name": x["name"],
                "base_url": x["base_url"],
                "model": x["model"],
                "timeout": x["timeout"],
                "enabled": x["enabled"],
                "api_key_enc": x.get("api_key_enc") or "",
                **({"api_key": x["api_key"]} if x.get("api_key") else {}),
            }
            for x in profiles_out
        ],
        "updated_at": int(time.time()),
    }
    with open(p, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    try:
        p.chmod(0o600)
    except OSError:
        pass


def _validate_base(base_url: str) -> None:
    try:
        from .ai.analyzer import validate_ai_base_url
        validate_ai_base_url(base_url)
    except RuntimeError:
        raise
    except Exception as e:
        raise ValueError(f"AI Base URL 校验失败: {e}") from e


def get_user_ai(user_id: str) -> Dict[str, Any]:
    """兼容旧调用方：返回「当前启用」配置（含解密后的 api_key）。"""
    doc = _load_raw(user_id)
    active = _active_profile(doc)
    if not active:
        return {}
    out = dict(active)
    out["api_key"] = _decode_key(active)
    return out


def _active_profile(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    profiles = doc.get("profiles") or []
    if not profiles:
        return None
    aid = str(doc.get("active_id") or "")
    for p in profiles:
        if str(p.get("id")) == aid:
            return p
    return profiles[0]


def public_status(user_id: str) -> Dict[str, Any]:
    doc = _load_raw(user_id)
    profiles = doc.get("profiles") or []
    active = _active_profile(doc)
    active_id = str(doc.get("active_id") or (active or {}).get("id") or "")
    pub_profiles = [
        _profile_public(p, active=(str(p.get("id")) == active_id))
        for p in profiles
    ]
    base = str((active or {}).get("base_url") or "")
    key = _decode_key(active) if active else ""
    eff = _effective_api_key(key, base)
    configured = bool(eff)
    masked = ""
    if key and key.lower() not in _LOCAL_KEY_PLACEHOLDERS:
        masked = _mask(key)
    elif configured and _is_local_or_private_url(base):
        masked = "(内网/本地 · 可无 Key)"
    return {
        "configured": configured,
        "api_key_masked": masked,
        "base_url": base,
        "model": (active or {}).get("model") or "",
        "timeout": float((active or {}).get("timeout") or 60),
        "scope": "user",
        "active_id": active_id,
        "profiles": pub_profiles,
        "profile_count": len(pub_profiles),
        "hint": "支持 DeepSeek / 通义千问 / 内网 OpenAI 兼容网关；多套配置点「使用」切换。",
    }


def save_user_ai(user_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """兼容旧单套保存：写入/更新当前启用配置（无则新建）。"""
    doc = _load_raw(user_id)
    active = _active_profile(doc)
    body = dict(data or {})
    body.setdefault("id", (active or {}).get("id") or "")
    if not body.get("name"):
        body["name"] = str(body.get("model") or (active or {}).get("name") or "默认")
    return upsert_profile(user_id, body, activate=True)


def upsert_profile(
    user_id: str,
    data: Dict[str, Any],
    *,
    activate: bool = False,
) -> Dict[str, Any]:
    """新增或更新一套配置。传空 api_key 表示保留原 Key。"""
    doc = _load_raw(user_id)
    profiles: List[Dict[str, Any]] = list(doc.get("profiles") or [])
    pid = str(data.get("id") or "").strip()
    if pid and not _ID_RX.match(pid):
        raise ValueError("无效配置 ID")
    existing = None
    if pid:
        for p in profiles:
            if str(p.get("id")) == pid:
                existing = p
                break
    if not pid:
        pid = _new_id()

    cur_key = _decode_key(existing) if existing else ""
    api_key = str(data.get("api_key") or "").strip() or cur_key
    base_url = _normalize_base_url(
        data.get("base_url") if data.get("base_url") is not None
        else (existing or {}).get("base_url") or "https://api.deepseek.com"
    )
    model = str(
        data.get("model") if data.get("model") is not None
        else (existing or {}).get("model") or "deepseek-chat"
    ).strip() or "deepseek-chat"
    name = str(
        data.get("name") if data.get("name") is not None
        else (existing or {}).get("name") or model or "未命名"
    ).strip()[:64] or model
    timeout = float(
        data.get("timeout") if data.get("timeout") is not None
        else (existing or {}).get("timeout") or 60
    )

    _validate_base(base_url)
    # 内网本地可无真实 Key；存占位以便「已配置」
    store_key = api_key
    if not store_key and _is_local_or_private_url(base_url):
        store_key = "local"
    if not _effective_api_key(store_key, base_url) and not _is_local_or_private_url(base_url):
        raise ValueError("公网模型需要填写 API Key；内网/本地地址可留空")
    enc = _encode_api_key(store_key)
    row = {
        "id": pid,
        "name": name,
        "base_url": base_url,
        "model": model,
        "timeout": timeout,
        "enabled": bool(_effective_api_key(store_key, base_url)),
        **enc,
    }

    if existing is not None:
        profiles = [row if str(p.get("id")) == pid else p for p in profiles]
    else:
        if len(profiles) >= 20:
            raise ValueError("最多保存 20 套模型配置")
        profiles.append(row)

    active_id = str(doc.get("active_id") or "")
    if activate or not active_id or active_id not in {str(p.get("id")) for p in profiles}:
        active_id = pid

    _persist(user_id, {"active_id": active_id, "profiles": profiles})
    return public_status(user_id)


def activate_profile(user_id: str, profile_id: str) -> Dict[str, Any]:
    doc = _load_raw(user_id)
    pid = str(profile_id or "").strip()
    ids = {str(p.get("id")) for p in (doc.get("profiles") or [])}
    if pid not in ids:
        raise ValueError("配置不存在")
    doc["active_id"] = pid
    _persist(user_id, doc)
    return public_status(user_id)


def delete_profile(user_id: str, profile_id: str) -> Dict[str, Any]:
    doc = _load_raw(user_id)
    pid = str(profile_id or "").strip()
    profiles = [p for p in (doc.get("profiles") or []) if str(p.get("id")) != pid]
    if len(profiles) == len(doc.get("profiles") or []):
        raise ValueError("配置不存在")
    active = str(doc.get("active_id") or "")
    if active == pid:
        active = str(profiles[0].get("id") or "") if profiles else ""
    _persist(user_id, {"active_id": active, "profiles": profiles})
    return public_status(user_id)


def resolve_ai_creds(user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """解析实际调用凭据：仅当前用户「启用中」的个人配置（不回退全局）。"""
    uid = str((user or {}).get("id") or "")
    empty = {
        "api_key": "",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "timeout": 60.0,
        "source": "none",
        "profile_id": "",
        "profile_name": "",
    }
    if not uid:
        return empty
    doc = _load_raw(uid)
    active = _active_profile(doc)
    if not active:
        return empty
    raw_key = _decode_key(active)
    base = _normalize_base_url(active.get("base_url") or empty["base_url"])
    model = str(active.get("model") or empty["model"]).strip()
    timeout = float(active.get("timeout") or empty["timeout"])
    meta = {
        "profile_id": str(active.get("id") or ""),
        "profile_name": str(active.get("name") or model),
    }
    key = _effective_api_key(raw_key, base)
    if not key:
        return {
            **empty,
            "base_url": base,
            "model": model,
            "timeout": timeout,
            **meta,
        }
    return {
        "api_key": key,
        "base_url": base,
        "model": model,
        "timeout": timeout,
        "source": "user",
        **meta,
    }
