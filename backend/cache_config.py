"""Redis / Elasticsearch / 配置文件路径。

优先级：环境变量 > platform_settings.json 的 cfg_* > 默认（config/ 优先，根目录旧文件回退）。
Redis/ES 可独立文件；未指定且文件不存在时，仍读 db_config.json 内嵌块。
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from . import config

_redis_cfg: Optional[Dict[str, Any]] = None
_es_cfg: Optional[Dict[str, Any]] = None
_paths_cache: Optional[Dict[str, Any]] = None

_ENV = {
    "db": "FORENSIC_DB_CONFIG",
    "redis": "FORENSIC_REDIS_CONFIG",
    "es": "FORENSIC_ES_CONFIG",
    "ai": "FORENSIC_AI_CONFIG",
}
_SETTING_KEY = {
    "db": "cfg_db",
    "redis": "cfg_redis",
    "es": "cfg_es",
    "ai": "cfg_ai",
}
_DEFAULT_NAME = {
    "db": "db_config.json",
    "redis": "redis_config.json",
    "es": "es_config.json",
    "ai": "ai_config.json",
}


def _read_platform_settings() -> Dict[str, Any]:
    p = config.resolve_config_file("platform_settings.json")
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _resolve_one(key: str, raw: str, default: Path) -> Path:
    s = (raw or "").strip()
    if not s:
        return default
    p = Path(s)
    if not p.is_absolute():
        # 仅文件名：走 config/ 优先 + 旧根回退
        if len(p.parts) == 1:
            return config.resolve_config_file(p.name)
        p = config.ROOT / p
    return p


def resolved_paths(force: bool = False) -> Dict[str, Any]:
    """返回各配置文件的解析路径与来源。"""
    global _paths_cache
    if _paths_cache is not None and not force:
        return _paths_cache
    st = _read_platform_settings()
    out: Dict[str, Any] = {}
    for key, env_name in _ENV.items():
        default = config.resolve_config_file(_DEFAULT_NAME[key])
        env = (os.getenv(env_name) or "").strip()
        setting = str(st.get(_SETTING_KEY[key]) or "").strip()
        if env:
            path, src = _resolve_one(key, env, default), "env"
            configured = env
        elif setting:
            path, src = _resolve_one(key, setting, default), "settings"
            configured = setting
        else:
            path, src, configured = default, "default", ""
        out[key] = {
            "path": path,
            "configured": configured,
            "source": src,
            "exists": path.is_file(),
        }
    _paths_cache = out
    return out


def db_config_path() -> Path:
    return resolved_paths()["db"]["path"]


def ai_config_path() -> Path:
    return resolved_paths()["ai"]["path"]


def redis_file_path() -> Optional[Path]:
    """独立 Redis 配置文件；无独立文件时返回 None（用 db_config 内嵌）。"""
    info = resolved_paths()["redis"]
    p: Path = info["path"]
    if info["configured"] or info["source"] == "env" or p.is_file():
        return p
    return None


def es_file_path() -> Optional[Path]:
    info = resolved_paths()["es"]
    p: Path = info["path"]
    if info["configured"] or info["source"] == "env" or p.is_file():
        return p
    return None


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _load_db() -> Dict[str, Any]:
    return _load_json(db_config_path())


def redis_config() -> Dict[str, Any]:
    global _redis_cfg
    if _redis_cfg is not None:
        return _redis_cfg

    standalone = redis_file_path()
    if standalone is not None:
        block = _load_json(standalone)
    else:
        raw = _load_db()
        block = raw.get("redis") if isinstance(raw.get("redis"), dict) else {}

    cfg: Dict[str, Any] = {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 6379,
        "password": "",
        "db": 0,
        "key_prefix": "cnpc:",
        "protocol": 2,
    }
    cfg.update({k: v for k, v in (block or {}).items() if v is not None and v != ""})

    _env_map = {
        "FORENSIC_REDIS_ENABLED": ("enabled", lambda v: v.lower() not in ("0", "false", "no")),
        "FORENSIC_REDIS_HOST": ("host", str),
        "FORENSIC_REDIS_PORT": ("port", int),
        "FORENSIC_REDIS_PASSWORD": ("password", str),
        "FORENSIC_REDIS_DB": ("db", int),
        "FORENSIC_REDIS_KEY_PREFIX": ("key_prefix", str),
    }
    for env_key, (field, cast) in _env_map.items():
        val = os.getenv(env_key)
        if val is not None:
            try:
                cfg[field] = cast(val)
            except Exception:
                pass

    _redis_cfg = cfg
    return cfg


def es_config() -> Dict[str, Any]:
    global _es_cfg
    if _es_cfg is not None:
        return _es_cfg

    standalone = es_file_path()
    if standalone is not None:
        block = _load_json(standalone)
    else:
        raw = _load_db()
        block = (raw.get("elasticsearch") or {}) if isinstance(raw.get("elasticsearch"), dict) else {}

    cfg: Dict[str, Any] = {
        "enabled": False,
        "hosts": ["https://127.0.0.1:9200"],
        "user": "elastic",
        "password": "",
        "verify_certs": True,
        "index_findings": "cnpc_findings",
        "index_ioc": "cnpc_ioc",
        "index_ip_ranges": "cnpc_ip_ranges",
        "index_edr_events": "cnpc_edr_events",
        "index_edr_detection_rules": "cnpc_edr_detection_rules",
        "edr_detection_enabled": False,
        "edr_detection_interval_sec": 300,
        "edr_detection_window_min": 15,
        "edr_detection_rules_per_run": 24,
    }
    cfg.update({k: v for k, v in (block or {}).items() if v is not None and v != ""})

    # 仅当配置未显式写 enabled 时，凭密码推断开启；显式 false 优先生效以省内存
    if "enabled" not in (block or {}) and (block.get("password") or os.getenv("FORENSIC_ES_PASSWORD")):
        cfg["enabled"] = True

    _env_map = {
        "FORENSIC_ES_ENABLED": ("enabled", lambda v: v.lower() not in ("0", "false", "no")),
        "FORENSIC_ES_HOSTS": ("hosts", lambda v: [x.strip() for x in v.split(",")]),
        "FORENSIC_ES_USER": ("user", str),
        "FORENSIC_ES_PASSWORD": ("password", str),
        "FORENSIC_ES_VERIFY_CERTS": ("verify_certs", lambda v: v.lower() not in ("0", "false", "no")),
        "FORENSIC_ES_INDEX_FINDINGS": ("index_findings", str),
        "FORENSIC_ES_INDEX_IOC": ("index_ioc", str),
        "FORENSIC_ES_INDEX_IP_RANGES": ("index_ip_ranges", str),
        "FORENSIC_ES_INDEX_EDR_EVENTS": ("index_edr_events", str),
        "FORENSIC_ES_EDR_DETECTION": ("edr_detection_enabled", lambda v: v.lower() not in ("0", "false", "no")),
    }
    for env_key, (field, cast) in _env_map.items():
        val = os.getenv(env_key)
        if val is not None:
            try:
                cfg[field] = cast(val)
            except Exception:
                pass

    _es_cfg = cfg
    return cfg


def reload_cache_config() -> None:
    global _redis_cfg, _es_cfg, _paths_cache
    _redis_cfg = None
    _es_cfg = None
    _paths_cache = None
