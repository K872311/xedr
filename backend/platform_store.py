"""
平台运行参数 / 大模型 / 系统更新记录 → MySQL。

本地 JSON 仍作冷启动与回退；MySQL 就绪后以库为准并回写本地。
机器路径、库密码等仍只在本地文件。
API Key 入库（及本地 json）加密存放，不写明文。
服务操作（日志路径 / 重启 / 开关机）走既有 audit_logs，不另建表。
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import mysql_db

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
SECRET_PATH = CONFIG_DIR / "platform_secret.key"

RUNTIME_KEYS = (
    "site_name",
    "note",
    "job_max_workers",
    "job_heavy_max",
    "job_per_user_max",
    "session_ttl_days",
    "session_idle_minutes",
    "section_page_size",
    "report_retention_days",
    "upload_max_mb",
    "upload_max_concurrent",
    "job_queue_soft_limit",
    "job_queue_hard_limit",
    "auto_import_jg",
    "audit_enabled",
    "registration_enabled",
    "registration_default_role",
    "eventlog_min_level",
)

_lock = threading.RLock()
_secret: Optional[bytes] = None
_tables_ok = False

try:
    from cryptography.fernet import Fernet  # type: ignore

    _HAS_FERNET = True
except Exception:
    Fernet = None  # type: ignore
    _HAS_FERNET = False


def _now() -> datetime:
    return datetime.now()


def _parse_json(val: Any, default: Any = None) -> Any:
    if val is None:
        return default
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, (bytes, bytearray)):
        val = val.decode("utf-8", errors="ignore")
    if isinstance(val, str):
        try:
            return json.loads(val or ("{}" if default == {} else "[]" if default == [] else "null"))
        except Exception:
            return default
    return default


def _with_conn(fn: Callable) -> Any:
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            out = fn(cur)
        conn.commit()
        return out
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


def ensure_platform_tables(conn=None) -> None:
    own = conn is None
    if own:
        if not mysql_db.mysql_ready():
            return
        conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS platform_runtime_settings (
                    id TINYINT NOT NULL PRIMARY KEY,
                    payload JSON NOT NULL,
                    updated_at DATETIME(6) NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS platform_ai_config (
                    id TINYINT NOT NULL PRIMARY KEY,
                    model VARCHAR(128) NOT NULL DEFAULT '',
                    base_url VARCHAR(512) NOT NULL DEFAULT '',
                    api_key_enc TEXT NOT NULL,
                    updated_at DATETIME(6) NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS platform_system_updates (
                    kind VARCHAR(32) NOT NULL,
                    package_id VARCHAR(128) NOT NULL,
                    version VARCHAR(64) NOT NULL DEFAULT '',
                    installed_at VARCHAR(64) NOT NULL DEFAULT '',
                    md5 VARCHAR(64) NOT NULL DEFAULT '',
                    description_json JSON NULL,
                    source VARCHAR(32) NOT NULL DEFAULT 'manual',
                    payload JSON NULL,
                    PRIMARY KEY (kind, package_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS platform_system_updates_meta (
                    id TINYINT NOT NULL PRIMARY KEY,
                    auto_update JSON NOT NULL,
                    last_check JSON NULL,
                    updated_at DATETIME(6) NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
        conn.commit()
    finally:
        if own:
            conn.close()


def ensure_ready() -> bool:
    global _tables_ok
    try:
        if not mysql_db.get_status().get("ok"):
            _tables_ok = False
            return False
    except Exception:
        _tables_ok = False
        return False
    if _tables_ok:
        return True
    try:
        ensure_platform_tables()
        _tables_ok = True
        return True
    except Exception as e:
        print(f"[platform_store] tables: {e}")
        return False


def _secret_bytes() -> bytes:
    global _secret
    if _secret is not None:
        return _secret
    with _lock:
        if _secret is not None:
            return _secret
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if SECRET_PATH.is_file():
            raw = SECRET_PATH.read_bytes().strip()
            if len(raw) >= 32:
                _secret = raw[:32]
                return _secret
        raw = secrets.token_bytes(32)
        SECRET_PATH.write_bytes(raw)
        try:
            SECRET_PATH.chmod(0o600)
        except Exception:
            pass
        _secret = raw
        return _secret


def encrypt_secret(plain: str) -> str:
    text = str(plain or "")
    if not text:
        return ""
    key = _secret_bytes()
    if _HAS_FERNET and Fernet is not None:
        token = Fernet(base64.urlsafe_b64encode(key)).encrypt(text.encode("utf-8"))
        return "fernet:" + token.decode("ascii")
    nonce = secrets.token_bytes(16)
    out = bytearray()
    data = text.encode("utf-8")
    for i, b in enumerate(data):
        block = hashlib.sha256(key + nonce + i.to_bytes(4, "big")).digest()
        out.append(b ^ block[i % 32])
    mac = hashlib.sha256(key + nonce + bytes(out)).digest()[:16]
    return "xor1:" + base64.urlsafe_b64encode(nonce + mac + bytes(out)).decode("ascii")


def decrypt_secret(blob: str) -> str:
    raw = str(blob or "")
    if not raw:
        return ""
    key = _secret_bytes()
    try:
        if raw.startswith("fernet:") and _HAS_FERNET and Fernet is not None:
            return (
                Fernet(base64.urlsafe_b64encode(key))
                .decrypt(raw[7:].encode("ascii"))
                .decode("utf-8")
            )
        if raw.startswith("xor1:"):
            packed = base64.urlsafe_b64decode(raw[5:].encode("ascii"))
            nonce, mac, data = packed[:16], packed[16:32], packed[32:]
            expect = hashlib.sha256(key + nonce + data).digest()[:16]
            if not secrets.compare_digest(mac, expect):
                return ""
            out = bytearray()
            for i, b in enumerate(data):
                block = hashlib.sha256(key + nonce + i.to_bytes(4, "big")).digest()
                out.append(b ^ block[i % 32])
            return bytes(out).decode("utf-8")
    except Exception:
        return ""
    return ""


def file_api_key(cfg: Dict[str, Any]) -> str:
    """从 ai_config.json 取密钥：优先解密 api_key_enc，兼容旧明文 api_key。"""
    if not isinstance(cfg, dict):
        return ""
    enc = str(cfg.get("api_key_enc") or "").strip()
    if enc:
        return decrypt_secret(enc)
    return str(cfg.get("api_key") or "").strip()


# ---------- 运行参数 ----------

def pick_runtime(settings: Dict[str, Any]) -> Dict[str, Any]:
    return {k: settings[k] for k in RUNTIME_KEYS if k in settings}


def load_runtime() -> Optional[Dict[str, Any]]:
    if not ensure_ready():
        return None
    try:
        def _q(cur):
            cur.execute("SELECT payload FROM platform_runtime_settings WHERE id=1 LIMIT 1")
            return cur.fetchone()

        row = _with_conn(_q)
        if not row:
            return None
        payload = _parse_json(row.get("payload"), {})
        if not isinstance(payload, dict) or not payload:
            return None
        return payload
    except Exception as e:
        print(f"[platform_store] load runtime: {e}")
        return None


def save_runtime(settings: Dict[str, Any]) -> bool:
    if not ensure_ready():
        return False
    payload = pick_runtime(settings)
    try:
        blob = json.dumps(payload, ensure_ascii=False)

        def _q(cur):
            cur.execute(
                """
                INSERT INTO platform_runtime_settings (id, payload, updated_at)
                VALUES (1, %s, %s)
                ON DUPLICATE KEY UPDATE payload=VALUES(payload), updated_at=VALUES(updated_at)
                """,
                (blob, _now()),
            )

        _with_conn(_q)
        return True
    except Exception as e:
        print(f"[platform_store] save runtime: {e}")
        return False


def seed_runtime_from_local(settings: Dict[str, Any]) -> bool:
    if load_runtime() is not None:
        return False
    ok = save_runtime(settings)
    if ok:
        print("[platform_store] seeded runtime settings")
    return ok


# ---------- 大模型 ----------

def load_ai() -> Optional[Dict[str, str]]:
    if not ensure_ready():
        return None
    try:
        def _q(cur):
            cur.execute(
                "SELECT model, base_url, api_key_enc FROM platform_ai_config WHERE id=1 LIMIT 1"
            )
            return cur.fetchone()

        row = _with_conn(_q)
        if not row:
            return None
        return {
            "model": str(row.get("model") or ""),
            "base_url": str(row.get("base_url") or ""),
            "api_key": decrypt_secret(str(row.get("api_key_enc") or "")),
        }
    except Exception as e:
        print(f"[platform_store] load ai: {e}")
        return None


def save_ai(model: str, base_url: str, api_key: str) -> bool:
    if not ensure_ready():
        return False
    try:
        enc = encrypt_secret(api_key)

        def _q(cur):
            cur.execute(
                """
                INSERT INTO platform_ai_config (id, model, base_url, api_key_enc, updated_at)
                VALUES (1, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                  model=VALUES(model),
                  base_url=VALUES(base_url),
                  api_key_enc=VALUES(api_key_enc),
                  updated_at=VALUES(updated_at)
                """,
                (
                    str(model or "")[:128],
                    str(base_url or "")[:512],
                    enc,
                    _now(),
                ),
            )

        _with_conn(_q)
        return True
    except Exception as e:
        print(f"[platform_store] save ai: {e}")
        return False


def seed_ai_from_local(cfg: Dict[str, str]) -> bool:
    if load_ai() is not None:
        return False
    ok = save_ai(cfg.get("model") or "", cfg.get("base_url") or "", cfg.get("api_key") or "")
    if ok:
        print("[platform_store] seeded ai config")
    return ok


# ---------- 系统更新记录 ----------

def _norm_auto(raw: Any) -> Dict[str, bool]:
    if isinstance(raw, dict):
        return {
            "system": bool(raw.get("system")),
            "library": bool(raw.get("library")),
        }
    return {"system": bool(raw), "library": bool(raw)}


def _norm_check(raw: Any) -> Dict[str, str]:
    if isinstance(raw, dict):
        return {
            "system": str(raw.get("system") or ""),
            "library": str(raw.get("library") or ""),
        }
    return {"system": "", "library": ""}


def load_updates() -> Optional[Dict[str, Any]]:
    if not ensure_ready():
        return None
    try:
        def _q(cur):
            cur.execute(
                "SELECT auto_update, last_check FROM platform_system_updates_meta WHERE id=1 LIMIT 1"
            )
            meta = cur.fetchone()
            cur.execute(
                """
                SELECT kind, package_id, version, installed_at, md5, description_json, source, payload
                FROM platform_system_updates
                ORDER BY installed_at DESC, package_id DESC
                LIMIT 200
                """
            )
            return meta, list(cur.fetchall() or [])

        meta, rows = _with_conn(_q)
        if meta is None and not rows:
            return None
        items: List[Dict[str, Any]] = []
        for r in rows:
            payload = _parse_json(r.get("payload"), None)
            if isinstance(payload, dict) and payload.get("id"):
                items.append(payload)
                continue
            desc = _parse_json(r.get("description_json"), [])
            items.append(
                {
                    "kind": r.get("kind") or "system",
                    "id": r.get("package_id") or "",
                    "version": r.get("version") or "",
                    "installed_at": r.get("installed_at") or "",
                    "md5": r.get("md5") or "",
                    "description": desc if isinstance(desc, list) else [],
                    "source": r.get("source") or "manual",
                }
            )
        auto = _norm_auto(_parse_json((meta or {}).get("auto_update"), {}))
        last = _norm_check(_parse_json((meta or {}).get("last_check"), {}))
        return {"auto_update": auto, "last_check": last, "items": items}
    except Exception as e:
        print(f"[platform_store] load updates: {e}")
        return None


def save_updates(data: Dict[str, Any]) -> bool:
    if not ensure_ready() or not isinstance(data, dict):
        return False
    try:
        auto = json.dumps(_norm_auto(data.get("auto_update")), ensure_ascii=False)
        last = json.dumps(_norm_check(data.get("last_check")), ensure_ascii=False)
        items = [x for x in (data.get("items") or []) if isinstance(x, dict)]
        rows = []
        for it in items[:200]:
            kind = str(it.get("kind") or "system")[:32]
            pid = str(it.get("id") or "")[:128]
            if not pid:
                continue
            desc = it.get("description")
            if not isinstance(desc, list):
                desc = [str(desc)] if desc else []
            rows.append(
                (
                    kind,
                    pid,
                    str(it.get("version") or "")[:64],
                    str(it.get("installed_at") or "")[:64],
                    str(it.get("md5") or "")[:32],
                    json.dumps(desc, ensure_ascii=False),
                    str(it.get("source") or "manual")[:32],
                    json.dumps(it, ensure_ascii=False),
                )
            )

        def _q(cur):
            cur.execute(
                """
                INSERT INTO platform_system_updates_meta (id, auto_update, last_check, updated_at)
                VALUES (1, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                  auto_update=VALUES(auto_update),
                  last_check=VALUES(last_check),
                  updated_at=VALUES(updated_at)
                """,
                (auto, last, _now()),
            )
            cur.execute("DELETE FROM platform_system_updates")
            if rows:
                cur.executemany(
                    """
                    INSERT INTO platform_system_updates
                      (kind, package_id, version, installed_at, md5, description_json, source, payload)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    rows,
                )

        _with_conn(_q)
        return True
    except Exception as e:
        print(f"[platform_store] save updates: {e}")
        return False


def seed_updates_from_local(data: Dict[str, Any]) -> bool:
    remote = load_updates()
    if remote is None:
        ok = save_updates(data)
        if ok:
            print("[platform_store] seeded system_updates")
        return ok
    if not remote.get("items") and (data.get("items") or []):
        merged = dict(data)
        merged["auto_update"] = remote.get("auto_update") or data.get("auto_update")
        merged["last_check"] = remote.get("last_check") or data.get("last_check")
        return save_updates(merged)
    return False


def catchup_all(
    *,
    runtime: Optional[Dict[str, Any]] = None,
    ai: Optional[Dict[str, str]] = None,
    updates: Optional[Dict[str, Any]] = None,
) -> None:
    """MySQL 恢复或首次就绪：本地有数据且库空则灌入。"""
    if not ensure_ready():
        return
    if runtime:
        seed_runtime_from_local(runtime)
    if ai:
        seed_ai_from_local(ai)
    if updates:
        seed_updates_from_local(updates)
