"""登录会话：优先存 Redis，不可用时回退内存 dict。

Redis key：{prefix}sess:{token}  →  JSON {user:{...}, created_at:float}
TTL = session_ttl_days * 86400 秒
"""
from __future__ import annotations
import json
import os
import secrets
import threading
import time
from typing import Any, Dict, Optional, Tuple

from .cache_policy import capacity, ttl
from .users import UserStore, _public, _verify_password, create_user, list_users, upgrade_password_hash

# 内存兜底（Redis 不可用时使用）
_sessions: Dict[str, Dict[str, Any]] = {}
_TTL = 86400 * 7  # 7 天

# 鉴权热路径缓存：token → (expires_at, user|None)
# 点按钮不必每次打 Redis/用户库；降权/禁用后最多延迟 _ME_CACHE_TTL 秒生效
_ME_CACHE: Dict[str, Tuple[float, Optional[Dict[str, Any]]]] = {}
_ME_CACHE_LOCK = threading.Lock()
_ME_CACHE_TTL = ttl("auth", 5.0, minimum=2.0, maximum=15.0)
_ME_CACHE_MAX = capacity("auth", 4000)


def invalidate_auth_cache(token: str = "", user_id: str = "", username: str = "") -> None:
    """登出 / 改密 / 禁用后清鉴权缓存。无参数则清空全部。"""
    tok = str(token or "").strip()
    uid = str(user_id or "").strip()
    uname = str(username or "").strip().lower()
    with _ME_CACHE_LOCK:
        if not tok and not uid and not uname:
            _ME_CACHE.clear()
            return
        if tok:
            _ME_CACHE.pop(tok, None)
        if uid or uname:
            drop = []
            for k, (_, user) in _ME_CACHE.items():
                if not isinstance(user, dict):
                    continue
                if uid and str(user.get("id") or "") == uid:
                    drop.append(k)
                elif uname and str(user.get("username") or "").lower() == uname:
                    drop.append(k)
            for k in drop:
                _ME_CACHE.pop(k, None)


def _me_cache_get(token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """返回 (hit, user)。hit=False 表示未缓存，需回源。"""
    now = time.time()
    with _ME_CACHE_LOCK:
        hit = _ME_CACHE.get(token)
        if not hit:
            return False, None
        exp, user = hit
        if now >= exp:
            _ME_CACHE.pop(token, None)
            return False, None
        return True, (dict(user) if isinstance(user, dict) else None)


def _me_cache_put(token: str, user: Optional[Dict[str, Any]]) -> None:
    with _ME_CACHE_LOCK:
        _ME_CACHE[token] = (time.time() + _ME_CACHE_TTL, dict(user) if isinstance(user, dict) else None)
        # 简单限长，避免异常增长
        if len(_ME_CACHE) > _ME_CACHE_MAX:
            trim = max(1, _ME_CACHE_MAX // 4)
            oldest = sorted(_ME_CACHE.items(), key=lambda x: x[1][0])[:trim]
            for k, _ in oldest:
                _ME_CACHE.pop(k, None)


def set_session_ttl_days(days: int) -> int:
    global _TTL
    days = max(1, min(90, int(days or 7)))
    _TTL = 86400 * days
    return days


def get_session_ttl_days() -> int:
    return max(1, int(_TTL // 86400))


def ensure_bootstrap_admin() -> None:
    """若无任何用户，创建 admin；密码仅输出到控制台或环境变量，不落 reports 目录。"""
    import sys
    try:
        if list_users():
            _remove_bootstrap_password_file()
            return
        env_pwd = os.environ.get("FORENSIC_BOOTSTRAP_ADMIN_PASSWORD") or ""
        pwd = env_pwd or secrets.token_urlsafe(18)
        create_user(
            username="admin",
            password=pwd,
            display_name="管理员",
            role="admin",
            note="系统自动创建，请尽快改密",
        )
        _remove_bootstrap_password_file()
        if env_pwd:
            print("[auth] bootstrap admin created from FORENSIC_BOOTSTRAP_ADMIN_PASSWORD", file=sys.stderr)
        else:
            print("[auth] ===== 首次安装 · 管理员账号（请立即改密）=====", file=sys.stderr)
            print("[auth] username: admin", file=sys.stderr)
            print(f"[auth] password: {pwd}", file=sys.stderr)
            print("[auth] =============================================", file=sys.stderr)
    except Exception as e:
        print("[auth] bootstrap:", e)


def _bootstrap_password_path():
    from . import config
    return config.REPORTS_DIR / ".bootstrap_admin_password"


def _remove_bootstrap_password_file() -> None:
    """删除历史版本可能写入 reports 的一次性密码文件。"""
    try:
        path = _bootstrap_password_path()
        if path.is_file():
            path.unlink()
    except OSError:
        pass


def _row_with_hash(username: str) -> Optional[Dict[str, Any]]:
    store = UserStore()
    try:
        return store.query_one("SELECT * FROM users WHERE username=?", (username.strip(),))
    finally:
        store.close()


# ---- Redis 会话 ----

def _sess_key(token: str) -> str:
    from .redis_client import prefix
    return f"{prefix()}sess:{token}"


def _redis_set_session(
    token: str,
    user: Dict[str, Any],
    created_at: float,
    *,
    login_ip: str = "",
) -> bool:
    from .redis_client import rset
    payload = json.dumps(
        {"user": user, "created_at": created_at, "login_ip": str(login_ip or "")},
        ensure_ascii=False,
    )
    return rset(_sess_key(token), payload, ex=int(_TTL))


def _redis_get_session(token: str) -> Optional[Dict[str, Any]]:
    from .redis_client import rget
    raw = rget(_sess_key(token))
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def _redis_del_session(token: str) -> None:
    from .redis_client import rdel
    rdel(_sess_key(token))


# ---- 公开接口 ----

def login(username: str, password: str, *, ip: str = "") -> Dict[str, Any]:
    username = (username or "").strip()
    password = password or ""
    if not username:
        raise ValueError("请输入用户名")
    row = _row_with_hash(username)
    if not row:
        raise ValueError("用户名或密码错误")
    if not row.get("enabled", 1):
        raise ValueError("账号已禁用")
    ph = row.get("password_hash") or ""
    if not ph:
        raise ValueError("该账号未设置密码，请先在用户管理中设置")
    if not _verify_password(password, ph):
        raise ValueError("用户名或密码错误")
    if not str(ph).startswith("pbkdf2$"):
        try:
            upgrade_password_hash(row.get("id") or "", password)
        except Exception:
            pass

    token = secrets.token_hex(24)
    user = _public(row)
    now = time.time()
    lip = str(ip or "").strip()[:64]
    try:
        from .users import touch_login
        touch_login(str(user.get("id") or ""), lip)
        user["last_login_at"] = now
        user["last_login_ip"] = lip
    except Exception as e:
        print("[auth] touch_login:", e)

    from .redis_client import is_available as redis_ok
    # 本机内存镜像：鉴权缓存未命中时不必每次打 Redis（局域网/公网都更稳）
    _sessions[token] = {"user": user, "created_at": now, "login_ip": lip}
    if redis_ok():
        _redis_set_session(token, user, now, login_ip=lip)
    _remove_bootstrap_password_file()
    return {"token": token, "user": user}


def logout(token: str) -> None:
    if not token:
        return
    invalidate_auth_cache(token=token)
    from .redis_client import is_available as redis_ok
    if redis_ok():
        _redis_del_session(token)
    else:
        _sessions.pop(token, None)
    # 内存会话也清掉，避免 Redis 关掉后旧 token 复活
    _sessions.pop(token, None)


def _token_from_sess_key(key, pref: str) -> str:
    """从 Redis key 解析 token；兼容 bytes / 带前缀。"""
    if isinstance(key, bytes):
        key = key.decode("utf-8", errors="ignore")
    key_s = str(key or "")
    marker = f"{pref}sess:"
    if key_s.startswith(marker):
        return key_s[len(marker):]
    if "sess:" in key_s:
        return key_s.split("sess:")[-1]
    return key_s


def list_sessions(include_token: bool = False) -> list:
    """在线会话列表（admin）。

    Redis 可用时以 Redis 为唯一真相源（内存只是鉴权镜像，不再并入列表，
    避免同一登录显示成 redis + memory 两条）。
    Redis 不可用时回退本机内存。
    """
    out = []
    now = time.time()
    from .redis_client import is_available as redis_ok, prefix

    redis_listed = False
    if redis_ok():
        try:
            from .redis_client import get_client
            r = get_client()
            if r is not None:
                pref = prefix()
                pat = f"{pref}sess:*"
                keys = []
                for key in r.scan_iter(match=pat, count=200):
                    keys.append(key)
                    if len(keys) >= 500:
                        break
                raws = r.mget(keys) if keys else []
                for key, raw in zip(keys, raws):
                    try:
                        if not raw:
                            continue
                        if isinstance(raw, bytes):
                            raw = raw.decode("utf-8", errors="ignore")
                        sess = json.loads(raw)
                        user = sess.get("user") or {}
                        token = _token_from_sess_key(key, pref)
                        if not token:
                            continue
                        created = float(sess.get("created_at") or 0)
                        if now - created > _TTL:
                            continue
                        out.append({
                            "token": token if include_token else "",
                            "sid": token[:16],
                            "token_short": token[:8] + "…" if len(token) > 8 else token,
                            "user_id": user.get("id") or "",
                            "username": user.get("username") or "",
                            "display_name": user.get("display_name") or "",
                            "role": user.get("role") or "",
                            "login_ip": sess.get("login_ip") or user.get("last_login_ip") or "",
                            "created_at": created,
                            "created_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(created)) if created else "",
                            "backend": "redis",
                        })
                    except Exception:
                        continue
                redis_listed = True
        except Exception as e:
            print("[auth] list_sessions redis:", e)
            redis_listed = False

    if not redis_listed:
        for token, sess in list(_sessions.items()):
            user = (sess or {}).get("user") or {}
            created = float((sess or {}).get("created_at") or 0)
            if now - created > _TTL:
                continue
            out.append({
                "token": token if include_token else "",
                "sid": token[:16],
                "token_short": token[:8] + "…" if len(token) > 8 else token,
                "user_id": user.get("id") or "",
                "username": user.get("username") or "",
                "display_name": user.get("display_name") or "",
                "role": user.get("role") or "",
                "login_ip": (sess or {}).get("login_ip") or user.get("last_login_ip") or "",
                "created_at": created,
                "created_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(created)) if created else "",
                "backend": "memory",
            })

    # 同 token 去重（极端情况下 Redis 扫描重复）
    dedup = {}
    for item in out:
        sid = str(item.get("sid") or item.get("token") or "")
        if not sid:
            continue
        prev = dedup.get(sid)
        if not prev or float(item.get("created_at") or 0) >= float(prev.get("created_at") or 0):
            dedup[sid] = item
    out = list(dedup.values())
    out.sort(key=lambda x: x.get("created_at") or 0, reverse=True)
    return out


def revoke_session(token: str = "", *, sid: str = "") -> bool:
    tok = str(token or "").strip()
    sid_s = str(sid or "").strip()
    if not tok and sid_s:
        for s in list_sessions(include_token=True):
            full = str(s.get("token") or "")
            if full.startswith(sid_s) or str(s.get("sid") or "") == sid_s:
                tok = full
                break
    if not tok:
        return False
    logout(tok)
    return True


def revoke_user_sessions(user_id: str = "", username: str = "") -> int:
    """吊销某用户全部会话（改密/禁用/删除后调用）。"""
    uid = str(user_id or "").strip()
    uname = str(username or "").strip()
    if not uid and not uname:
        return 0
    n = 0
    for s in list_sessions(include_token=True):
        if uid and str(s.get("user_id") or "") == uid:
            logout(s.get("token") or "")
            n += 1
            continue
        if uname and str(s.get("username") or "") == uname:
            logout(s.get("token") or "")
            n += 1
    return n


def me(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    hit, cached = _me_cache_get(token)
    if hit:
        return cached

    # 优先本机会话镜像（登录时双写），避免 Redis 抖动拖慢每次按钮
    sess = _sessions.get(token)
    if not sess:
        from .redis_client import is_available as redis_ok
        if redis_ok():
            sess = _redis_get_session(token)
            if sess:
                # 回填内存，后续请求不再打 Redis
                _sessions[token] = sess
    if not sess:
        _me_cache_put(token, None)
        return None
    if time.time() - float(sess.get("created_at") or 0) > _TTL:
        logout(token)
        return None
    user = _fresh_user(sess.get("user"), token)
    if user:
        _me_cache_put(token, user)
        # 刷新会话里的用户快照（角色变更后）
        try:
            sess["user"] = dict(user)
            _sessions[token] = sess
        except Exception:
            pass
    return user


def _fresh_user(snap: Optional[Dict[str, Any]], token: str) -> Optional[Dict[str, Any]]:
    """从用户库刷新角色/启用状态；配合 me() 短缓存，不必每个请求都打库。"""
    if not isinstance(snap, dict):
        return None
    uid = str(snap.get("id") or "").strip()
    uname = str(snap.get("username") or "").strip()
    try:
        from .users import get_user, get_user_by_username
        row = get_user(uid) if uid else None
        if not row and uname:
            row = get_user_by_username(uname)
    except Exception:
        return snap
    if not row:
        logout(token)
        return None
    if not row.get("enabled"):
        logout(token)
        return None
    return row


def parse_bearer(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return authorization.strip()


# HttpOnly 会话 Cookie：浏览器 JS 读不到；鉴权仍走现有 Bearer 处理（中间件把 Cookie 提升为 Authorization）。
SESSION_COOKIE_NAME = "forensic_sid"
SESSION_SET_HEADER = "x-set-session-cookie"
SESSION_CLEAR_HEADER = "x-clear-session-cookie"
# 最外层 ASGI 挂在 scope 上的袋子：BaseHTTPMiddleware 会丢掉 Set-Cookie / 自定义头，但改不掉这个 dict。
SESSION_SCOPE_BAG = "forensic_session_cookie"
_SESSION_TOKEN_RE = None


def valid_session_token(token: str) -> bool:
    global _SESSION_TOKEN_RE
    if _SESSION_TOKEN_RE is None:
        import re
        _SESSION_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
    return bool(token and _SESSION_TOKEN_RE.fullmatch(str(token).strip()))


def read_session_cookie(cookie_header: str) -> str:
    from http.cookies import SimpleCookie
    jar = SimpleCookie()
    try:
        jar.load(str(cookie_header or ""))
    except Exception:
        return ""
    morsel = jar.get(SESSION_COOKIE_NAME)
    if not morsel:
        return ""
    tok = str(morsel.value or "").strip().strip('"')
    return tok if valid_session_token(tok) else ""


def _cookie_secure_from_scope(scope: Optional[dict] = None, request=None) -> bool:
    host = ""
    scheme = "http"
    try:
        if request is not None:
            host = str(request.url.hostname or "").lower()
            scheme = str(request.url.scheme or "http").lower()
            xf = str((request.headers.get("x-forwarded-proto") or "").split(",")[0]).strip().lower()
            if xf in ("http", "https"):
                scheme = xf
        elif scope:
            headers = {
                k.decode("latin-1").lower(): v.decode("latin-1")
                for k, v in (scope.get("headers") or [])
            }
            host = (headers.get("host") or "").split(":")[0].lower()
            scheme = str(scope.get("scheme") or "http").lower()
            xf = (headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
            if xf in ("http", "https"):
                scheme = xf
    except Exception:
        return False
    if host in {"127.0.0.1", "localhost", "::1", "[::1]"}:
        return False
    return scheme == "https"


def format_session_set_cookie(token: str, *, secure: bool) -> str:
    from starlette.responses import Response
    resp = Response()
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=int(_TTL),
        httponly=True,
        samesite="lax",
        path="/",
        secure=secure,
    )
    return resp.headers.get("set-cookie") or ""


def format_session_clear_cookie(*, secure: bool) -> str:
    from starlette.responses import Response
    resp = Response()
    resp.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
        secure=secure,
    )
    return resp.headers.get("set-cookie") or ""


def _session_bag(request):
    try:
        if request is None:
            return None
        bag = request.scope.get(SESSION_SCOPE_BAG)
        return bag if isinstance(bag, dict) else None
    except Exception:
        return None


def attach_session_cookie(response, request, token: str) -> None:
    """不直接 Set-Cookie：写入最外层中间件的 scope 袋子，避免 BaseHTTPMiddleware 丢掉 Cookie。"""
    tok = str(token or "").strip()
    if not valid_session_token(tok):
        return
    bag = _session_bag(request)
    if bag is not None:
        bag["set"] = tok
        bag["clear"] = False
    if response is not None:
        try:
            response.headers[SESSION_SET_HEADER] = tok
        except Exception:
            pass


def clear_session_cookie(response, request=None) -> None:
    bag = _session_bag(request)
    if bag is not None:
        bag["clear"] = True
        bag["set"] = ""
    if response is not None:
        try:
            response.headers[SESSION_CLEAR_HEADER] = "1"
        except Exception:
            pass
