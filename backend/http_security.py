"""HTTP 安全头 + CORS。默认仅本机或与当前 Host 同主机的 :8000/:8001；整段内网需 FORENSIC_CORS=lan。"""
from __future__ import annotations

import os
import re
import threading
import time
import uuid

from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

# 旧行为：整段内网 :8000/:8001。默认不再启用，需 FORENSIC_CORS=lan
_LAN_ORIGIN_RE = re.compile(
    r"^https?://("
    r"localhost|127\.0\.0\.1|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}"
    r")(:(8000|8001))?$",
    re.IGNORECASE,
)
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_CORS_PORTS = {None, 80, 443, 8000, 8001}
_CORS_HEADERS = "Authorization, Content-Type, X-Upload-Filename"
_CORS_METHODS = "GET, POST, PUT, DELETE, OPTIONS"


def cors_origin_regex() -> str:
    extra = (os.environ.get("FORENSIC_CORS_REGEX") or "").strip()
    if extra:
        return extra
    if (os.environ.get("FORENSIC_CORS") or "").strip().lower() in ("lan", "private", "1", "true"):
        return _LAN_ORIGIN_RE.pattern
    # 默认：仅本机 loopback（兼容旧调用方）；实际跨源由 SameHostCORSMiddleware 按请求 Host 判断
    return r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:(8000|8001))?$"


def _origin_allowed(origin: str, request_host: str) -> bool:
    origin = (origin or "").strip()
    if not origin:
        return False
    extra = (os.environ.get("FORENSIC_CORS_REGEX") or "").strip()
    if extra:
        try:
            return re.fullmatch(extra, origin) is not None
        except re.error:
            return False
    if (os.environ.get("FORENSIC_CORS") or "").strip().lower() in ("lan", "private", "1", "true"):
        return _LAN_ORIGIN_RE.fullmatch(origin) is not None
    try:
        u = urlparse(origin)
    except Exception:
        return False
    if u.scheme not in ("http", "https"):
        return False
    oh = (u.hostname or "").lower()
    if u.port not in _CORS_PORTS:
        return False
    req = (request_host or "").strip().lower()
    if req.startswith("[") and "]" in req:
        rh = req[1:req.find("]")].lower()
    elif req.count(":") == 1:
        rh = req.split(":", 1)[0]
    else:
        rh = req.split(":", 1)[0] if req else ""
    if oh in _LOOPBACK and rh in _LOOPBACK:
        return True
    return bool(oh and rh and oh == rh)


class SameHostCORSMiddleware(BaseHTTPMiddleware):
    """默认只放行本机，或与当前 Host 同主机的 :8000/:8001（供规则库 8001 调主站）。"""

    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("origin") or ""
        host = request.headers.get("host") or (request.url.hostname or "")
        allowed = bool(origin) and _origin_allowed(origin, host)
        if request.method == "OPTIONS" and origin:
            if not allowed:
                return Response(status_code=403)
            return Response(
                status_code=204,
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Methods": _CORS_METHODS,
                    "Access-Control-Allow-Headers": _CORS_HEADERS,
                    "Access-Control-Allow-Credentials": "true",
                    "Access-Control-Max-Age": "600",
                    "Vary": "Origin",
                },
            )
        resp = await call_next(request)
        if allowed:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Headers"] = _CORS_HEADERS
            resp.headers["Access-Control-Allow-Methods"] = _CORS_METHODS
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Vary"] = "Origin"
        return resp


def trust_proxy() -> bool:
    return (os.environ.get("FORENSIC_TRUST_PROXY") or "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def client_ip(request: Request | None) -> str:
    if not request:
        return ""
    try:
        peer = (request.client.host or "") if request.client else ""
        trusted = {
            x.strip()
            for x in (os.environ.get("FORENSIC_TRUSTED_PROXIES") or "127.0.0.1,::1").split(",")
            if x.strip()
        }
        if trust_proxy() and peer in trusted:
            xf = request.headers.get("x-forwarded-for") or ""
            if xf:
                return xf.split(",")[0].strip()[:64]
        if request.client:
            return peer[:64]
    except Exception:
        pass
    return ""


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, allow_inline_script: bool = False):
        super().__init__(app)
        # 规则库管理后台仍是单页内联 <script>；主站 Vue 已拆到 /app/assets，保持 script-src 'self'
        self.allow_inline_script = bool(allow_inline_script)

    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        host = request.url.hostname or "localhost"
        if not re.fullmatch(r"[A-Za-z0-9.:\-]+", host):
            host = "localhost"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        scheme = request.url.scheme
        # 反代 HTTPS 时仍发 http 进进程；用 X-Forwarded-Proto 写对 HSTS / CSP
        xf_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
        if xf_proto in ("http", "https"):
            scheme = xf_proto
        # 管理后台(:8001) 跨源调主站(:8000)。localhost 与 127.0.0.1 在浏览器是不同源，
        # CSP connect-src 必须同时放行，否则登录 fetch 会被静默拦截。
        hosts = [host]
        if host in ("localhost", "127.0.0.1"):
            hosts = ["localhost", "127.0.0.1"]
        sibling_origins = " ".join(
            f"{scheme}://{h}:{p}" for h in hosts for p in ("8000", "8001")
        )
        # 公网域名访问时允许同 host 的 80/443（反代场景）
        public_extra = (os.environ.get("FORENSIC_CSP_CONNECT") or "").strip()
        connect_src = f"'self' {sibling_origins}"
        if public_extra:
            connect_src = f"{connect_src} {public_extra}"
        script_src = "'self' 'unsafe-inline'" if self.allow_inline_script else "'self'"
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            f"default-src 'self'; script-src {script_src}; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            f"connect-src {connect_src}; object-src 'none'; base-uri 'self'; "
            "form-action 'self'; frame-ancestors 'self'",
        )
        resp.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        if scheme == "https":
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        if request.url.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp


def _slow_request_threshold(method: str, path: str) -> float | None:
    """返回慢请求告警阈值（毫秒）；None 表示不记 warn。

    入库/静态资源在分析高峰时排队是预期现象，不要刷爆应用日志。
    """
    p = str(path or "")
    m = str(method or "GET").upper()
    if p.startswith("/app/assets/") or p.startswith("/assets/"):
        return None
    if m == "POST" and p in {
        "/api/collect/report",
        "/api/collect/import-linuxsc",
        "/api/collect/import-jg",
        "/api/jobs/analyze",
        "/api/jobs/analyze-batch",
        "/api/jobs/reanalyze-all",
    }:
        return 8000.0
    if p.startswith("/api/system/runtime") or p.startswith("/api/system/services"):
        return 2000.0
    # section / sections：大报告读 SQLite + 进程瘦身属常态，阈值放宽，避免刷屏
    if "/api/collect/section/" in p or "/api/collect/sections/" in p:
        return 5000.0
    if "/api/collect/import-pack" in p:
        return 5000.0
    try:
        return float(os.environ.get("FORENSIC_SLOW_REQUEST_MS") or "1500")
    except ValueError:
        return 1500.0


def _should_log_api_error(method: str, path: str, status: int) -> bool:
    """记录 /api 的业务失败；过滤登录态探测等常态噪声。"""
    if status < 400:
        return False
    p = (path or "").split("?", 1)[0]
    if not p.startswith("/api/"):
        return False
    m = (method or "GET").upper()
    # 会话探测 / 未登录轮询：401 很常见，不刷屏
    if status == 401 and p.startswith("/api/auth/"):
        return False
    if status == 404 and p in {"/api/favicon.ico", "/api/logo"}:
        return False
    # 报告尚未分析完成时前端会轮询 summary，404 属预期
    if status == 404 and m == "GET" and p.startswith("/api/collect/summary/"):
        return False
    # AI 结果未生成时的探测（兼容旧客户端仍可能发 404）
    if status == 404 and m == "GET" and (
        p.startswith("/api/ai/result/") or p.startswith("/api/ai/section-result/")
    ):
        return False
    # 自身写日志接口失败仍记，避免递归由 applog._TLS.busy 挡住
    return True


def _log_api_outcome(
    *,
    request: Request,
    status: int,
    total_ms: float,
    request_id: str,
    exc: BaseException | None = None,
) -> None:
    try:
        from . import applog
    except Exception:
        return
    method = request.method
    path = request.url.path
    # 未捕获异常一律记；HTTP 4xx/5xx 走过滤
    if exc is None and not _should_log_api_error(method, path, status):
        return
    detail = ""
    if exc is not None:
        detail = f" exc={type(exc).__name__}: {str(exc)[:300]}"
        try:
            import traceback
            tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            lines = [ln for ln in tb.strip().splitlines() if ln.strip()][-8:]
            if lines:
                detail += " | tb=" + " || ".join(lines)[:800]
        except Exception:
            pass
    msg = (
        f"method={method} path={path} status={status} "
        f"total_ms={total_ms:.1f} ip={client_ip(request)} id={request_id}{detail}"
    )
    level_error = status >= 500 or exc is not None
    try:
        if level_error:
            applog.error("api_error", msg, status=status, path=path, method=method, request_id=request_id)
        else:
            applog.warn("api_error", msg, status=status, path=path, method=method, request_id=request_id)
    except Exception:
        print(f"[api_error] {msg}")


class RequestTimingMiddleware(BaseHTTPMiddleware):
    """请求耗时头 + 慢请求 / API 报错写入应用日志。"""

    async def dispatch(self, request: Request, call_next):
        incoming = (request.headers.get("x-request-id") or "").strip()
        request_id = incoming if re.fullmatch(r"[A-Za-z0-9._-]{8,64}", incoming) else uuid.uuid4().hex
        request.state.request_id = request_id
        started = time.perf_counter()
        response = None
        try:
            response = await call_next(request)
        except Exception as exc:
            total_ms = (time.perf_counter() - started) * 1000.0
            _log_api_outcome(
                request=request,
                status=500,
                total_ms=total_ms,
                request_id=request_id,
                exc=exc,
            )
            raise
        total_ms = (time.perf_counter() - started) * 1000.0
        auth_ms = float(getattr(request.state, "auth_ms", 0.0) or 0.0)
        db_ms = float(getattr(request.state, "db_ms", 0.0) or 0.0)
        response.headers["X-Request-ID"] = request_id
        metrics = [f"total;dur={total_ms:.1f}"]
        if auth_ms:
            metrics.append(f"auth;dur={auth_ms:.1f}")
        if db_ms:
            metrics.append(f"db;dur={db_ms:.1f}")
        response.headers["Server-Timing"] = ", ".join(metrics)
        threshold = _slow_request_threshold(request.method, request.url.path)
        if threshold is not None and total_ms >= max(50.0, threshold):
            size = response.headers.get("content-length") or ""
            msg = (
                f"method={request.method} path={request.url.path} "
                f"status={response.status_code} total_ms={total_ms:.1f} "
                f"auth_ms={auth_ms:.1f} db_ms={db_ms:.1f} bytes={size or '?'} "
                f"ip={client_ip(request)} id={request_id}"
            )
            try:
                from . import applog
                applog.warn("slow_request", msg)
            except Exception:
                print(f"[slow_request] {msg}")
        if response.status_code >= 400:
            _log_api_outcome(
                request=request,
                status=int(response.status_code),
                total_ms=total_ms,
                request_id=request_id,
            )
        return response


_BODY_LIMIT_MB: int | None = None


def sync_body_limit_from_settings() -> int:
    """与 platform_settings.upload_max_mb 对齐；FORENSIC_MAX_BODY_MB 可覆盖。"""
    global _BODY_LIMIT_MB
    env_raw = (os.environ.get("FORENSIC_MAX_BODY_MB") or "").strip()
    if env_raw:
        try:
            _BODY_LIMIT_MB = max(5, min(2048, int(env_raw)))
            return _BODY_LIMIT_MB
        except ValueError:
            pass
    try:
        from backend.settings import get_settings
        _BODY_LIMIT_MB = max(5, min(2048, int(get_settings().get("upload_max_mb") or 1024)))
    except Exception:
        _BODY_LIMIT_MB = 1024
    return _BODY_LIMIT_MB


def body_limit_bytes(*, fixed_max_bytes: int | None = None) -> int:
    if fixed_max_bytes is not None:
        return int(fixed_max_bytes)
    return sync_body_limit_from_settings() * 1024 * 1024


class RequestBodyLimitMiddleware:
    """在 JSON/multipart 解析前限制请求体，避免超大或分块请求耗尽内存。"""

    def __init__(self, app: ASGIApp, max_bytes: int | None = None):
        self.app = app
        self._fixed_max_bytes = int(max_bytes) if max_bytes is not None else None
        self._body_sem = threading.BoundedSemaphore(16)
        self._heavy_sem = threading.BoundedSemaphore(5)

    def _max_bytes(self) -> int:
        return body_limit_bytes(fixed_max_bytes=self._fixed_max_bytes)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        max_bytes = self._max_bytes()
        max_mb = max_bytes // (1024 * 1024)
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers") or []
        }
        try:
            content_length = int(headers.get("content-length") or 0)
        except ValueError:
            content_length = 0
        if content_length > max_bytes:
            resp = JSONResponse(
                {"detail": f"请求体过大，上限 {max_mb}MB"},
                status_code=413,
            )
            await resp(scope, receive, send)
            return
        has_body = scope.get("method") in {"POST", "PUT", "PATCH"}
        path = str(scope.get("path") or "")
        heavy = path in {
            "/api/collect/report",
            "/api/analyze/pipeline",
            "/api/ai/analyze",
            "/api/sql/execute",
        }
        sem = self._heavy_sem if heavy else self._body_sem
        acquired = (not has_body) or sem.acquire(blocking=False)
        if not acquired:
            resp = JSONResponse({"detail": "并发请求过多，请稍后再试"}, status_code=429)
            await resp(scope, receive, send)
            return

        consumed = 0
        response_started = False

        async def limited_receive():
            nonlocal consumed
            message = await receive()
            if message.get("type") == "http.request":
                consumed += len(message.get("body") or b"")
                if consumed > max_bytes:
                    raise _RequestTooLarge()
            return message

        async def tracked_send(message):
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _RequestTooLarge:
            if response_started:
                raise
            resp = JSONResponse(
                {"detail": f"请求体过大，上限 {max_mb}MB"},
                status_code=413,
            )
            await resp(scope, receive, send)
        finally:
            if has_body and acquired:
                sem.release()


class _RequestTooLarge(Exception):
    pass


class SessionCookieAuthMiddleware:
    """Cookie → Bearer（现有接口不用改）；并把登录下发的会话 Cookie 写到最外层响应。"""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        from backend.auth import SESSION_COOKIE_NAME, SESSION_SCOPE_BAG, read_session_cookie

        scope = dict(scope)
        bag = {"set": "", "clear": False}
        scope[SESSION_SCOPE_BAG] = bag
        headers = list(scope.get("headers") or [])
        has_auth = any(k.lower() == b"authorization" for k, _ in headers)
        if not has_auth:
            cookie_header = ""
            for k, v in headers:
                if k.lower() == b"cookie":
                    cookie_header = v.decode("latin-1")
                    break
            if cookie_header:
                try:
                    token = read_session_cookie(cookie_header)
                except Exception:
                    token = ""
                if token:
                    scope["headers"] = headers + [
                        (b"authorization", f"Bearer {token}".encode("ascii"))
                    ]

        async def send_wrapper(message):
            if message.get("type") != "http.response.start":
                await send(message)
                return
            raw = list(message.get("headers") or [])
            set_tok = str(bag.get("set") or "").strip()
            clear = bool(bag.get("clear"))
            prefix = SESSION_COOKIE_NAME.lower() + "="
            kept = []
            for k, v in raw:
                lk = k.lower()
                if lk == b"x-set-session-cookie":
                    hdr = v.decode("latin-1").strip()
                    if hdr and not set_tok:
                        set_tok = hdr
                    continue
                if lk == b"x-clear-session-cookie":
                    clear = True
                    continue
                if lk == b"set-cookie" and v.decode("latin-1").lower().startswith(prefix):
                    continue
                kept.append((k, v))
            if set_tok or clear:
                try:
                    from backend.auth import (
                        format_session_clear_cookie,
                        format_session_set_cookie,
                        valid_session_token,
                        _cookie_secure_from_scope,
                    )
                    secure = _cookie_secure_from_scope(scope)
                    cookie = ""
                    if clear:
                        cookie = format_session_clear_cookie(secure=secure)
                    elif valid_session_token(set_tok):
                        cookie = format_session_set_cookie(set_tok, secure=secure)
                    if cookie:
                        kept.append((b"set-cookie", cookie.encode("latin-1")))
                except Exception as e:
                    print("[session-cookie]", e)
            message = dict(message)
            message["headers"] = kept
            await send(message)

        await self.app(scope, receive, send_wrapper)
