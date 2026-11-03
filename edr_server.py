"""EDR 后台：独立进程、独立端口、独立账号，与分析平台分离。

启动：  python edr_server.py                 （默认 0.0.0.0:8100）
        python edr_server.py --port 8100
        uvicorn edr_server:app --port 8100
忘记 admin 密码：python edr_server.py --reset-admin
"""
from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.http_security import RequestBodyLimitMiddleware, SecurityHeadersMiddleware  # noqa: E402

DIST = ROOT / "agent_admin" / "dist"
EDR_PORT = int(os.getenv("EDR_PORT") or "8100")
_ASSET_EXT = {".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
              ".woff", ".woff2", ".ttf"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        from backend.mysql_db import init_on_startup
        init_on_startup()
    except Exception as e:
        print("[edr] mysql init:", e)
    try:
        from backend import agent_edr, agent_protocol
        agent_protocol.ensure_db()
        agent_edr.ensure()
        agent_protocol.reset_live_shutdown()
        agent_protocol.install_live_shutdown_hooks()
    except Exception as e:
        print("[edr] db init:", e)
    try:
        from backend.edr_auth import ensure_bootstrap_admin
        ensure_bootstrap_admin()
    except Exception as e:
        print("[edr] bootstrap admin:", e)
    try:
        from backend.detection_corpus_bootstrap import ensure_detection_corpus
        r = ensure_detection_corpus()
        if r.get("steps"):
            print("[edr] detection corpus ready:", len(r.get("steps") or []), "steps")
    except Exception as e:
        print("[edr] detection corpus:", e)
    try:
        from backend import elastic_detection_es as edes
        if edes.detection_enabled():
            edes.ensure_edr_indices()
            edes.publish_detection_rules_to_es(max_rules=500)
            edes.start_background_loop()
            print("[edr] elasticsearch EQL detection loop started")
    except Exception as e:
        print("[edr] elastic detection es:", e)
    try:
        yield
    finally:
        try:
            from backend import agent_protocol
            agent_protocol.shutdown_live()
        except Exception:
            pass


app = FastAPI(title="EDR 后台", version="1.0.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(RequestBodyLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


@app.middleware("http")
async def _same_origin_guard(request: Request, call_next):
    """浏览器跨站写请求一律拒绝（Cookie 已 SameSite=Strict，这里再兜一层）。终端 Agent 不带 Origin，不受影响。"""
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin") or ""
        if origin and origin != "null":
            host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0].strip()
            if urlsplit(origin).netloc.lower() != host.lower():
                return JSONResponse({"detail": "跨站请求被拒绝"}, status_code=403)
    return await call_next(request)


@app.exception_handler(Exception)
async def _unhandled(_request: Request, exc: Exception):
    print("[edr] unhandled:", repr(exc))
    return JSONResponse({"detail": "服务器内部错误"}, status_code=500)


from backend.edr_api import router as _edr_router  # noqa: E402

app.include_router(_edr_router)


def _no_cache() -> dict:
    return {"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache"}


def _safe_asset(rel: str):
    raw = str(rel or "").replace("\\", "/").strip()
    if not raw or raw.startswith("/") or ":" in raw or ".." in raw.split("/"):
        return None
    root = DIST.resolve()
    cand = root.joinpath(*[p for p in raw.split("/") if p not in ("", ".")]).resolve()
    try:
        cand.relative_to(root)
    except ValueError:
        return None
    return cand if cand.is_file() and cand.suffix.lower() in _ASSET_EXT else None


@app.get("/", response_class=HTMLResponse)
@app.get("/{full_path:path}", response_class=HTMLResponse)
def spa(full_path: str = ""):
    if full_path.startswith("api/"):
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    asset = _safe_asset(full_path) if full_path else None
    if asset is not None:
        cache = {"Cache-Control": "public, max-age=31536000, immutable"} if full_path.startswith("assets/") else {}
        return FileResponse(asset, headers=cache)
    index = DIST / "index.html"
    if index.is_file():
        return HTMLResponse(index.read_text(encoding="utf-8"), headers=_no_cache())
    return HTMLResponse(
        "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='UTF-8'><title>EDR 后台未构建</title></head>"
        "<body style='font-family:sans-serif;padding:40px'><h2>EDR 后台前端尚未构建</h2>"
        "<p>请在 <code>agent_admin</code> 执行 <code>npm install && npm run build</code>。</p></body></html>",
        headers=_no_cache(),
    )


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="EDR 后台")
    ap.add_argument("--host", default=os.getenv("EDR_HOST") or "0.0.0.0")
    ap.add_argument("--port", type=int, default=EDR_PORT)
    ap.add_argument("--reload", action="store_true", help="开发模式：Python 改动自动重载")
    ap.add_argument("--reset-admin", action="store_true", help="重置 admin 密码并打印")
    args = ap.parse_args()

    if args.reset_admin:
        from backend.edr_auth import reset_admin_cli
        print("EDR admin 新密码（首次登录须修改）：", reset_admin_cli())
        sys.exit(0)

    import uvicorn

    print(f"EDR 后台启动: http://localhost:{args.port}/")
    if args.reload:
        uvicorn.run("edr_server:app", host=args.host, port=args.port, reload=True,
                    timeout_graceful_shutdown=10,
                    reload_dirs=[str(ROOT / "backend"), str(ROOT)], reload_includes=["edr_server.py", "*.py"],
                    reload_excludes=["**/reports/*", "**/__pycache__/*", "**/node_modules/*"])
    else:
        uvicorn.run(app, host=args.host, port=args.port, timeout_graceful_shutdown=10)
