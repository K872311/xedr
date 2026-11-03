"""EDR 后台 API（独立进程 edr_server.py 挂载）。

- /api/edr/*   ：EDR 自己的登录、账号、配置
- /api/agent/* ：终端上报（接入密钥）+ 管理台接口（EDR 会话）
与分析平台账号完全隔离：只认 edr_sid 会话，不认分析平台的 forensic_sid。
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

from . import edr_auth
from .http_security import client_ip

router = APIRouter()

SERVER_URL_META_KEY = "edr_server_url"


# ---------- 鉴权 ----------

def _token(request: Request) -> str:
    return edr_auth.token_from_request(
        request.headers.get("cookie") or "", request.headers.get("authorization") or ""
    )


def _require_user(request: Request, *, allow_must_change: bool = False) -> Dict[str, Any]:
    user = edr_auth.me(_token(request))
    if not user:
        raise HTTPException(401, detail="未登录或会话已过期")
    if user.get("must_change") and not allow_must_change:
        raise HTTPException(403, detail="首次登录请先修改密码")
    return user


def _require_admin(request: Request) -> Dict[str, Any]:
    user = _require_user(request)
    if user.get("role") != "admin":
        raise HTTPException(403, detail="需要管理员权限")
    return user


def _require_agent_or_user(request: Request) -> Dict[str, Any]:
    """终端 Agent 用接入密钥；管理台用 EDR 会话。"""
    from .agent_protocol import verify_enroll_key
    auth = str(request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        auth = auth[7:].strip()
    if verify_enroll_key(auth):
        return {"id": "agent-enroll", "username": "agent", "role": "agent", "agent": True}
    return _require_user(request)


def _bearer(request: Request) -> str:
    auth = str(request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        auth = auth[7:].strip()
    return auth


def _agent_auth(request: Request, agent_id: str = "", *, register: bool = False) -> Dict[str, Any]:
    """Agent 端点鉴权，返回 {cred, agent_id, ...}。

    1) 每 Agent 凭据（fa_ 前缀 + X-Agent-Id）：身份固定，payload 里的 agent_id 必须一致；
    2) 共享接入密钥：仅用于首次注册；若该 Agent 已有独立凭据或被吊销，共享密钥不再能冒充它；
       管理员关闭 allow_shared_key 后，共享密钥只能 register；
    3) 管理台会话：沿用原行为。
    """
    from . import agent_protocol as ap
    tok = _bearer(request)
    claimed = str(agent_id or "").strip()
    if tok.startswith(ap.SECRET_PREFIX):
        hdr = str(request.headers.get("x-agent-id") or "").strip()
        aid = hdr or claimed
        st = ap.verify_agent_secret(aid, tok)
        if st == "revoked":
            raise HTTPException(403, detail="该 Agent 已被吊销")
        if st != "ok":
            raise HTTPException(401, detail="Agent 凭据无效")
        if claimed and claimed != aid:
            raise HTTPException(403, detail="agent_id 与凭据不匹配")
        return {"id": f"agent:{aid}", "username": "agent", "role": "agent", "agent": True,
                "cred": "secret", "agent_id": aid}
    if ap.verify_enroll_key(tok):
        if not register:
            if not ap.shared_key_allowed():
                raise HTTPException(401, detail="共享接入密钥已停用，请使用 Agent 独立凭据")
            if claimed:
                st = ap.agent_auth_state(claimed)
                if st["revoked"]:
                    raise HTTPException(403, detail="该 Agent 已被吊销")
                if st["has_secret"]:
                    raise HTTPException(403, detail="该 Agent 已启用独立凭据，共享密钥不再接受")
        return {"id": "agent-enroll", "username": "agent", "role": "agent", "agent": True,
                "cred": "enroll", "agent_id": claimed}
    user = _require_user(request)
    return {**user, "cred": "user", "agent_id": claimed}


def _actor(user: Dict[str, Any]) -> str:
    return str(user.get("username") or "admin")


def _audit(action: str, user: Optional[Dict[str, Any]] = None, *, detail: str = "", agent_id: str = "") -> None:
    try:
        from . import agent_edr
        agent_edr.ensure()
        agent_edr._audit(action, agent_id=agent_id, detail=detail, actor=_actor(user or {}) if user else "")
    except Exception as e:
        print("[edr-audit]", e)


def _set_cookie(resp: Response, request: Request, token: str) -> None:
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "http").split(",")[0].strip()
    resp.set_cookie(
        edr_auth.COOKIE_NAME, token, max_age=edr_auth.SESSION_TTL,
        httponly=True, samesite="strict", path="/", secure=(proto == "https"),
    )


# ---------- EDR 自身：登录 / 账号 ----------

@router.post("/api/edr/auth/login")
def edr_login(request: Request, data: dict = Body(...)):
    from .ratelimit import check_login_allowed, record_login_failure, record_login_success
    ip = client_ip(request)
    uname = str((data or {}).get("username") or "").strip()
    rl_key = "edr:" + uname
    try:
        check_login_allowed(ip, rl_key)
    except ValueError as e:
        raise HTTPException(429, detail=str(e))
    try:
        out = edr_auth.login(uname, str((data or {}).get("password") or ""), ip=ip)
    except ValueError as e:
        record_login_failure(ip, rl_key)
        _audit("edr_login_failed", None, detail=f"{uname} @ {ip}")
        msg = str(e)
        raise HTTPException(400, detail=msg if "禁用" in msg else "用户名或密码错误")
    record_login_success(ip, rl_key)
    _audit("edr_login", out["user"], detail=f"@ {ip}")
    resp = JSONResponse({"user": out["user"]})
    _set_cookie(resp, request, out["token"])
    return resp


@router.post("/api/edr/auth/logout")
def edr_logout(request: Request):
    tok = _token(request)
    user = edr_auth.me(tok)
    edr_auth.logout(tok)
    if user:
        _audit("edr_logout", user)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(edr_auth.COOKIE_NAME, path="/")
    return resp


@router.get("/api/edr/auth/session")
def edr_session(request: Request):
    user = _require_user(request, allow_must_change=True)
    return {"user": user}


@router.post("/api/edr/auth/change-password")
def edr_change_password(request: Request, data: dict = Body(...)):
    user = _require_user(request, allow_must_change=True)
    try:
        edr_auth.change_own_password(
            user["id"],
            str((data or {}).get("current_password") or ""),
            str((data or {}).get("new_password") or ""),
            keep_token=_token(request),
        )
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("edr_change_password", user)
    return {"ok": True, "user": edr_auth.me(_token(request))}


@router.get("/api/edr/users")
def edr_users_list(request: Request):
    _require_admin(request)
    return {"items": edr_auth.list_users(), "roles": edr_auth.ROLE_LABELS}


@router.post("/api/edr/users")
def edr_users_create(request: Request, data: dict = Body(...)):
    user = _require_admin(request)
    d = data or {}
    try:
        out = edr_auth.create_user(
            str(d.get("username") or ""), str(d.get("password") or ""),
            role=str(d.get("role") or "analyst"), display_name=str(d.get("display_name") or ""),
            must_change=bool(d.get("must_change", True)),
        )
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("edr_user_create", user, detail=f"{out['username']} ({out['role']})")
    return out


@router.patch("/api/edr/users/{uid}")
def edr_users_update(uid: str, request: Request, data: dict = Body(...)):
    user = _require_admin(request)
    d = data or {}
    if uid == user["id"] and (d.get("enabled") is False or (d.get("role") and d.get("role") != "admin")):
        raise HTTPException(400, detail="不能禁用或降级自己")
    try:
        out = edr_auth.update_user(
            uid,
            role=d.get("role"),
            enabled=d.get("enabled") if "enabled" in d else None,
            display_name=d.get("display_name"),
        )
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("edr_user_update", user, detail=f"{out['username']} role={out['role']} enabled={out['enabled']}")
    return out


@router.post("/api/edr/users/{uid}/reset-password")
def edr_users_reset(uid: str, request: Request, data: dict = Body(...)):
    user = _require_admin(request)
    try:
        edr_auth.reset_password(uid, str((data or {}).get("password") or ""), must_change=True)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("edr_user_reset_password", user, detail=uid)
    return {"ok": True}


@router.delete("/api/edr/users/{uid}")
def edr_users_delete(uid: str, request: Request):
    user = _require_admin(request)
    if uid == user["id"]:
        raise HTTPException(400, detail="不能删除自己")
    try:
        edr_auth.delete_user(uid)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("edr_user_delete", user, detail=uid)
    return {"ok": True}


# ---------- EDR 自身：回连地址 ----------

def _meta_get(key: str) -> str:
    from . import agent_protocol
    agent_protocol.ensure_db()
    with agent_protocol._lock:
        conn = agent_protocol._connect()
        try:
            row = conn.execute("SELECT value FROM agent_meta WHERE key=?", (key,)).fetchone()
            return str(row["value"] or "") if row else ""
        finally:
            conn.close()


def _meta_set(key: str, value: str) -> None:
    from . import agent_protocol
    agent_protocol.ensure_db()
    with agent_protocol._lock:
        conn = agent_protocol._connect()
        try:
            conn.execute(
                """INSERT INTO agent_meta(key, value) VALUES(?,?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (key, value),
            )
            conn.commit()
        finally:
            conn.close()


def _is_loopback_url(url: str) -> bool:
    u = str(url or "").lower()
    return any(h in u for h in ("://127.0.0.1", "://localhost", "://[::1]", "://0.0.0.0"))


def _normalize_server_url(url: str) -> str:
    return str(url or "").strip().rstrip("/")[:400]


def _public_base_url(request: Request) -> str:
    """安装包内嵌的回连地址：优先 EDR 配置，其次当前访问地址；拒绝 127.0.0.1。"""
    configured = _normalize_server_url(_meta_get(SERVER_URL_META_KEY))
    if configured and not _is_loopback_url(configured):
        return configured
    xf_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    xf_host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
    host = xf_host or request.headers.get("host") or ""
    detected = _normalize_server_url(f"{xf_proto or request.url.scheme or 'http'}://{host}") if host else ""
    if not detected or _is_loopback_url(detected):
        raise HTTPException(
            400,
            detail="当前访问地址是 127.0.0.1，装到别的机器连不上。"
                   "请先在「配置 → 接入与地址」填写 EDR 平台地址（如 http://<平台IP>:8100），或用局域网 IP 打开后台再下载。",
        )
    return detected


@router.get("/api/edr/settings")
def edr_settings_get(request: Request):
    _require_user(request)
    return {"agent_server_url": _meta_get(SERVER_URL_META_KEY)}


@router.get("/api/edr/overview")
def api_edr_overview(request: Request, online_within_sec: int = Query(45)):
    _require_user(request)
    from .edr_overview import get_overview
    return get_overview(online_within_sec=max(12, min(int(online_within_sec or 45), 3600)))


@router.put("/api/edr/settings")
def edr_settings_set(request: Request, data: dict = Body(...)):
    user = _require_admin(request)
    url = _normalize_server_url((data or {}).get("agent_server_url") or "")
    if url and not url.lower().startswith(("http://", "https://")):
        raise HTTPException(400, detail="地址需以 http:// 或 https:// 开头")
    if url and _is_loopback_url(url):
        raise HTTPException(400, detail="不能填 127.0.0.1 / localhost，终端连不上")
    _meta_set(SERVER_URL_META_KEY, url)
    _audit("edr_settings", user, detail=f"agent_server_url={url}")
    return {"ok": True, "agent_server_url": url}


# ---------- 终端接入 / 管理 ----------

@router.get("/api/agent/protocol")
def api_agent_protocol(request: Request):
    _require_user(request)
    from .agent_protocol import protocol_info
    return protocol_info()


@router.get("/api/agent/list")
def api_agent_list(request: Request, online_within_sec: int = Query(45, ge=12, le=3600)):
    _require_user(request)
    from .agent_protocol import list_agents
    return list_agents(online_within_sec=online_within_sec)


@router.get("/api/agent/stream")
async def api_agent_stream(request: Request, last_rev: int = Query(0, ge=0)):
    """SSE：Agent 心跳/快照/事件变更时推送，供管理台静默刷新。"""
    _require_user(request)
    from .agent_protocol import async_iter_live_sse
    return StreamingResponse(
        async_iter_live_sse(request, last_rev),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@router.post("/api/agent/register")
def api_agent_register(request: Request, payload: dict = Body(...)):
    p = payload or {}
    who = _agent_auth(request, str(p.get("agent_id") or ""), register=True)
    from .agent_protocol import register_agent
    out = register_agent(p, cred=who.get("cred", "user"))
    if not out.get("ok"):
        raise HTTPException(403, detail=out.get("error") or "注册被拒绝")
    # 用独立凭据注册时，agent_id 必须与凭据一致（防止凭据 A 改写 B 的记录）
    if who.get("cred") == "secret" and out.get("agent_id") != who.get("agent_id"):
        raise HTTPException(403, detail="agent_id 与凭据不匹配")
    return out


@router.post("/api/agent/heartbeat")
def api_agent_heartbeat(request: Request, payload: dict = Body(...)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from .agent_protocol import heartbeat
    out = heartbeat(payload or {})
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "heartbeat 失败")
    return out


@router.post("/api/agent/snapshot")
def api_agent_snapshot(request: Request, payload: dict = Body(...)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from .agent_protocol import upsert_snapshot
    out = upsert_snapshot(payload or {})
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "snapshot 失败")
    return out


@router.get("/api/agent/install-package")
def api_agent_install_package(request: Request, require_latest: bool = Query(False)):
    """管理员下载开箱安装包：已写入 EDR 平台地址 + 接入密钥。

    响应头 X-Agent-* 给出版本/构建/SHA256/是否最新版；require_latest=1 时非最新版拒绝下载。
    """
    user = _require_admin(request)
    from pathlib import Path as _Path

    from . import agent_release
    from .agent_protocol import build_install_package
    rel = agent_release.release_status()
    if require_latest and not rel.get("is_latest"):
        raise HTTPException(409, detail="当前 Agent 不是最新构建：" + "；".join(rel.get("reasons") or [rel.get("status", "")]))
    try:
        data, filename = build_install_package(server_url=_public_base_url(request))
    except FileNotFoundError as e:
        raise HTTPException(404, detail=str(e))
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("agent_install_package", user, detail=f"{filename} status={rel.get('status')} sha={str(rel.get('exe_sha256',''))[:12]}")
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
        "X-Agent-Status": str(rel.get("status", "")),
        "X-Agent-Is-Latest": "1" if rel.get("is_latest") else "0",
        "X-Agent-Version": str(rel.get("version") or rel.get("source_version") or ""),
        "X-Agent-Build-Id": str(rel.get("build_id") or ""),
        "X-Agent-Build-Time": str(rel.get("build_time") or ""),
        "X-Agent-Sha256": str(rel.get("exe_sha256") or ""),
        "Access-Control-Expose-Headers": "X-Agent-Status,X-Agent-Is-Latest,X-Agent-Version,X-Agent-Build-Id,X-Agent-Build-Time,X-Agent-Sha256",
    }
    # 磁盘缓存命中时走 FileResponse，避免再整包读入内存
    if isinstance(data, _Path):
        return FileResponse(
            path=str(data),
            media_type="application/zip",
            filename=filename,
            headers=headers,
        )
    return Response(content=data, media_type="application/zip", headers=headers)


@router.get("/api/agent/release")
def api_agent_release(request: Request):
    """当前可下发 Agent 的发布状态（版本/构建/SHA256/是否最新）。"""
    _require_admin(request)
    from . import agent_release
    return agent_release.release_status()


@router.post("/api/agent/release/build")
def api_agent_release_build(request: Request):
    """后台触发 scripts/build_agent.py 重新构建（需服务器有 Go）。"""
    user = _require_admin(request)
    import threading

    from . import agent_release
    if agent_release._build_state.get("running"):
        raise HTTPException(409, detail="已有构建正在进行")
    if not agent_release._find_go():
        raise HTTPException(400, detail="服务器未安装 Go，无法在线构建")
    threading.Thread(target=agent_release.run_build, daemon=True, name="agent-build").start()
    _audit("agent_release_build", user)
    return {"ok": True, "started": True}


@router.post("/api/agent/v2/events/batch")
def api_agent_v2_batch(request: Request, payload: dict = Body(...)):
    """v2 幂等批量上报（见 agent_ingest_v2）。身份以凭据为准。"""
    p = payload or {}
    who = _agent_auth(request, str(p.get("agent_id") or ""))
    aid = who.get("agent_id") or str(p.get("agent_id") or "")
    if not aid:
        raise HTTPException(400, detail="缺少 agent_id")
    from . import agent_ingest_v2
    out = agent_ingest_v2.ingest_batch(aid, p.get("events") or [], stream=str(p.get("stream") or "main"))
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "批量上报失败")
    return out


@router.post("/api/agent/credential/rotate")
def api_agent_credential_rotate(request: Request, payload: dict = Body(default={})):
    """Agent 自助轮换凭据（须用现有独立凭据调用）。"""
    who = _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    if who.get("cred") != "secret":
        raise HTTPException(403, detail="仅持有独立凭据的 Agent 可轮换")
    from .agent_protocol import rotate_agent_secret
    out = rotate_agent_secret(who["agent_id"])
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "轮换失败")
    return out


@router.post("/api/agent/{agent_id}/revoke")
def api_agent_revoke(agent_id: str, request: Request, payload: dict = Body(default={})):
    """管理员吊销/恢复某 Agent：吊销后其凭据与共享密钥都无法再接入。"""
    user = _require_admin(request)
    from .agent_protocol import set_agent_revoked
    revoked = bool((payload or {}).get("revoked", True))
    out = set_agent_revoked(agent_id, revoked)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "失败")
    _audit("agent_revoke" if revoked else "agent_restore", user, agent_id=agent_id)
    return out


@router.get("/api/agent/credentials")
def api_agent_credentials(request: Request):
    _require_admin(request)
    from .agent_protocol import credential_summary
    return {"ok": True, **credential_summary()}


@router.post("/api/agent/credentials/policy")
def api_agent_credentials_policy(request: Request, payload: dict = Body(...)):
    """是否仍接受共享接入密钥访问已注册 Agent 的业务端点（register 始终允许）。"""
    user = _require_admin(request)
    from .agent_protocol import credential_summary, set_shared_key_allowed
    allowed = bool((payload or {}).get("allow_shared_key", True))
    set_shared_key_allowed(allowed)
    _audit("agent_shared_key_policy", user, detail=f"allow_shared_key={allowed}")
    return {"ok": True, **credential_summary()}


@router.post("/api/agent/enroll-key/rotate")
def api_agent_enroll_rotate(request: Request):
    """轮换接入密钥（已装 Agent 需重新下载安装包）。"""
    user = _require_admin(request)
    from .agent_protocol import get_or_create_enroll_key
    key = get_or_create_enroll_key(rotate=True)
    _audit("agent_enroll_rotate", user)
    return {"ok": True, "rotated": True, "hint": key[:6] + "…" + key[-4:]}


@router.get("/api/agent/rules")
def api_agent_rules(request: Request):
    _require_user(request)
    from . import agent_rules
    return agent_rules.list_platform_rule_stats()


@router.post("/api/agent/sync")
def api_agent_sync(request: Request, payload: dict = Body(default_factory=dict)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from . import agent_sync
    aid = str((payload or {}).get("agent_id") or "").strip()
    since = int((payload or {}).get("since_rev") or 0)
    parts = (payload or {}).get("parts")
    if isinstance(parts, list):
        parts = [str(p) for p in parts][:16]
    else:
        parts = None
    return agent_sync.bundle(aid, since, parts=parts)


@router.get("/api/edr/agent-sync/manifest")
def api_edr_agent_sync_manifest(request: Request):
    _require_user(request)
    from . import agent_sync
    return agent_sync.manifest()


@router.post("/api/edr/agent-sync/bump")
def api_edr_agent_sync_bump(request: Request, payload: dict = Body(default_factory=dict)):
    """管理员手动递增 sync_rev，强制在线 Agent 下次轮询全量/增量同步。"""
    _require_admin(request)
    from . import agent_sync
    part = str((payload or {}).get("part") or "manual")[:32]
    rev = agent_sync.bump_sync(part)
    return {"ok": True, "sync_rev": rev, "manifest": agent_sync.manifest()}


@router.get("/api/edr/agent-integrations")
def api_edr_agent_integrations_get(request: Request):
    _require_user(request)
    from . import agent_sync
    return agent_sync.get_integrations_document()


@router.put("/api/edr/agent-integrations")
def api_edr_agent_integrations_put(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_sync
    body = payload or {}
    updates = body.get("defaults") if isinstance(body.get("defaults"), dict) else {}
    if not updates and isinstance(body, dict) and "server" not in body:
        updates = {k: v for k, v in body.items() if isinstance(v, bool)}
    server = body.get("server") if isinstance(body.get("server"), dict) else None
    return agent_sync.save_integrations_defaults(
        updates if isinstance(updates, dict) else {},
        server_updates=server,
    )


@router.post("/api/agent/memory-yara")
def api_agent_memory_yara(request: Request, payload: dict = Body(default_factory=dict)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from . import memory_yara
    rev = str((payload or {}).get("rev") or "").strip()
    out = memory_yara.bundle(rev)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "规则包不可用")
    return out


@router.get("/api/edr/memory-yara")
def api_edr_memory_yara_list(request: Request):
    _require_user(request)
    from . import memory_yara
    return memory_yara.list_rules()


@router.put("/api/edr/memory-yara/controls")
def api_edr_memory_yara_controls_set(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import memory_yara
    doc = memory_yara.save_controls(payload or {})
    return {"ok": True, "controls": doc, "pack": memory_yara.list_rules()}


@router.post("/api/agent/rules")
def api_agent_rules_create(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_rules
    try:
        return agent_rules.create_rule(payload or {})
    except ValueError as e:
        raise HTTPException(400, detail=str(e))


@router.put("/api/agent/rules/{rule_id}")
def api_agent_rules_update(rule_id: str, request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_rules
    try:
        return agent_rules.update_rule(rule_id, payload or {})
    except ValueError as e:
        raise HTTPException(400, detail=str(e))


@router.patch("/api/agent/rules/{rule_id}")
def api_agent_rules_patch(rule_id: str, request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_rules
    try:
        if "enabled" in (payload or {}):
            return agent_rules.set_rule_enabled(rule_id, bool(payload.get("enabled")))
        return agent_rules.update_rule(rule_id, payload or {})
    except ValueError as e:
        raise HTTPException(400, detail=str(e))


@router.delete("/api/agent/rules/{rule_id}")
def api_agent_rules_delete(rule_id: str, request: Request):
    _require_admin(request)
    from . import agent_rules
    try:
        return agent_rules.delete_rule(rule_id)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))


@router.post("/api/agent/rules/bulk-enabled")
def api_agent_rules_bulk_enabled(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import agent_rules

    body = payload or {}
    enabled = bool(body.get("enabled", True))
    ids = body.get("rule_ids") or body.get("ids")
    if ids is not None and not isinstance(ids, list):
        raise HTTPException(400, detail="rule_ids 须为数组")
    source = str(body.get("source") or "")
    if body.get("all_filtered") and isinstance(ids, list):
        out = agent_rules.bulk_set_rules_enabled(enabled, rule_ids=[str(x) for x in ids], source=source)
    elif body.get("all_elastic"):
        out = agent_rules.bulk_set_rules_enabled(enabled, source="elastic")
    elif body.get("all_custom"):
        out = agent_rules.bulk_set_rules_enabled(enabled, source="custom")
    elif body.get("all_sensor"):
        out = agent_rules.bulk_set_rules_enabled(enabled, source="sensor")
    elif body.get("all"):
        out = agent_rules.bulk_set_rules_enabled(
            enabled,
            rule_ids=[str(r.get("id")) for r in agent_rules.list_rules() if r.get("id")],
        )
    elif isinstance(ids, list) and ids:
        out = agent_rules.bulk_set_rules_enabled(enabled, rule_ids=[str(x) for x in ids], source=source)
    else:
        raise HTTPException(400, detail="需要 rule_ids、all_filtered、all_elastic 等参数")
    user = getattr(request.state, "user", None) or {}
    _audit("agent_rules_bulk", user, detail=f"enabled={enabled} changed={out.get('changed')}")
    return out


@router.post("/api/edr/elastic-detection/evm/bulk-enabled")
def api_elastic_evm_bulk_enabled(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import elastic_detection_import as edi

    body = payload or {}
    out = edi.bulk_set_evm_enabled(
        bool(body.get("enabled", True)),
        rule_ids=[str(x) for x in (body.get("rule_ids") or [])] if body.get("rule_ids") else None,
        all_rules=bool(body.get("all")),
    )
    return out


@router.get("/api/edr/elastic-detection/es/status")
def api_elastic_detection_es_status(request: Request):
    _require_user(request)
    from . import elastic_detection_es as edes
    return edes.status()


@router.post("/api/edr/elastic-detection/es/run")
def api_elastic_detection_es_run(request: Request):
    _require_admin(request)
    from . import elastic_detection_es as edes
    return edes.run_detection_cycle(force=True)


@router.post("/api/edr/elastic-detection/es/publish-rules")
def api_elastic_detection_es_publish(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import elastic_detection_es as edes
    max_r = int((payload or {}).get("max_rules") or 2000)
    return edes.publish_detection_rules_to_es(max_rules=max_r)


@router.get("/api/edr/elastic-detection/rule/{rule_id}")
def api_elastic_detection_rule_detail(request: Request, rule_id: str):
    _require_user(request)
    from . import elastic_detection_import as edi

    return edi.get_official_rule_detail(rule_id)


@router.get("/api/edr/elastic-detection/catalog")
def api_elastic_detection_catalog(
    request: Request,
    q: str = "",
    platform: str = "",
    status: str = "",
    limit: int = 100,
    offset: int = 0,
    refresh: bool = False,
):
    _require_user(request)
    from . import elastic_detection_import as edi

    if refresh:
        cat = edi.scan_catalog(platform=platform)
        edi.save_catalog(cat)
    else:
        cat = edi.load_catalog()
    items = list(cat.get("items") or [])
    qn = str(q or "").strip().lower()
    st = str(status or "").strip().lower()
    plat = str(platform or "").strip().lower()
    if plat:
        items = [x for x in items if str(x.get("platform") or "").lower() == plat]
    if st:
        items = [x for x in items if str(x.get("status") or "").lower() == st]
    if qn:
        items = [
            x for x in items
            if qn in str(x.get("name") or "").lower()
            or qn in str(x.get("id") or "").lower()
            or qn in str(x.get("rel_path") or "").lower()
        ]
    total = len(items)
    off = max(0, int(offset or 0))
    lim = max(1, min(int(limit or 100), 500))
    return {
        "ok": True,
        "stats": cat.get("stats") or {},
        "scanned_at": cat.get("scanned_at"),
        "total": total,
        "items": items[off : off + lim],
    }


@router.post("/api/edr/elastic-detection/scan")
def api_elastic_detection_scan(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import elastic_detection_import as edi

    platform = str((payload or {}).get("platform") or "")
    max_files = int((payload or {}).get("max_files") or 0)
    cat = edi.scan_catalog(platform=platform, max_files=max_files)
    path = edi.save_catalog(cat)
    user = getattr(request.state, "user", None) or {}
    _audit("elastic_detection_scan", user, detail=str(path))
    return {"ok": True, "path": str(path), **cat}


@router.post("/api/edr/elastic-detection/import")
def api_elastic_detection_import(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import elastic_detection_import as edi

    body = payload or {}
    ids = body.get("rule_ids") or body.get("ids") or []
    if not isinstance(ids, list):
        raise HTTPException(400, detail="rule_ids 须为数组")
    enable = bool(body.get("enable", False))
    dry_run = bool(body.get("dry_run", True))
    mode = str(body.get("mode") or "both")
    en_a = body.get("enable_agent")
    en_e = body.get("enable_evm")
    out = edi.import_rules(
        [str(x) for x in ids],
        enable=enable,
        enable_agent=en_a if "enable_agent" in body else None,
        enable_evm=en_e if "enable_evm" in body else None,
        mode=mode,
        dry_run=dry_run,
    )
    user = getattr(request.state, "user", None) or {}
    _audit(
        "elastic_detection_import",
        user,
        detail=f"dry_run={dry_run} enable={enable} n={len(ids)} created={len(out.get('created') or [])}",
    )
    return out


@router.get("/api/edr/wazuh-sca/catalog")
def api_wazuh_sca_catalog(
    request: Request,
    q: str = "",
    platform: str = "",
    limit: int = 100,
    offset: int = 0,
    refresh: bool = False,
):
    _require_user(request)
    from . import wazuh_ruleset as wr

    cat = wr.scan_catalog(platform=platform) if refresh else wr.load_catalog()
    if refresh:
        wr.save_catalog(cat)
    items = list(cat.get("items") or [])
    qn = str(q or "").strip().lower()
    plat = str(platform or "").strip().lower()
    if plat:
        items = [x for x in items if str(x.get("platform") or "").lower() == plat]
    if qn:
        items = [
            x for x in items
            if qn in str(x.get("name") or "").lower()
            or qn in str(x.get("policy_id") or "").lower()
            or qn in str(x.get("file") or "").lower()
        ]
    total = len(items)
    off = max(0, int(offset or 0))
    lim = max(1, min(int(limit or 100), 500))
    return {
        "ok": True,
        "stats": cat.get("stats") or {},
        "mitre_json": wr.mitre_enterprise_path(),
        "total": total,
        "items": items[off : off + lim],
    }


@router.post("/api/edr/wazuh-sca/scan")
def api_wazuh_sca_scan(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import wazuh_ruleset as wr

    platform = str((payload or {}).get("platform") or "")
    max_files = int((payload or {}).get("max_files") or 0)
    cat = wr.scan_catalog(platform=platform, max_files=max_files)
    path = wr.save_catalog(cat)
    user = getattr(request.state, "user", None) or {}
    _audit("wazuh_sca_scan", user, detail=str(path))
    return {"ok": True, "path": str(path), **cat}


@router.get("/api/edr/detection-corpus/status")
def api_detection_corpus_status(request: Request):
    _require_user(request)
    from .detection_corpus_bootstrap import corpus_status
    return corpus_status()


@router.post("/api/edr/detection-corpus/bootstrap")
def api_detection_corpus_bootstrap(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from .detection_corpus_bootstrap import ensure_detection_corpus

    body = payload or {}
    out = ensure_detection_corpus(
        force=bool(body.get("force")),
        skip_elastic_import=bool(body.get("skip_elastic_import")),
    )
    user = getattr(request.state, "user", None) or {}
    _audit("detection_corpus_bootstrap", user, detail=str(out.get("marker") or ""))
    return out


@router.post("/api/edr/wazuh-sca/build-bundle")
def api_wazuh_sca_build_bundle(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import agent_sync, wazuh_ruleset as wr

    body = payload or {}
    ids = body.get("policy_ids") or body.get("policies")
    if ids is not None and not isinstance(ids, list):
        raise HTTPException(400, detail="policy_ids 须为数组")
    max_per = int(body.get("max_checks_per_policy") or 0)
    doc = wr.build_agent_bundle(
        policy_ids=[str(x) for x in ids] if isinstance(ids, list) else None,
        platform=str(body.get("platform") or "windows"),
        max_checks_per_policy=max_per,
    )
    if "max_checks_per_run" in body:
        doc["max_checks_per_run"] = int(body.get("max_checks_per_run") or 48)
    path = wr.save_agent_bundle(doc)
    agent_sync.bump_sync("sca")
    user = getattr(request.state, "user", None) or {}
    _audit("wazuh_sca_build_bundle", user, detail=str(path))
    return {"ok": True, "path": str(path), "policies": len(doc.get("policies") or []), "bundle": doc}


@router.get("/api/agent/events/{event_id}")
def api_agent_event_get(event_id: int, request: Request):
    _require_user(request)
    from .agent_protocol import get_event
    r = get_event(event_id)
    if not r.get("ok"):
        raise HTTPException(404, r.get("error") or "事件不存在")
    return r


@router.get("/api/agent/events/{event_id}/related")
def api_agent_event_related(event_id: int, request: Request, limit: int = Query(20, ge=1, le=50)):
    _require_user(request)
    from .agent_protocol import related_events_by_payload
    return related_events_by_payload(event_id, limit=limit)


@router.post("/api/agent/event")
def api_agent_event(request: Request, payload: dict = Body(...)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from .agent_protocol import report_event
    out = report_event(payload or {})
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "事件写入失败")
    return out


@router.post("/api/edr/events/enrich-details")
def api_edr_events_enrich_details(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from .agent_protocol import enrich_event_details, get_event
    body = payload or {}
    eid = body.get("event_id")
    if eid is not None:
        get_event(int(eid))
        return get_event(int(eid))
    limit = int(body.get("limit") or 500)
    return enrich_event_details(limit=max(1, min(limit, 2000)))


@router.get("/api/agent/events")
def api_agent_events(
    request: Request,
    status: str = Query(""),
    agent_id: str = Query(""),
    limit: int = Query(100, ge=1, le=500),
    sync: int = Query(0, ge=0, le=1),
):
    _require_user(request)
    from .agent_protocol import list_events
    from . import agent_edr
    # 先返回列表，避免 sync 晋升拖慢首屏；sync 在列表之后后台式执行（同请求末尾）
    out = list_events(status=status, agent_id=agent_id, limit=limit)
    if int(sync or 0) == 1:
        try:
            synced = agent_edr.sync_threats_from_timeline(limit=400)
            out["sync"] = synced
            # 晋升后若有新增，再补一刀轻量列表
            if isinstance(synced, dict) and int(synced.get("promoted") or 0) > 0:
                out = list_events(status=status, agent_id=agent_id, limit=limit)
                out["sync"] = synced
        except Exception as e:
            out["sync"] = {"ok": False, "error": str(e)}
    return out


@router.patch("/api/agent/events/{event_id}")
def api_agent_event_update(event_id: int, request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from .agent_protocol import update_event
    out = update_event(event_id, status=str((payload or {}).get("status") or ""))
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "更新失败")
    return out


@router.delete("/api/agent/events")
def api_agent_events_delete_bulk(
    request: Request,
    status: str = Query(""),
    agent_id: str = Query(""),
    severity: str = Query(""),
):
    user = _require_admin(request)
    from .agent_protocol import delete_events
    out = delete_events(status=status, agent_id=agent_id, severity=severity)
    _audit("events_delete_bulk", user, agent_id=agent_id,
           detail=f"status={status or '*'} severity={severity or '*'} deleted={out.get('deleted', 0)}")
    return out


@router.delete("/api/agent/events/{event_id}")
def api_agent_event_delete(event_id: int, request: Request):
    _require_admin(request)
    from .agent_protocol import delete_event
    out = delete_event(event_id)
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "删除失败")
    return out


# ---------- 处置 / 时间线 / 策略 / 狩猎 ----------

@router.post("/api/agent/commands/poll")
def api_agent_commands_poll(request: Request, payload: dict = Body(...)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from . import agent_edr
    return agent_edr.poll_commands(str((payload or {}).get("agent_id") or ""))


@router.post("/api/agent/commands/ack")
def api_agent_commands_ack(request: Request, payload: dict = Body(...)):
    from . import agent_edr
    p = payload or {}
    cid = str(p.get("id") or p.get("command_id") or "")
    # 命令所属 Agent 即"声称身份"：独立凭据只能回执自己的命令，已升级 Agent 的命令不能用共享密钥回执
    try:
        owner = agent_edr.command_owner(cid)
    except Exception:
        owner = ""
    who = _agent_auth(request, owner)
    out = agent_edr.ack_command(
        cid,
        ok=bool(p.get("ok", True)),
        result=p.get("result") if isinstance(p.get("result"), dict) else {},
        caller_agent_id=who.get("agent_id", "") if who.get("cred") == "secret" else "",
    )
    if not out.get("ok"):
        raise HTTPException(403 if out.get("forbidden") else 400, detail=out.get("error") or "回执失败")
    return out


@router.post("/api/agent/timeline")
def api_agent_timeline_ingest(request: Request, payload: dict = Body(...)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from . import agent_edr
    out = agent_edr.ingest_timeline(payload or {})
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "写入失败")
    return out


@router.get("/api/agent/timeline")
def api_agent_timeline_list(
    request: Request,
    agent_id: str = Query(""),
    etype: str = Query(""),
    q: str = Query(""),
    kind: str = Query(""),
    limit: int = Query(100, ge=1, le=500),
):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_timeline(agent_id, etype=etype, q=q, kind=kind, limit=limit)


@router.get("/api/agent/dns")
def api_agent_dns_hunt(
    request: Request,
    q: str = Query(""),
    agent_id: str = Query(""),
    nx_only: int = Query(0),
    match_ioc: int = Query(1),
    limit: int = Query(200, ge=1, le=1000),
):
    """DNS 域名聚合；默认用项目根 ioc_data.db 对域名/应答 IP 做精确匹配。"""
    _require_user(request)
    from . import agent_telemetry
    return agent_telemetry.list_dns(
        agent_id,
        q=q.strip(),
        nx_only=bool(nx_only),
        limit=limit,
        match_ioc=bool(match_ioc),
    )


@router.get("/api/agent/{agent_id}/processes")
def api_agent_processes(
    agent_id: str,
    request: Request,
    q: str = Query(""),
    alive: str = Query(""),
    limit: int = Query(200, ge=1, le=1000),
):
    _require_user(request)
    from . import agent_telemetry
    flag = {"1": True, "true": True, "0": False, "false": False}.get(alive.strip().lower())
    return agent_telemetry.list_processes(agent_id, q=q.strip(), alive=flag, limit=limit)


@router.get("/api/agent/{agent_id}/process/{entity_id}")
def api_agent_process_detail(agent_id: str, entity_id: str, request: Request, events_limit: int = Query(200, ge=1, le=1000)):
    """进程实体：祖先链、子进程、按实体归属的全部事件（网络/DNS/文件/DLL…）。"""
    _require_user(request)
    from . import agent_telemetry
    out = agent_telemetry.process_detail(agent_id, entity_id.strip(), events_limit=events_limit)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "进程实体不存在")
    return out


@router.get("/api/agent/investigate")
def api_agent_investigate(
    request: Request,
    q: str = Query(""),
    agent_id: str = Query(""),
    hostname: str = Query(""),
    etype: str = Query(""),
    nature: str = Query(""),
    path: str = Query(""),
    hash_q: str = Query(""),
    range: str = Query("today"),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    hide_proc_noise: int = Query(1),
):
    """日志调查：实时时间线检索。"""
    _require_user(request)
    from . import agent_edr
    return agent_edr.investigate_logs(
        q=q, agent_id=agent_id, hostname=hostname, etype=etype, nature=nature,
        path=path, hash_q=hash_q, range_key=range, limit=limit, offset=offset,
        hide_proc_noise=bool(int(hide_proc_noise if hide_proc_noise is not None else 1)),
    )


@router.get("/api/agent/investigate/{log_id}")
def api_agent_investigate_detail(request: Request, log_id: int):
    _require_user(request)
    from . import agent_edr
    out = agent_edr.get_log_detail(log_id)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "日志不存在")
    return out


@router.get("/api/agent/hunt")
def api_agent_hunt(request: Request, q: str = Query(...), limit: int = Query(100, ge=1, le=300)):
    _require_user(request)
    from . import agent_edr
    out = agent_edr.hunt(q, limit=limit)
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "狩猎失败")
    return out


@router.get("/api/agent/policy")
def api_agent_policy_get(request: Request, scope: str = Query("global")):
    _require_user(request)
    from . import agent_edr
    return agent_edr.get_policy(scope)


@router.put("/api/agent/policy")
def api_agent_policy_set(request: Request, payload: dict = Body(...)):
    user = _require_admin(request)
    from . import agent_edr
    p = payload or {}
    out = agent_edr.set_policy(
        str(p.get("scope") or "global"),
        p.get("policy") if isinstance(p.get("policy"), dict) else {},
        actor=_actor(user),
        note=str(p.get("note") or "")[:200],
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "保存失败")
    return out


@router.get("/api/agent/policy/history")
def api_agent_policy_history(request: Request, scope: str = Query("global"), limit: int = Query(50, ge=1, le=200)):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_policy_history(scope, limit=limit)


@router.post("/api/agent/policy/rollback")
def api_agent_policy_rollback(request: Request, payload: dict = Body(...)):
    user = _require_admin(request)
    from . import agent_edr
    p = payload or {}
    try:
        rev = int(p.get("rev") or 0)
    except (TypeError, ValueError):
        rev = 0
    out = agent_edr.rollback_policy(str(p.get("scope") or "global"), rev, actor=_actor(user))
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "回滚失败")
    _audit("policy_rollback", user, detail=f"to rev {rev} -> new rev {out.get('rev')}")
    return out


@router.get("/api/agent/policy/rollout")
def api_agent_policy_rollout(request: Request, scope: str = Query("global")):
    _require_user(request)
    from . import agent_edr
    return agent_edr.policy_rollout(scope)


@router.get("/api/agent/whitelist")
def api_agent_whitelist_list(request: Request):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_whitelist()


@router.post("/api/agent/whitelist")
def api_agent_whitelist_add(request: Request, payload: dict = Body(...)):
    user = _require_admin(request)
    from . import agent_edr
    p = payload or {}
    try:
        src_eid = int(p.get("source_event_id") or 0)
    except (TypeError, ValueError):
        src_eid = 0
    out = agent_edr.add_whitelist(
        str(p.get("kind") or ""), str(p.get("value") or ""), note=str(p.get("note") or ""),
        agent_id=str(p.get("agent_id") or ""),
        rule=str(p.get("rule") or ""),
        created_by=str(user.get("username") or ""),
        source_event_id=src_eid,
        apply_existing=bool(p.get("apply_existing")),
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "添加失败")
    return out


@router.patch("/api/agent/whitelist/{wid}")
def api_agent_whitelist_patch(wid: str, request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_edr
    out = agent_edr.set_whitelist_enabled(wid, bool((payload or {}).get("enabled")))
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "更新失败")
    return out


@router.get("/api/agent/events/{event_id}/allow-candidates")
def api_agent_event_allow_candidates(event_id: int, request: Request):
    _require_user(request)
    from . import alert_allow
    from .agent_protocol import get_event
    r = get_event(event_id)
    if not r.get("ok"):
        raise HTTPException(404, r.get("error") or "事件不存在")
    ev = r["item"]
    items = alert_allow.candidates(ev)
    return {
        "ok": True,
        "items": items,
        "default_picks": alert_allow.default_allow_pick_indices(items, ev),
        "rule_prefix": alert_allow.rule_prefix(ev.get("title") or ""),
        "agent_id": ev.get("agent_id") or "",
        "hostname": ev.get("hostname") or "",
    }


@router.delete("/api/agent/whitelist/{wid}")
def api_agent_whitelist_del(wid: str, request: Request):
    _require_admin(request)
    from . import agent_edr
    out = agent_edr.delete_whitelist(wid)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "删除失败")
    return out


@router.get("/api/agent/groups")
def api_agent_groups_list(request: Request):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_groups()


@router.put("/api/agent/groups")
def api_agent_groups_upsert(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_edr
    p = payload or {}
    return agent_edr.upsert_group(
        str(p.get("id") or ""), str(p.get("name") or ""),
        list(p.get("agent_ids") or []), note=str(p.get("note") or ""),
    )


@router.get("/api/agent/audit")
def api_agent_audit_list(request: Request, limit: int = Query(100, ge=1, le=500)):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_audit(limit=limit)


@router.get("/api/agent/ioc")
def api_agent_ioc_list(request: Request):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_ioc()


@router.post("/api/agent/ioc")
def api_agent_ioc_add(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_edr
    p = payload or {}
    out = agent_edr.add_ioc(
        str(p.get("ioc_type") or p.get("kind") or "hash"),
        str(p.get("value") or ""),
        severity=str(p.get("severity") or "high"),
        note=str(p.get("note") or ""),
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "添加失败")
    return out


@router.post("/api/agent/ioc/import")
def api_agent_ioc_import(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_edr
    p = payload or {}
    return agent_edr.import_iocs(
        str(p.get("text") or ""),
        ioc_type=str(p.get("ioc_type") or "hash"),
        severity=str(p.get("severity") or "high"),
    )


@router.get("/api/agent/ioc/lib-status")
def api_agent_ioc_lib_status(request: Request):
    """本地 agent_ioc + 情报库 ioc_data.db 状态。"""
    _require_user(request)
    from . import agent_edr
    return agent_edr.ioc_lib_status()


@router.delete("/api/agent/ioc/{iid}")
def api_agent_ioc_del(iid: str, request: Request):
    _require_admin(request)
    from . import agent_edr
    out = agent_edr.delete_ioc(iid)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "删除失败")
    return out


@router.get("/api/agent/tags")
def api_agent_tags_get(request: Request, agent_id: str = Query("")):
    _require_user(request)
    from . import agent_edr
    return agent_edr.get_agent_tags(agent_id)


@router.get("/api/agent/seq-rules")
def api_agent_seq_list(request: Request):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_seq_rules()


@router.put("/api/agent/seq-rules")
def api_agent_seq_upsert(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_edr
    out = agent_edr.upsert_seq_rule(payload or {})
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "保存失败")
    return out


@router.delete("/api/agent/seq-rules/{rule_id}")
def api_agent_seq_delete(request: Request, rule_id: str):
    _require_admin(request)
    from . import agent_edr
    out = agent_edr.delete_seq_rule(rule_id)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "删除失败")
    return out


@router.get("/api/agent/attck-board")
def api_agent_attck_board(request: Request, agent_id: str = Query(""), days: int = Query(0)):
    _require_user(request)
    from . import agent_edr
    return agent_edr.attck_board(agent_id=agent_id, days=days)


@router.get("/api/agent/notify")
def api_agent_notify_get(request: Request):
    _require_admin(request)
    from . import agent_notify
    return agent_notify.get_notify_config()


@router.put("/api/agent/notify")
def api_agent_notify_set(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_notify
    return agent_notify.set_notify_config(payload or {})


@router.post("/api/agent/notify/test")
def api_agent_notify_test(request: Request):
    _require_admin(request)
    from . import agent_notify
    return agent_notify.test_notify()


@router.get("/api/agent/store/stats")
def api_agent_store_stats(request: Request):
    _require_user(request)
    from . import agent_store
    return agent_store.store_stats()


@router.post("/api/agent/store/purge")
def api_agent_store_purge(request: Request):
    _require_admin(request)
    from . import agent_store
    rc = agent_store.retention_config()
    return agent_store.purge(timeline_days=rc["timeline_days"], events_days=rc["events_days"])


@router.get("/api/agent/store/search")
def api_agent_store_search(request: Request, q: str = Query(""), agent_id: str = Query(""), limit: int = Query(200)):
    _require_user(request)
    from . import agent_store
    return {"ok": True, "items": agent_store.search_mysql_timeline(q, agent_id=agent_id, limit=limit)}


@router.get("/api/agent/attack-story")
def api_agent_attack_story(request: Request, agent_id: str = Query(""), event_id: int = Query(0), limit: int = Query(80)):
    _require_user(request)
    from . import agent_edr
    return agent_edr.attack_story(agent_id, event_id=event_id, limit=limit)


@router.get("/api/agent/threat-process-tree")
def api_agent_threat_process_tree(
    request: Request,
    agent_id: str = Query(""),
    event_id: int = Query(0),
    max_nodes: int = Query(56, ge=8, le=120),
):
    _require_user(request)
    from . import agent_edr
    out = agent_edr.threat_process_tree(agent_id, event_id=event_id, max_nodes=max_nodes)
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "无法构建进程树")
    return out


@router.get("/api/agent/upgrade-pubkey")
def api_agent_upgrade_pubkey(request: Request):
    """升级验签公钥（可嵌入 Agent 构建 ldflags / agent.json）。"""
    _require_user(request)
    from . import agent_edr
    out = agent_edr.get_upgrade_pubkey()
    if not out.get("ok"):
        raise HTTPException(500, detail=out.get("error") or "密钥不可用")
    return out


@router.get("/api/agent/upgrade-packages")
def api_agent_upgrade_list(request: Request):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_upgrade_packages()


@router.post("/api/agent/upgrade-packages")
async def api_agent_upgrade_upload(request: Request):
    """上传灰度升级包（multipart: file + version + note）。"""
    user = _require_admin(request)
    from . import agent_edr
    form = await request.form()
    up = form.get("file")
    if up is None:
        raise HTTPException(400, detail="缺少 file")
    content = await up.read()
    out = agent_edr.save_upgrade_package(
        content,
        version=str(form.get("version") or ""),
        filename=str(getattr(up, "filename", None) or "forensic-agent.exe"),
        note=str(form.get("note") or ""),
        actor=_actor(user),
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "上传失败")
    return out


@router.delete("/api/agent/upgrade-packages/{pid}")
def api_agent_upgrade_delete(pid: str, request: Request):
    _require_admin(request)
    from . import agent_edr
    out = agent_edr.delete_upgrade_package(pid)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "删除失败")
    return out


@router.get("/api/agent/upgrade-packages/{pid}/download")
def api_agent_upgrade_download(pid: str, request: Request):
    """Agent 拉取升级包：独立凭据 / 接入密钥 / EDR 登录用户均可。"""
    _agent_auth(request, str(request.headers.get("x-agent-id") or "") if _bearer(request).startswith("fa_") else "")
    from . import agent_edr
    meta, data = agent_edr.read_upgrade_package_bytes(pid)
    if not meta or data is None:
        raise HTTPException(404, detail="升级包不存在")
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{meta.get("filename") or "forensic-agent.exe"}"',
            "X-Package-Sha256": meta.get("sha256") or "",
            "X-Package-Version": meta.get("version") or "",
            "X-Package-Sig-Ed25519": meta.get("sig_ed25519") or "",
            "Cache-Control": "no-store",
        },
    )


@router.post("/api/agent/upgrade-packages/{pid}/push")
def api_agent_upgrade_push(pid: str, request: Request, payload: dict = Body(...)):
    """灰度推送：选择终端下发 upgrade 指令。"""
    user = _require_admin(request)
    from . import agent_edr
    out = agent_edr.push_upgrade(
        pid,
        list((payload or {}).get("agent_ids") or []),
        actor=_actor(user),
        base_url=_public_base_url(request),
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "推送失败")
    return out


# 带 {agent_id} 通配的路由放最后，避免吞掉上面的固定路径

@router.delete("/api/agent/{agent_id}")
def api_agent_delete(agent_id: str, request: Request):
    user = _require_admin(request)
    from .agent_protocol import delete_agent
    out = delete_agent(agent_id)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "删除失败")
    _audit("agent_delete", user, agent_id=agent_id, detail="删除终端记录及其时间线 / 告警")
    return out


@router.get("/api/agent/{agent_id}/snapshot/{module}")
def api_agent_snapshot_get(agent_id: str, module: str, request: Request):
    _require_user(request)
    from .agent_protocol import get_snapshot
    out = get_snapshot(agent_id, module)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "无快照")
    return out


@router.post("/api/agent/{agent_id}/commands")
def api_agent_command_create(agent_id: str, request: Request, payload: dict = Body(...)):
    user = _require_admin(request)
    from . import agent_edr
    p = payload or {}
    out = agent_edr.create_command(
        agent_id,
        str(p.get("action") or ""),
        p.get("params") if isinstance(p.get("params"), dict) else {},
        actor=_actor(user),
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "创建指令失败")
    return out


@router.get("/api/agent/commands")
def api_agent_commands_list_all(request: Request, agent_id: str = "", limit: int = 80):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_commands(agent_id, limit=limit)


@router.get("/api/agent/fleet/drift")
def api_agent_fleet_drift(request: Request, online_within_sec: int = 45):
    _require_user(request)
    from . import agent_fleet

    return agent_fleet.fleet_drift_summary(
        online_within_sec=max(12, min(int(online_within_sec or 45), 3600))
    )


@router.get("/api/agent/diagnostics")
def api_agent_diagnostics_list(request: Request, agent_id: str = "", limit: int = 50):
    _ = request
    from . import agent_diagnostics as adiag
    return adiag.list_diagnostics(agent_id=agent_id, limit=limit)


@router.get("/api/agent/{agent_id}/diagnostics/{command_id}/download")
def api_agent_diagnostics_download(agent_id: str, command_id: str, request: Request):
    _require_user(request)
    from . import agent_diagnostics as adiag

    meta = adiag.get_command_result_meta(agent_id, command_id)
    if not meta.get("ok"):
        raise HTTPException(404 if meta.get("error") == "指令不存在" else 403, detail=meta.get("error"))
    if meta.get("action") != "collect_diagnostics":
        raise HTTPException(400, detail="非诊断指令")
    if meta.get("status") != "done":
        raise HTTPException(409, detail="诊断尚未完成")
    data, filename, err = adiag.read_download_bytes(agent_id, command_id)
    if err or not data:
        raise HTTPException(404, detail=err or "文件不存在")
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/agent/{agent_id}/commands")
def api_agent_commands_list(agent_id: str, request: Request):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_commands(agent_id)


@router.put("/api/agent/{agent_id}/tags")
def api_agent_tags_set(agent_id: str, request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_edr
    return agent_edr.set_agent_tags(agent_id, list((payload or {}).get("tags") or []))
