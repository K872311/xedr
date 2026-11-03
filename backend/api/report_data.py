"""High-traffic report data routes."""
import time
from typing import Callable, Optional, Tuple

from fastapi import APIRouter, Header, HTTPException, Query, Request

from backend.api.contracts import (
    DirectoryPageResponse,
    FileTreeResponse,
    PageResponse,
    ProcessDetailResponse,
    SectionsResponse,
)
from backend.services import report_data as service


def build_report_data_router(
    require_access: Callable[[str, Optional[str]], object],
    prepare_report: Callable[[str], Tuple[str, object, object]],
) -> APIRouter:
    router = APIRouter(prefix="/api/collect", tags=["report-data"])

    def ready(fn: str, authorization: Optional[str], request: Request) -> str:
        started = time.perf_counter()
        require_access(fn, authorization)
        request.state.auth_ms = (time.perf_counter() - started) * 1000.0
        started = time.perf_counter()
        rid, _, _ = prepare_report(fn)
        request.state.db_ms = (time.perf_counter() - started) * 1000.0
        return rid

    def measured(request: Request, call):
        started = time.perf_counter()
        try:
            return call()
        finally:
            request.state.db_ms = float(getattr(request.state, "db_ms", 0.0) or 0.0) + (
                time.perf_counter() - started
            ) * 1000.0

    @router.get("/section/{fn:path}", response_model=PageResponse)
    def section(
        fn: str,
        request: Request,
        name: str = Query(...),
        offset: int = Query(0, ge=0, le=10_000_000),
        limit: int = Query(100, ge=1, le=20000),
        q: str = Query("", max_length=500),
        channel: str = Query("", max_length=300),
        hits_only: bool = Query(False),
        authorization: Optional[str] = Header(None),
    ):
        rid = ready(fn, authorization, request)
        page = measured(request, lambda: service.section_page(
            rid, name, offset=offset, limit=limit, q=q, channel=channel, hits_only=hits_only,
        ))
        if page is None:
            raise HTTPException(404, detail="该模块数据不可用")
        return page

    @router.get("/files-under/{fn:path}", response_model=DirectoryPageResponse)
    def files_under(
        fn: str,
        request: Request,
        dir: str = Query(..., min_length=1, max_length=800),
        offset: int = Query(0, ge=0, le=10_000_000),
        limit: int = Query(300, ge=1, le=2000),
        authorization: Optional[str] = Header(None),
    ):
        rid = ready(fn, authorization, request)
        return measured(request, lambda: service.files_under(rid, dir, offset=offset, limit=limit))

    @router.get("/files-directory/{fn:path}", response_model=DirectoryPageResponse)
    def files_directory(
        fn: str,
        request: Request,
        dir: str = Query("", max_length=800),
        offset: int = Query(0, ge=0, le=10_000_000),
        limit: int = Query(300, ge=1, le=2000),
        q: str = Query("", max_length=500),
        hidden_only: bool = Query(False),
        authorization: Optional[str] = Header(None),
    ):
        rid = ready(fn, authorization, request)
        return measured(request, lambda: service.directory_page(
            rid, dir, offset=offset, limit=limit, q=q,
            hidden_only=hidden_only,
        ))

    @router.get("/file-content/{fn:path}")
    def file_content(
        fn: str,
        request: Request,
        path: str = Query(..., min_length=1, max_length=1000),
        authorization: Optional[str] = Header(None),
    ):
        rid = ready(fn, authorization, request)
        item = measured(request, lambda: service.file_content(rid, path))
        if item is None:
            raise HTTPException(404, detail="文件不在本报告的采集清单中")
        return item

    @router.get("/remote-tools/{fn:path}")
    def remote_tools(
        fn: str,
        request: Request,
        authorization: Optional[str] = Header(None),
    ):
        """远控软件：安装实例、无人值守、本机 ID、会话时间线。"""
        rid = ready(fn, authorization, request)
        return measured(request, lambda: service.remote_tools(rid))

    @router.get("/ir-lateral/{fn:path}")
    def ir_lateral(fn: str, request: Request, authorization: Optional[str] = Header(None)):
        rid = ready(fn, authorization, request)
        return measured(request, lambda: service.ir_lateral(rid))

    @router.get("/ir-cred-theft/{fn:path}")
    def ir_cred_theft(fn: str, request: Request, authorization: Optional[str] = Header(None)):
        rid = ready(fn, authorization, request)
        return measured(request, lambda: service.ir_cred_theft(rid))

    @router.get("/ir-beacon/{fn:path}")
    def ir_beacon(fn: str, request: Request, authorization: Optional[str] = Header(None)):
        rid = ready(fn, authorization, request)
        return measured(request, lambda: service.ir_beacon(rid))

    @router.get("/ir-defense-weaken/{fn:path}")
    def ir_defense_weaken(fn: str, request: Request, authorization: Optional[str] = Header(None)):
        rid = ready(fn, authorization, request)
        return measured(request, lambda: service.ir_defense_weaken(rid))

    @router.get("/ir-exfil/{fn:path}")
    def ir_exfil(fn: str, request: Request, authorization: Optional[str] = Header(None)):
        rid = ready(fn, authorization, request)
        return measured(request, lambda: service.ir_exfil(rid))

    @router.get("/process-detail/{fn:path}", response_model=ProcessDetailResponse)
    def process(
        fn: str,
        request: Request,
        pid: int = Query(..., ge=0, le=4_294_967_295),
        authorization: Optional[str] = Header(None),
    ):
        rid = ready(fn, authorization, request)
        item = measured(request, lambda: service.process_detail(rid, pid))
        if item is None:
            raise HTTPException(404, detail="未找到该进程详情")
        return item

    @router.get("/threat-trace/{fn:path}")
    def threat_trace(
        fn: str,
        request: Request,
        q: str = Query("", max_length=500),
        pid: Optional[int] = Query(None, ge=0, le=4_294_967_295),
        file: str = Query("", max_length=500),
        limit: int = Query(80, ge=10, le=200),
        authorization: Optional[str] = Header(None),
    ):
        rid = ready(fn, authorization, request)
        return measured(request, lambda: service.threat_trace(rid, q=q, pid=pid, file=file, limit=limit))

    @router.post("/threat-trace-ai/{fn:path}")
    def threat_trace_ai(
        fn: str,
        request: Request,
        q: str = Query("", max_length=500),
        pid: Optional[int] = Query(None, ge=0, le=4_294_967_295),
        file: str = Query("", max_length=500),
        limit: int = Query(80, ge=10, le=200),
        authorization: Optional[str] = Header(None),
    ):
        """威胁溯检 AI 分析：使用当前用户/全局大模型配置。"""
        started = time.perf_counter()
        user = require_access(fn, authorization)
        request.state.auth_ms = (time.perf_counter() - started) * 1000.0
        started = time.perf_counter()
        rid, _, _ = prepare_report(fn)
        request.state.db_ms = (time.perf_counter() - started) * 1000.0
        user_obj = user if isinstance(user, dict) else None
        return measured(
            request,
            lambda: service.threat_trace_ai(rid, q=q, pid=pid, file=file, limit=limit, user=user_obj),
        )

    @router.get("/finding-evidence/{fn:path}", response_model=PageResponse)
    def evidence(
        fn: str,
        request: Request,
        id: str = Query(..., min_length=1, max_length=512),
        offset: int = Query(0, ge=0, le=10_000_000),
        limit: int = Query(50, ge=1, le=500),
        authorization: Optional[str] = Header(None),
    ):
        rid = ready(fn, authorization, request)
        page = measured(
            request, lambda: service.finding_evidence(rid, id, offset=offset, limit=limit),
        )
        if page is None:
            raise HTTPException(404, detail="未找到该告警证据")
        return page

    @router.get("/sections/{fn:path}", response_model=SectionsResponse)
    def sections(
        fn: str,
        request: Request,
        names: str = Query(..., min_length=1, max_length=500),
        limit: int = Query(600, ge=1, le=2000),
        authorization: Optional[str] = Header(None),
    ):
        name_list = [x.strip() for x in names.split(",") if x.strip()]
        if len(name_list) > 20:
            raise HTTPException(400, detail="一次最多请求 20 个模块")
        rid = ready(fn, authorization, request)
        return measured(request, lambda: service.sections(rid, name_list, limit=limit))

    @router.get("/files-tree-data/{fn:path}", response_model=FileTreeResponse)
    def files_tree(
        fn: str,
        request: Request,
        q: str = Query("", max_length=500),
        hidden_only: bool = Query(False),
        limit: int = Query(3000, ge=1, le=20_000),
        offset: int = Query(0, ge=0, le=10_000_000),
        root: str = Query("", max_length=64),
        tree: bool = Query(True),
        recent_days: int = Query(0, ge=0, le=30),
        mtime_from: str = Query("", max_length=32),
        mtime_to: str = Query("", max_length=32),
        authorization: Optional[str] = Header(None),
    ):
        rid = ready(fn, authorization, request)
        return measured(request, lambda: service.file_tree(
            rid, q=q, hidden_only=hidden_only, limit=limit,
            offset=offset, root=root, include_tree=tree, recent_days=recent_days,
            mtime_from=mtime_from, mtime_to=mtime_to,
        ))

    return router
