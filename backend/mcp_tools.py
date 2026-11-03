# -*- coding: utf-8 -*-
"""平台 MCP 工具目录（只读优先）。

后续可用 FastMCP / 官方 MCP SDK 把本目录暴露给 Cursor。
当前先提供 list/dispatch，便于 Skill 与管理端试调。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

TOOL_DEFS: List[Dict[str, Any]] = [
    {
        "name": "search_knowledge",
        "description": "检索应急知识库（特征/误报/剧本）",
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["q"]},
    },
    {
        "name": "search_findings",
        "description": "全局检索告警/报告内容/台账",
        "inputSchema": {
            "type": "object",
            "properties": {
                "q": {"type": "string"},
                "scope": {"type": "string"},
                "hostname": {"type": "string"},
                "size": {"type": "integer"},
            },
            "required": ["q"],
        },
    },
    {
        "name": "threat_trace_locate",
        "description": "跨报告按文件名/哈希定位",
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}, "os_family": {"type": "string"}}, "required": ["q"]},
    },
    {
        "name": "campaign_summary",
        "description": "战役聚合摘要（可走缓存）",
        "inputSchema": {"type": "object", "properties": {"os_family": {"type": "string"}, "limit": {"type": "integer"}}},
    },
    {
        "name": "list_skills",
        "description": "列出内置研判 Skill",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "agent_list",
        "description": "列出在线/离线终端 Agent",
        "inputSchema": {"type": "object", "properties": {"online_within_sec": {"type": "integer"}}},
    },
]


def list_tools() -> Dict[str, Any]:
    return {"ok": True, "tools": TOOL_DEFS, "readonly": True}


def call_tool(name: str, arguments: Optional[Dict[str, Any]] = None, *, user: Any = None) -> Dict[str, Any]:
    args = arguments if isinstance(arguments, dict) else {}
    n = str(name or "").strip()
    try:
        if n == "search_knowledge":
            from .knowledge_store import search_knowledge
            items = search_knowledge(str(args.get("q") or ""), limit=int(args.get("limit") or 20))
            return {"ok": True, "items": items, "total": len(items)}
        if n == "search_findings":
            from .search import search_findings
            return search_findings(
                user,
                str(args.get("q") or ""),
                hostname=str(args.get("hostname") or "") or None,
                scope=str(args.get("scope") or "all"),
                size=int(args.get("size") or 30),
            )
        if n == "threat_trace_locate":
            from .services.threat_trace import locate_threat_trace_targets
            return locate_threat_trace_targets(str(args.get("q") or ""), os_family=str(args.get("os_family") or ""))
        if n == "campaign_summary":
            from .campaign_jobs import build_campaign_sync
            return build_campaign_sync(limit_hosts=int(args.get("limit") or 80), os_family=str(args.get("os_family") or ""))
        if n == "list_skills":
            from .skills_registry import list_skills
            return list_skills()
        if n == "agent_list":
            from .agent_protocol import list_agents
            return list_agents(online_within_sec=int(args.get("online_within_sec") or 180))
        return {"ok": False, "error": f"未知工具: {n}"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}
