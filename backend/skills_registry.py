# -*- coding: utf-8 -*-
"""内置研判 Skill（剧本）：描述步骤，供 UI / MCP / 未来 Agent 编排调用。

Skill 不直接改主机；默认只读。步骤里的 tool 对应平台已有 API。
"""
from __future__ import annotations

from typing import Any, Dict, List

SKILLS: List[Dict[str, Any]] = [
    {
        "id": "suspected-drop-exe",
        "title": "可疑落地 exe 标准研判",
        "summary": "文件名/哈希 → 知识库 → 跨主机 locate → 本机威胁溯查 → 持久化核对",
        "tags": ["落点", "溯查"],
        "readonly": True,
        "steps": [
            {"tool": "search_knowledge", "args": {"q": "{feature}"}, "why": "认特征"},
            {"tool": "threat_trace_locate", "args": {"q": "{feature}"}, "why": "跨主机同名"},
            {"tool": "threat_trace", "args": {"file": "{report}", "q": "{feature}"}, "why": "本机关联"},
            {"tool": "search_findings", "args": {"q": "{feature}", "scope": "all"}, "why": "告警与内容"},
        ],
    },
    {
        "id": "remote-tool-campaign",
        "title": "远控跨主机扩面",
        "summary": "远控关键词 → 战役聚合 → 逐台打开远控模块",
        "tags": ["远控", "战役"],
        "readonly": True,
        "steps": [
            {"tool": "search_knowledge", "args": {"q": "{feature}"}, "why": "手法说明"},
            {"tool": "campaign_summary", "args": {"os_family": "{os_family}"}, "why": "跨主机线索"},
            {"tool": "search_findings", "args": {"q": "{feature}", "scope": "findings"}, "why": "相关告警"},
        ],
    },
    {
        "id": "exfil-triage",
        "title": "外传/压缩时间窗研判",
        "summary": "压缩/云同步关键词 → 外传模块 → 网络画像",
        "tags": ["外传"],
        "readonly": True,
        "steps": [
            {"tool": "search_knowledge", "args": {"q": "{feature}"}, "why": "手法边界"},
            {"tool": "search_findings", "args": {"q": "{feature}", "scope": "all"}, "why": "相关证据"},
        ],
    },
]


def list_skills() -> Dict[str, Any]:
    return {"ok": True, "items": list(SKILLS), "total": len(SKILLS)}


def get_skill(skill_id: str) -> Dict[str, Any]:
    sid = str(skill_id or "").strip()
    for s in SKILLS:
        if s["id"] == sid:
            return {"ok": True, "item": s}
    return {"ok": False, "error": "skill 不存在"}
