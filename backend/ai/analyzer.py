"""AI 分析：有 API Key 走大模型；否则用结构化启发式报告（不阻塞管线）"""
from __future__ import annotations
import http.client
import json
import ipaddress
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
from collections import Counter
from typing import Any, Dict, List, Optional

from .. import config
from .citations import CITATION_RULE, attach_refs, cited_completion, citation_note


def _pick_findings(analysis: Dict, report_file: str = "") -> list:
    try:
        from ..finding_review import findings_for_ai
        return findings_for_ai(analysis, report_file)
    except Exception:
        return list(analysis.get("findings_aggregated") or analysis.get("findings") or [])


def _norm_evidence_snippet(ev: Any, limit: int = 120) -> str:
    if isinstance(ev, list):
        parts = [str(x).strip() for x in ev if str(x or "").strip()]
        text = " · ".join(parts)
    else:
        text = str(ev or "").strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def _heuristic(report: Dict, analysis: Dict, report_file: str = "") -> Dict[str, Any]:
    findings = _pick_findings(analysis, report_file)
    summary = analysis.get("summary") or {}
    by_cat = Counter(f.get("category") for f in findings)
    high = [f for f in findings if str(f.get("severity", "")).lower() in ("high", "critical")]

    risk = "低"
    score = 10
    if summary.get("high", 0) >= 5 or by_cat.get("RMM", 0) or by_cat.get("远控痕迹", 0):
        risk, score = "高", 75
    elif summary.get("high", 0) >= 1 or summary.get("medium", 0) >= 10:
        risk, score = "中", 45
    if by_cat.get("可疑命令", 0):
        risk, score = "高", max(score, 80)
    if any(f.get("title") in ("mimikatz", "删除卷影(勒索/反取证)", "凭据转储工具") or
           "mimikatz" in str(f.get("title", "")).lower() for f in findings):
        risk, score = "严重", 95

    highlights = []
    for f in high[:8]:
        ev_s = _norm_evidence_snippet(f.get("evidence"), 100)
        highlights.append({
            "severity": f.get("severity") or "medium",
            "category": f.get("category") or f.get("type") or "",
            "title": f.get("title") or f.get("name") or "",
            "evidence": ev_s,
        })

    cat_lines = []
    for cat, n in sorted(by_cat.items(), key=lambda x: (-x[1], str(x[0]))):
        if cat and n:
            cat_lines.append(f"{cat} {n}")
    narrative = (
        f"主机 {report.get('hostname', 'unknown')} 规则引擎共检出 {summary.get('total', 0)} 项"
        f"（本次研判使用 {len(findings)} 条未排除命中）。\n"
        f"风险等级：{risk}（启发式评分 {score}/100）。\n"
    )
    if cat_lines:
        narrative += f"类别分布：{' · '.join(cat_lines[:12])}。\n"
    if by_cat.get("RMM") or by_cat.get("远控痕迹"):
        narrative += "发现远程控制/RMM 相关痕迹，建议立即核查是否为授权运维工具，并核对外联目标。\n"
    if by_cat.get("网络外联"):
        narrative += f"存在 {by_cat['网络外联']} 个去重后的公网外联 IP，建议结合防火墙与威胁情报复核。\n"
    if by_cat.get("可疑命令"):
        narrative += "PowerShell/启动项/任务中出现可疑命令特征，优先排查横向移动与凭据窃取。\n"
    if not findings:
        narrative += "未命中当前规则集；不代表主机干净，可补充 IOC 或开启 AI 深析。\n"

    return {
        "mode": "heuristic",
        "risk_level": risk,
        "risk_score": score,
        "summary": narrative,
        "highlights": highlights,
        "recommendations": [],
        "model": None,
    }


def _chat_completions_url(base_url: str) -> str:
    """规范 OpenAI 兼容地址。DeepSeek 官方 OpenAI 格式为 https://api.deepseek.com/chat/completions
    （不要用 /anthropic，那是 Anthropic 协议）。"""
    u = (base_url or "").strip().rstrip("/")
    if not u:
        u = "https://api.openai.com/v1"
    low = u.lower()
    # 误配 Anthropic 入口时自动纠正为 OpenAI 入口
    if "api.deepseek.com" in low and "/anthropic" in low:
        u = "https://api.deepseek.com"
        low = u.lower()
    if low.endswith("/chat/completions"):
        return u
    # DeepSeek：官方 curl 用 https://api.deepseek.com/chat/completions
    # 也兼容用户填写的 .../v1
    if "api.deepseek.com" in low:
        if low.rstrip("/").endswith("/v1"):
            return u + "/chat/completions"
        return "https://api.deepseek.com/chat/completions"
    return u + "/chat/completions"


def validate_ai_base_url(base_url: str) -> List[str]:
    """保存/调用前统一校验 Base URL，返回钉扎用的公网 IP。"""
    return _validate_outbound_url(_chat_completions_url(base_url))


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


# 公有云 OpenAI 兼容入口（允许企业 DNS 劫持到内网 IP）
_ALLOWED_AI_HOSTS = frozenset({
    "api.deepseek.com",
    "api.openai.com",
    "dashscope.aliyuncs.com",  # 通义千问 compatible-mode
    "dashscope-intl.aliyuncs.com",
    "api.moonshot.cn",  # Kimi
    "api.siliconflow.cn",
    "open.bigmodel.cn",  # 智谱
})


def _env_flag(name: str, default: bool = False) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


def _allow_private_ai_url() -> bool:
    """内网/本地大模型默认允许（应急平台常见）；FORENSIC_ALLOW_PRIVATE_AI_URL=0 可关闭。"""
    return _env_flag("FORENSIC_ALLOW_PRIVATE_AI_URL", default=True)


def _validate_outbound_url(url: str) -> List[str]:
    """校验 AI URL，并返回已解析的 IP 列表（用于连接钉扎，防 DNS 重绑定）。"""
    try:
        u = urllib.parse.urlsplit(url)
    except Exception as e:
        raise RuntimeError("AI Base URL 非法") from e
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise RuntimeError("AI Base URL 只允许不含凭据的 http/https 地址")
    host = u.hostname.lower()
    port = u.port or (443 if u.scheme == "https" else 80)
    # 官方端点：仍解析钉扎，但允许其解析到任意可路由地址（部分企业 DNS 会劫持）
    allow_official = host in _ALLOWED_AI_HOSTS and u.scheme == "https"
    allow_private = _allow_private_ai_url()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as e:
        raise RuntimeError("AI Base URL 域名解析失败") from e
    ips: List[str] = []
    seen = set()
    for info in infos:
        raw = info[4][0]
        if raw in seen:
            continue
        seen.add(raw)
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        # 仍拒绝组播/保留段；内网与回环在 allow_private 时放行（Ollama / vLLM / 内网网关）
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            if not allow_official:
                raise RuntimeError("AI Base URL 地址不可用")
        elif _is_blocked_ip(ip) and not allow_official and not allow_private:
            raise RuntimeError(
                "AI Base URL 禁止访问本机或内网地址（如需内网模型，设置 FORENSIC_ALLOW_PRIVATE_AI_URL=1）"
            )
        if allow_private or allow_official or not _is_blocked_ip(ip):
            ips.append(raw)
    if not ips:
        raise RuntimeError("AI Base URL 无可用解析地址")
    return ips


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """连到 IP，但用真实域名做 SNI / 证书校验。"""

    def __init__(self, *args, server_hostname: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self._server_hostname = server_hostname

    def connect(self) -> None:
        self.sock = self._create_connection(
            (self.host, self.port), self.timeout, self.source_address,
        )
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if self._tunnel_host:
            self._tunnel()
        context = self._context
        if context is None:
            context = ssl.create_default_context()
        self.sock = context.wrap_socket(
            self.sock, server_hostname=self._server_hostname or self.host,
        )


def _http_post_pinned(
    url: str,
    *,
    body: bytes,
    headers: Dict[str, str],
    timeout: float,
    pinned_ips: Optional[List[str]] = None,
) -> bytes:
    """用校验过的 IP 直连，Host/SNI 仍用原域名，避免解析后再被重绑定到内网。"""
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"
    ips = list(pinned_ips or []) or _validate_outbound_url(url)
    hdrs = {str(k): str(v) for k, v in (headers or {}).items()}
    if "Host" not in hdrs and "host" not in {k.lower() for k in hdrs}:
        hdrs["Host"] = host if u.port is None else f"{host}:{u.port}"

    last_err: Optional[Exception] = None
    for ip in ips[:4]:
        conn = None
        try:
            if u.scheme == "https":
                ctx = ssl.create_default_context()
                conn = _PinnedHTTPSConnection(
                    ip, port, timeout=timeout, context=ctx, server_hostname=host,
                )
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            conn.request("POST", path, body=body, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read(2 * 1024 * 1024 + 1)
            if resp.status >= 400:
                detail = raw[:500].decode("utf-8", errors="replace")
                raise RuntimeError(f"HTTP {resp.status} {resp.reason or ''}: {detail}")
            if len(raw) > 2 * 1024 * 1024:
                raise RuntimeError("模型响应超过 2MB")
            return raw
        except Exception as e:
            last_err = e
        finally:
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass
    if last_err is not None:
        raise last_err
    raise RuntimeError("AI 请求失败：无可用连接")


def _extract_message_text(data: Dict[str, Any]) -> str:
    """兼容普通 content 与 DeepSeek 思考模式 reasoning_content。"""
    try:
        msg = (data.get("choices") or [{}])[0].get("message") or {}
    except Exception:
        msg = {}
    content = (msg.get("content") or "").strip()
    reasoning = (msg.get("reasoning_content") or "").strip()
    if content:
        return content
    if reasoning:
        return reasoning
    return ""


def _http_error_detail(err: Exception) -> str:
    if isinstance(err, urllib.error.HTTPError):
        body = ""
        try:
            body = err.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        return f"HTTP {err.code} {err.reason}: {body}"
    return str(err)[:400]


def _windows_from_findings(findings: list) -> list:
    """只把命中本身当窗口，不附带 file_scans / 进程全文。"""
    compact = []
    for f in findings[:30]:
        ev_s = _norm_evidence_snippet(f.get("evidence"), 160)
        compact.append({
            "id": f.get("id"),
            "category": f.get("category") or f.get("type"),
            "severity": f.get("severity"),
            "title": f.get("title") or f.get("name"),
            "evidence": ev_s,
            "source": f.get("source"),
            "matcher": f.get("matcher"),
            "rule_id": f.get("rule_id"),
            "review": f.get("review_status") or "pending",
        })
    return compact


def _normalize_model(model: str, base_url: str = "") -> str:
    m = str(model or "").strip()
    low = m.lower()
    url = str(base_url or "").lower()
    aliases = {
        "deepseek-v4-flash": "deepseek-chat",
        "deepseek-v4-pro": "deepseek-reasoner",
        "deepseek-v3": "deepseek-chat",
    }
    # 仅公有云 DashScope 才把「千问」别名落到 qwen-plus；内网用真实模型 ID
    if "dashscope" in url:
        aliases.update({
            "qianwen": "qwen-plus",
            "通义千问": "qwen-plus",
            "qwen": "qwen-plus",
        })
    if low in aliases:
        return aliases[low]
    if m:
        return m
    if "deepseek" in url:
        return "deepseek-chat"
    if "dashscope" in url:
        return "qwen-plus"
    # 内网 / 其它 OpenAI 兼容：不强行改成 deepseek
    return "gpt-4o-mini"


def _chat_sender(
    url: str,
    api_key: str,
    model: str,
    timeout: float,
    *,
    max_tokens: Optional[int] = None,
):
    """返回 send(messages) -> text；网络/HTTP 错误抛 RuntimeError（含请求地址）。"""
    try:
        pinned = _validate_outbound_url(url)
    except Exception as e:
        raise RuntimeError(f"请求 {url} 失败 — {_http_error_detail(e)}") from e

    def send(messages: List[Dict[str, str]]) -> str:
        body: Dict[str, Any] = {
            "model": model,
            "temperature": 0.2,
            "stream": False,
            "messages": messages,
        }
        if max_tokens:
            body["max_tokens"] = int(max(64, min(int(max_tokens), 4096)))
        # Qwen3 / Strata / DeepSeek-V3 思考模式会把研判拖到数十秒；默认关闭
        low_m = str(model or "").lower()
        low_u = str(url or "").lower()
        if (
            low_m.startswith("qwen")
            or "qwen" in low_m
            or "strata" in low_u
            or "deepseek" in low_m
            or "flash" in low_m
        ):
            body["chat_template_kwargs"] = {"enable_thinking": False}
            body["enable_thinking"] = False
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # 有 Key 则带 Bearer（内网占位 local/ollama 也带，兼容部分网关必填头）
        key = str(api_key or "").strip()
        if key and key.lower() not in ("none", "null", "-", "no-key", "nokey"):
            headers["Authorization"] = f"Bearer {key}"
        try:
            raw = _http_post_pinned(
                url,
                body=json.dumps(body).encode("utf-8"),
                headers=headers,
                timeout=max(5.0, min(timeout, 300.0)),
                pinned_ips=pinned,
            )
            data = json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise RuntimeError(f"请求 {url} 失败 — {_http_error_detail(e)}") from e
        return _extract_message_text(data)

    return send


def _llm(report: Dict, analysis: Dict, report_file: str = "", creds: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    findings = _pick_findings(analysis, report_file)
    if not findings:
        raise RuntimeError("无规则命中锚点，已跳过大型模型（不盲扫采集原文）")
    compact, refs = attach_refs(_windows_from_findings(findings))
    kb_cards = []
    try:
        from ..knowledge_store import context_for_ai
        needles = []
        for f in findings[:20]:
            for k in ("title", "evidence", "rule_id"):
                v = f.get(k)
                if v:
                    needles.append(str(v)[:120])
        kb_cards = context_for_ai(needles, limit=6)
        if kb_cards:
            kb_compact, kb_refs = attach_refs(kb_cards, start=len(compact) + 1)
            compact_kb = kb_compact
            merged = dict(refs or {})
            if isinstance(kb_refs, dict):
                merged.update(kb_refs)
            refs = merged
        else:
            compact_kb = []
    except Exception:
        compact_kb = []
    payload_user = {
        "hostname": report.get("hostname"),
        "ip": str(report.get("ip") or "")[:80],
        "collect_time": report.get("collect_time"),
        "summary": analysis.get("summary") or analysis.get("summary_aggregated"),
        "finding_windows": compact,
        "knowledge_cards": compact_kb,
        "anchor_count": len(findings),
        "note": (
            "仅根据规则命中窗口研判；knowledge_cards 为平台知识库释义（可引用），"
            "不要假设还有未提供的文件/进程证据。"
        ),
    }
    system = (
        "你是资深应急响应与主机取证分析师。只根据给定的规则命中窗口研判，"
        "禁止编造窗口外的文件、进程或日志。"
        "若提供 knowledge_cards，可用来解释特征/误报边界，但仍须以 finding_windows 事实为准。"
        "输出简洁中文，只写风险相关内容："
        "1) 总体风险等级(严重/高/中/低)与理由；"
        "2) 可能的攻击阶段/手法（候选）；"
        "3) 需优先关注的风险点（条目与原因，均标为候选）。"
        "未经人工复核接受前，禁止使用「确认」表述恶意/入侵，一律用「候选」。"
        "不要输出处置建议、核查步骤或任何操作指引。"
        "已排除(rejected)的命中不会出现在窗口中。"
        + CITATION_RULE
    )
    creds = creds or {}
    api_key = (creds.get("api_key") or config.AI_API_KEY or "").strip()
    base_url = (creds.get("base_url") or config.AI_BASE_URL or "").strip()
    model = _normalize_model(creds.get("model") or config.AI_MODEL or "", base_url)
    timeout = float(creds.get("timeout") or config.AI_TIMEOUT or 60)
    url = _chat_completions_url(base_url)
    send = _chat_sender(url, api_key, model, timeout)
    text, cite = cited_completion(send, [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(payload_user, ensure_ascii=False)},
    ], list(refs))
    if not text:
        raise RuntimeError("模型返回空内容")
    # 粗提风险词
    risk = "中"
    for lv in ("严重", "高", "中", "低"):
        if lv in text[:120]:
            risk = lv
            break
    return {
        "mode": "llm",
        "risk_level": risk,
        "risk_score": {"严重": 95, "高": 75, "中": 45, "低": 15}.get(risk, 50),
        "summary": text,
        "highlights": [],
        "recommendations": [],
        "model": model,
        "request_url": url,
        "config_source": creds.get("source") or "global",
        "citations": cite,
        "evidence_refs": refs,
        "citation_note": citation_note(cite),
    }


def load_inputs_for_ai(report_file: str) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """按报告 ID 组装 AI 输入：优先已有分析结果，避免前端上传大 JSON / 全量重跑。"""
    from .. import paths as P
    from ..db_store import db_exists, load_view_from_db

    rid = P.report_id(report_file)
    report: Dict[str, Any] = {}
    analysis: Dict[str, Any] = {}

    rj = P.resolve_report_json(rid)
    if rj and rj.exists():
        try:
            with open(rj, encoding="utf-8") as fh:
                raw = json.load(fh) or {}
            if isinstance(raw, dict):
                report = {
                    "hostname": raw.get("hostname") or "",
                    "ip": raw.get("ip") or "",
                    "collect_time": raw.get("collect_time") or "",
                    "os": raw.get("os") or "",
                    "os_family": raw.get("os_family") or "",
                }
        except Exception:
            report = {}

    rp = P.resolve_result_json(rid)
    if rp and rp.exists():
        try:
            with open(rp, encoding="utf-8") as fh:
                data = json.load(fh) or {}
            if isinstance(data, dict):
                analysis = data.get("analysis") if isinstance(data.get("analysis"), dict) else {}
                if not report.get("hostname"):
                    report["hostname"] = data.get("hostname") or report.get("hostname") or ""
        except Exception:
            analysis = {}

    if not (analysis.get("findings_aggregated") or analysis.get("findings")) and db_exists(rid):
        view = load_view_from_db(rid) or {}
        if isinstance(view, dict):
            if not report.get("hostname"):
                report["hostname"] = view.get("hostname") or ""
            if not report.get("ip"):
                report["ip"] = view.get("ip") or ""
            if not report.get("collect_time"):
                report["collect_time"] = view.get("collect_time") or ""
            an = view.get("analysis") if isinstance(view.get("analysis"), dict) else {}
            findings = (
                an.get("findings_aggregated")
                or an.get("findings")
                or view.get("findings_aggregated")
                or view.get("findings")
                or []
            )
            analysis = {
                **an,
                "findings_aggregated": findings,
                "summary": an.get("summary") or view.get("summary") or analysis.get("summary") or {},
                "summary_aggregated": (
                    an.get("summary_aggregated")
                    or view.get("summary_aggregated")
                    or analysis.get("summary_aggregated")
                    or {}
                ),
            }

    if not isinstance(analysis, dict):
        analysis = {}
    if not isinstance(report, dict):
        report = {}
    return report, analysis


def analyze_with_ai(
    report: Dict,
    analysis: Dict,
    use_llm: bool = True,
    report_file: str = "",
    user: Optional[Dict[str, Any]] = None,
    creds: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    use_llm=True 且当前账号已配置 Key → 调大模型（仅命中窗口）；
    use_llm=False → 仅启发式；
    无命中锚点 → 不调用大模型。
    凭据：显式 creds → 当前用户个人配置（不使用全局 Key）。
    """
    anchors = _pick_findings(analysis, report_file)
    base = _heuristic(report, analysis, report_file)
    base["anchor_count"] = len(anchors)
    if not use_llm:
        base["note"] = "仅启发式研判（未调用大模型）。"
        return base
    if not anchors:
        base["note"] = "无规则命中锚点，已跳过大型模型，不盲扫采集原文。请先做规则匹配。"
        base["mode"] = "no_anchor"
        return base
    if creds is None:
        try:
            from ..user_ai import resolve_ai_creds
            creds = resolve_ai_creds(user)
        except Exception:
            creds = {"api_key": "", "base_url": "", "model": "", "timeout": 60, "source": "none"}
    if not (creds.get("api_key") or "").strip():
        base["note"] = "未配置个人 API Key。请到「我的大模型」填写并保存（每位账号独立配置，不共用）。"
        base["mode"] = "need_config"
        return base
    try:
        llm = _llm(report, analysis, report_file, creds=creds)
        llm["heuristic"] = {
            "risk_level": base["risk_level"],
            "risk_score": base["risk_score"],
        }
        llm["base_url"] = creds.get("base_url") or config.AI_BASE_URL
        llm["anchor_count"] = len(anchors)
        return llm
    except Exception as e:
        detail = _http_error_detail(e) if hasattr(e, '__class__') else str(e)
        base["mode"] = "heuristic_fallback"
        base["error"] = str(detail)[:400]
        base["note"] = f"大模型调用失败，已回退启发式研判。原因：{str(detail)[:200]}"
        base["config_source"] = creds.get("source") or "global"
        base["model"] = _normalize_model(creds.get("model") or "", creds.get("base_url") or "")
        return base


def analyze_trace_with_ai(
    trace_pack: Dict[str, Any],
    *,
    user: Optional[Dict[str, Any]] = None,
    creds: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """威胁溯检专用 AI：只吃关联窗口，不扫整份报告。"""
    if creds is None:
        try:
            from ..user_ai import resolve_ai_creds
            creds = resolve_ai_creds(user)
        except Exception:
            creds = {"api_key": "", "base_url": "", "model": "", "timeout": 60, "source": "none"}
    configured = bool((creds.get("api_key") or "").strip())
    if not configured:
        return {
            "mode": "need_config",
            "configured": False,
            "risk_level": "",
            "risk_score": 0,
            "summary": "未配置个人大模型 API Key。请到「我的大模型」填写 Base URL / Model / API Key（每位账号独立，不共用全局）。",
            "highlights": [],
            "recommendations": ["打开「我的大模型」保存个人配置，或由管理员配置全局 AI"],
            "model": None,
            "config_source": creds.get("source") or "global",
        }

    windows = (trace_pack or {}).get("evidence_windows") or []
    if not windows and not (trace_pack or {}).get("matches"):
        return {
            "mode": "no_anchor",
            "configured": True,
            "risk_level": "低",
            "risk_score": 10,
            "summary": "当前溯检无关联证据窗口，无法做 AI 研判。请先检索出进程关联结果。",
            "highlights": [],
            "recommendations": [],
            "model": creds.get("model"),
            "config_source": creds.get("source") or "global",
        }

    system = (
        "你是资深应急响应与主机取证分析师，正在做「威胁溯检」进程关联研判。"
        "只根据给定的关联证据窗口（含置信度强/中/弱）输出简洁中文，只写风险相关："
        "1) 总体风险等级(严重/高/中/低)与理由；"
        "2) 可能的行为链（启动→持久化→外联等，仅限窗口内事实，均为候选）；"
        "3) 需优先关注的风险点（候选）。"
        "未经人工复核接受前禁止写「确认」；弱关联必须标明「待复核」。"
        "不要输出处置建议、核查步骤或任何操作指引。"
        "禁止编造窗口外的文件、进程、日志或 IP。"
        + CITATION_RULE
    )
    api_key = (creds.get("api_key") or "").strip()
    base_url = (creds.get("base_url") or config.AI_BASE_URL or "").strip()
    model = _normalize_model(creds.get("model") or config.AI_MODEL or "", base_url)
    timeout = float(creds.get("timeout") or config.AI_TIMEOUT or 60)
    pack = dict(trace_pack or {})
    win_refd, refs = attach_refs(windows)
    match_refd, match_refs = attach_refs(pack.get("matches") or [], start=len(win_refd) + 1)
    refs.update(match_refs)
    pack["evidence_windows"] = win_refd
    pack["matches"] = match_refd
    url = _chat_completions_url(base_url)
    try:
        send = _chat_sender(url, api_key, model, timeout)
        text, cite = cited_completion(send, [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(pack, ensure_ascii=False)},
        ], list(refs))
    except Exception as e:
        return {
            "mode": "error",
            "configured": True,
            "risk_level": "",
            "risk_score": 0,
            "summary": f"大模型调用失败：{_http_error_detail(e)}",
            "highlights": [],
            "recommendations": ["检查 Base URL / API Key / 网络出站，或先使用系统总结"],
            "model": model,
            "error": _http_error_detail(e)[:300],
            "config_source": creds.get("source") or "global",
        }

    if not text:
        return {
            "mode": "error",
            "configured": True,
            "summary": "模型返回空内容",
            "highlights": [],
            "recommendations": [],
            "model": model,
            "config_source": creds.get("source") or "global",
        }
    risk = "中"
    for lv in ("严重", "高", "中", "低"):
        if lv in text[:160]:
            risk = lv
            break
    return {
        "mode": "llm",
        "configured": True,
        "risk_level": risk,
        "risk_score": {"严重": 95, "高": 75, "中": 45, "低": 15}.get(risk, 50),
        "summary": text,
        "highlights": [],
        "recommendations": [],
        "model": model,
        "request_url": url,
        "config_source": creds.get("source") or "global",
        "note": "AI 推断，需结合强关联证据人工复核。",
        "citations": cite,
        "evidence_refs": refs,
        "citation_note": citation_note(cite),
    }


# ─── 模块级 AI 分析 ─────────────────────────────────────────────────────────

_SECTION_LABELS: Dict[str, str] = {
    "process": "进程",
    "service": "服务",
    "task": "计划任务",
    "startup": "启动项",
    "accounts": "本地用户",
    "ps": "PowerShell/Shell 历史",
    "registry": "注册表",
    "office": "Office 痕迹",
    "wmi": "WMI",
    "eventlog": "系统日志",
    "applogs": "应用日志",
    "network": "网络连接",
    "exec": "执行痕迹",
    "remote": "远程凭据",
    "browser": "浏览器",
    "driver": "驱动",
    "security": "安全策略",
    "disk": "磁盘变更",
    "program": "已安装程序",
}

_SECTION_FMT = (
    "用简洁中文 Markdown 输出，只写风险相关，结构固定为：\n"
    "1) 风险等级（严重/高/中/低）与一句话理由；\n"
    "2) 可疑条目（候选）：用 Markdown 表格，表头含「名称|位置/路径|原因」三列；"
    "另有补充项可用无序列表。\n"
    "措辞须用「候选」表述风险结论，未经人工复核接受前禁止写「确认」恶意/入侵。"
    "不要输出处置建议、核查步骤或任何操作指引。禁止编造列表外证据。"
)

_SECTION_PROMPTS: Dict[str, str] = {
    "process": (
        "以下是主机进程列表快照。关注：未签名进程、路径异常（临时目录/AppData/Downloads、"
        "系统目录下的非系统程序）、可疑命令行（编码、下载、执行策略绕过）、可疑父子关系。\n"
        "重要：可疑条目表格须尽量覆盖样本中每一条「未签名/空签名」或路径异常的进程，"
        "不要只挑几条代表性样本；若条目过多可按风险排序，但仍应尽量列全。"
        + _SECTION_FMT
    ),
    "service": (
        "以下是主机服务列表。关注：服务路径异常、使用非系统目录或临时目录、未签名或公司字段空白、"
        "状态异常（Stopped 但 start_type=Auto）。"
        + _SECTION_FMT
    ),
    "task": (
        "以下是计划任务列表。关注：命令行含编码/下载/脚本执行、路径指向临时目录、作者字段伪造、"
        "触发器频率异常。"
        + _SECTION_FMT
    ),
    "startup": (
        "以下是启动项列表。关注：非常规路径、命令行含编码或绕过参数、未签名条目。"
        + _SECTION_FMT
    ),
    "accounts": (
        "以下是本地用户列表。关注：陌生账户、隐藏/禁用账户、隶属高权限组、UID=0（Linux）、"
        "SID 异常。"
        + _SECTION_FMT
    ),
    "ps": (
        "以下是 PowerShell/Shell 历史记录。关注：编码命令（-EncodedCommand）、下载执行（IEX/wget/curl）、"
        "凭据操作、横向移动命令（psexec/wmic/schtasks）、混淆。"
        + _SECTION_FMT
    ),
    "registry": (
        "以下是注册表相关数据。关注：Run/RunOnce 项含可疑路径、COM劫持、禁用安全功能的键值。"
        + _SECTION_FMT
    ),
    "office": (
        "以下是 Office 相关痕迹（宏、加载项、最近文件）。关注：宏自动执行、可疑加载项路径、"
        "带宏的文件。"
        + _SECTION_FMT
    ),
    "wmi": (
        "以下是 WMI 持久化数据（订阅、绑定）。关注：事件过滤器+消费者绑定、CommandLineEventConsumer、"
        "ActiveScriptEventConsumer。"
        + _SECTION_FMT
    ),
    "eventlog": (
        "以下是系统日志事件（规则命中或全量片段）。关注：高危 EventID（4624/4625/4688/4698/7045等）、"
        "异常登录、日志清除（1102/104）、进程创建中的可疑命令行。"
        + _SECTION_FMT
    ),
    "applogs": (
        "以下是服务器应用/中间件日志（Web access、error 等，可能已含规则命中标记）。"
        "关注：路径穿越、敏感文件探测、扫描器 UA、SQL/命令注入、WebShell、Log4j/反序列化、"
        "管理后台爆破、异常状态码与可疑 URL。"
        "可疑条目表格优先覆盖带 hit/rule 命中的行，再补充其它高风险原文。"
        + _SECTION_FMT
    ),
    "network": (
        "以下是网络连接快照。关注：连接到非常规端口、已知恶意 IP 段、发起连接的进程路径可疑。"
        + _SECTION_FMT
    ),
    "exec": (
        "以下是执行痕迹（Prefetch/UserAssist/JumpList/Amcache 等）。"
        "关注：恶意工具（mimikatz/meterpreter/cobalt strike等）、临时路径程序、时间点异常。"
        + _SECTION_FMT
    ),
    "remote": (
        "以下是远程访问凭据/工具数据。关注：RDP 历史连接至陌生主机、SSH 密钥指向外部、"
        "cmdkey 存储凭据、未授权的远控工具。"
        + _SECTION_FMT
    ),
}

_DEFAULT_SECTION_PROMPT = (
    "以下是主机某模块的采集数据，请分析是否存在安全风险。"
    + _SECTION_FMT
)


def _section_heuristic(
    section: str,
    items: list,
    hostname: str = "",
    hint: str = "",
) -> Dict[str, Any]:
    """无 LLM 时的简单启发式分析（计数 + 签名统计）。"""
    label = _SECTION_LABELS.get(section, section)
    total = len(items)
    unsigned = sum(
        1 for x in items
        if isinstance(x, dict)
        and str(x.get("signature") or x.get("sig_status") or "").strip().lower()
        in ("", "missing", "notsigned", "unsigned", "error", "unknown", "-")
    )
    summary = (
        f"模块「{label}」共 {total} 条记录"
        f"（主机 {hostname or '未知'}）。\n"
    )
    if total == 0:
        summary += "无数据，无法进一步分析。\n"
    elif section in ("ps",):
        suspicious = [
            x for x in items
            if isinstance(x, dict) and any(
                kw in str(x.get("command") or x.get("line") or "").lower()
                for kw in ("encodedcommand", "iex", "invoke-expression", "downloadstring",
                           "base64", "bypass", "hidden", "wget", "curl", "bitsadmin")
            )
        ]
        if suspicious:
            summary += f"检测到 {len(suspicious)} 条可疑命令（含编码/下载/绕过关键词），需优先排查。\n"
        else:
            summary += "未发现明显可疑命令特征（建议结合上下文人工核实）。\n"
    elif unsigned and total:
        pct = round(unsigned * 100 / total)
        summary += f"未签名/空签名条目 {unsigned}/{total}（{pct}%），建议核查路径与来源。\n"
    else:
        summary += "签名状态正常，建议结合规则告警与路径特征人工核实。\n"

    risk = "低"
    score = 10
    if section in ("ps",) and any(
        isinstance(x, dict) and any(
            kw in str(x.get("command") or x.get("line") or "").lower()
            for kw in ("encodedcommand", "iex", "downloadstring", "base64")
        )
        for x in items
    ):
        risk, score = "高", 70
    elif unsigned > 5:
        risk, score = "中", 40

    return {
        "mode": "heuristic",
        "section": section,
        "label": label,
        "risk_level": risk,
        "risk_score": score,
        "summary": summary,
        "highlights": [],
        "recommendations": [],
    }


# 进程等模块送模型时优先保留的字段（空值也保留，避免签名/路径丢失）
_SECTION_KEEP_KEYS: Dict[str, tuple] = {
    "process": (
        "pid", "PID", "ppid", "PPID", "name", "path", "command_line", "command",
        "CommandLine", "user", "User", "signature", "sig_status", "SigStatus",
        "company", "signer", "start_time", "source",
    ),
    "service": (
        "name", "status", "start_type", "path", "command", "payload",
        "signature", "sig_status", "company", "pid",
    ),
    "task": (
        "name", "status", "command", "payload", "author", "signature",
        "sig_status", "company", "next_run",
    ),
    "startup": ("name", "command", "path", "user", "signature", "sig_status", "company"),
    "applogs": ("time", "file", "line_no", "text", "hit", "rule_id", "severity", "title"),
}


def _is_unsigned_item(x: Dict[str, Any]) -> bool:
    raw = str(
        x.get("signature") or x.get("sig_status") or x.get("SigStatus") or ""
    ).strip().lower()
    if x.get("signed") is False:
        return True
    return raw in ("", "missing", "notsigned", "unsigned", "error", "unknown", "-", "空签名", "未签名")


def _section_item_priority(section: str, x: Any) -> int:
    """采样排序：分数越高越优先送模型（避免「前 N 条」漏掉未签名）。"""
    if not isinstance(x, dict):
        return 0
    score = 0
    if section in ("process", "service", "task", "startup"):
        if _is_unsigned_item(x):
            score += 100
        path = str(x.get("path") or x.get("command") or x.get("command_line") or "").lower()
        for bad in (
            "\\temp\\", "/temp/", "\\appdata\\", "/appdata/",
            "\\downloads\\", "\\public\\", "\\virtualstore\\",
            "\\users\\", "/home/", "\\programdata\\",
        ):
            if bad in path:
                score += 40
                break
        name = str(x.get("name") or "").lower()
        if name in ("system", "registry", "idle", "smss.exe", "csrss.exe"):
            score -= 80
    if section == "ps":
        cmd = str(x.get("command") or x.get("line") or "").lower()
        for kw in ("encodedcommand", "iex", "downloadstring", "bypass", "hidden", "base64"):
            if kw in cmd:
                score += 80
                break
    if section == "applogs":
        if isinstance(x.get("hit"), dict) or x.get("rule_id"):
            score += 120
        text = str(x.get("text") or "").lower()
        for kw in ("../", ".git", "jndi:", "union select", "webshell", "eval(", "actuator"):
            if kw in text:
                score += 50
                break
    return score


def _compact_section_items(section: str, items: list, limit: int = 120) -> tuple:
    """精简并优先采样；返回 (compact_list, truncated: bool)。"""
    lim = max(1, min(int(limit or 120), 200))
    ranked = sorted(
        enumerate(items or []),
        key=lambda iv: (-_section_item_priority(section, iv[1]), iv[0]),
    )
    picked = [x for _, x in ranked[:lim]]
    keep = _SECTION_KEEP_KEYS.get(section) or ()
    compact = []
    for x in picked:
        if not isinstance(x, dict):
            compact.append(str(x)[:300])
            continue
        out: Dict[str, Any] = {}
        for k in keep:
            if k in x:
                out[k] = x.get(k)
        for k, v in x.items():
            if k in out:
                continue
            if v in (None, "", [], {}):
                continue
            if isinstance(v, (str, int, float, bool)):
                out[k] = v
            elif isinstance(v, list) and v:
                out[k] = v[:3]
        # 长字段截断，控制 token
        for fk in ("command_line", "command", "CommandLine", "path"):
            if isinstance(out.get(fk), str) and len(out[fk]) > 400:
                out[fk] = out[fk][:400] + "…"
        compact.append(out)
    return compact, len(items or []) > lim


def analyze_section_with_ai(
    section: str,
    items: list,
    hostname: str = "",
    use_llm: bool = True,
    user: Optional[Dict[str, Any]] = None,
    creds: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """对单模块数据做 AI 分析（可选 LLM）。"""
    label = _SECTION_LABELS.get(section, section)
    base = _section_heuristic(section, items, hostname)

    if not use_llm:
        base["note"] = f"仅启发式研判「{label}」。"
        return base

    if creds is None:
        try:
            from ..user_ai import resolve_ai_creds
            creds = resolve_ai_creds(user)
        except Exception:
            creds = {"api_key": "", "base_url": "", "model": "", "timeout": 60, "source": "none"}

    api_key = (creds.get("api_key") or "").strip()
    if not api_key:
        base["note"] = "未配置个人 API Key，已回退启发式。请到「我的大模型」填写并保存（不共用全局）。"
        base["mode"] = "need_config"
        return base

    base_url = (creds.get("base_url") or config.AI_BASE_URL or "").strip()
    model = _normalize_model(creds.get("model") or config.AI_MODEL or "", base_url)
    timeout = float(creds.get("timeout") or config.AI_TIMEOUT or 60)
    url = _chat_completions_url(base_url)

    # 进程等优先送未签名/路径异常，默认最多 120 条（不再死取「列表前 60」）
    sample_limit = 120 if section in ("process", "applogs") else 80
    compact, truncated = _compact_section_items(section, items, limit=sample_limit)
    compact, refs = attach_refs(compact)
    unsigned_n = sum(
        1 for x in (items or [])
        if isinstance(x, dict) and _is_unsigned_item(x)
    )

    system_prompt = _SECTION_PROMPTS.get(section, _DEFAULT_SECTION_PROMPT) + CITATION_RULE
    note = (
        f"「{label}」共 {len(items)} 条，本次送入 {len(compact)} 条"
        f"（未签名约 {unsigned_n}）。"
    )
    if truncated:
        note += "已按风险优先采样（未签名/异常路径优先），并非列表原始顺序前 N 条。未送入条目为候选延期线索。"
    else:
        note += "已覆盖当前筛选范围内全部条目。"

    payload_user = {
        "hostname": hostname or "unknown",
        "section": label,
        "total_count": len(items),
        "unsigned_count": unsigned_n,
        "sample_count": len(compact),
        "truncated": truncated,
        "sample": compact,
        "note": note,
        "instruction": (
            "请基于 sample 逐条研判；未签名进程应尽量全部出现在「可疑条目」表格中。"
            "结论一律为候选，勿写确认。"
            if section == "process"
            else "请基于 sample 研判，勿编造 sample 外证据。结论一律为候选，勿写确认。"
        ),
    }

    try:
        send = _chat_sender(url, api_key, model, timeout)
        text, cite = cited_completion(send, [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(payload_user, ensure_ascii=False)},
        ], list(refs))
    except Exception as e:
        detail = _http_error_detail(e)
        base["mode"] = "heuristic_fallback"
        base["error"] = str(detail)[:400]
        base["truncated"] = truncated
        base["deferred"] = True
        base["note"] = f"大模型调用失败，已回退启发式研判。原因：{str(detail)[:200]}"
        base["config_source"] = creds.get("source") or "global"
        base["model"] = model
        return base

    if not text:
        base["mode"] = "heuristic_fallback"
        base["truncated"] = truncated
        base["deferred"] = True
        base["note"] = "模型返回空内容，已回退启发式分析。"
        return base

    risk = "中"
    for lv in ("严重", "高", "中", "低"):
        if lv in text[:200]:
            risk = lv
            break
    return {
        "mode": "llm",
        "section": section,
        "label": label,
        "risk_level": risk,
        "risk_score": {"严重": 95, "高": 75, "中": 45, "低": 15}.get(risk, 45),
        "summary": text,
        "highlights": [],
        "recommendations": [],
        "model": model,
        "request_url": url,
        "config_source": creds.get("source") or "global",
        "truncated": truncated,
        "deferred": bool(truncated),
        "note": "AI 模块分析（候选），需结合规则告警与原始证据人工复核，未经接受前非确认。",
        "citations": cite,
        "evidence_refs": refs,
        "citation_note": citation_note(cite),
    }
