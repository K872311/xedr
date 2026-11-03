"""Linux 规则匹配：rules/linux/* + rules-linux-system.json + 启发式。

对齐 Windows persistence：分析 Linux 报告时由 pipeline 调用本 matcher。
规则来源：LinuxEmergencyTool-C 抽取包（sigma / signatures / process / network / kernel / tools_rules 权限维持）。
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import Finding
from ..rules_loader import RuleStore

_SUS_CRON = re.compile(
    r"(curl\s|wget\s|python[23]?\s|perl\s|ruby\s|php\s|nc\s|ncat\s|bash\s+-i|/dev/tcp/|"
    r"base64\s+-d|mkfifo|/tmp/|/dev/shm/|/var/tmp/|chmod\s+[+]x|"
    r"nohup\s|/root/\.|/\$\(|&\s*$)",
    re.I,
)
_SUS_UNIT = re.compile(
    r"(ExecStart=.*/(tmp|dev/shm|var/tmp)/|"
    r"/(tmp|dev/shm|var/tmp|home)/[^\s;]*\.(sh|py|elf|bin|out)\b|"
    r"curl\s|wget\s|base64|/dev/tcp/|bash\s+-i|nc\s+-e)",
    re.I,
)
_SUS_PATH = re.compile(
    r"^/(tmp|dev/shm|var/tmp|home)/|/opt/[^/\s]+/(tmp|raw|payload)/",
    re.I,
)

_REGEX_CACHE: Dict[str, Optional[re.Pattern]] = {}

# 过短/过宽的 contains 规则易误伤系统进程；命中后按行过滤
_KERNEL_NAME_RE = re.compile(r"^\[.+\]$")


def _module_diff_indicates_hidden_lkm(mod_diff: str) -> bool:
    """仅在「sysfs initstate=live 却不在 /proc/modules」时告警。

    旧版「剩余可疑」含大量参数目录/builtin 漏滤，不再据此出 Rootkit 告警。
    """
    text = str(mod_diff or "")
    if not text.strip():
        return False
    m = re.search(r"强可疑[^=\n]*=\s*(\d+)", text)
    if m:
        return int(m.group(1)) > 0
    # 强可疑段有实质行（非空）
    if re.search(r"---\s*强可疑", text):
        block = re.split(r"---\s*强可疑[^\n]*---", text, maxsplit=1)
        if len(block) > 1:
            body = re.split(r"\n---\s+", block[1], maxsplit=1)[0]
            for ln in body.splitlines():
                s = ln.strip()
                if s and s != "(空)" and not s.startswith("#"):
                    return True
        return False
    # 极旧英文输出
    if re.search(r"only in\s+/sys/module|hidden\s+lkm|hidden\s+module", text, re.I):
        return True
    return False


# 采集器自报告 / 上次采集产物进入语料后的噪声行
_COLLECTOR_NOISE_RE = re.compile(
    r"(?i)(?:^|/|\\)"
    r"(?:LinuxSC_v?\d[\w.-]*\.sh|_COLLECT_FOOTPRINT\.txt|"
    r"LinuxSC_[\w.:-]+/|"
    r"collect_[\w.-]+\.json|"
    r"\.local/share/Trash/|"
    r"Hunt/prompt_command\.txt|SystemInfo/prompt_command\.txt|"
    r"Hunt/systemd_sus_exec\.txt)"
)
# pattern → 若证据行匹配这些，视为误报丢弃
_FP_PATTERN_DROPS: Dict[str, Tuple[re.Pattern, ...]] = {
    "daemon": (
        re.compile(r"-daemon\b", re.I),
        re.compile(r"/usr/(libexec|lib|bin)/.*daemon", re.I),
    ),
    "kdevtmpf": (re.compile(r"\[kdevtmpfs?\]", re.I), re.compile(r"\bkdevtmpfs\b", re.I)),
    "kswapd0": (re.compile(r"\[kswapd\d*\]", re.I),),
    "kswapd1": (re.compile(r"\[kswapd\d*\]", re.I),),
    "netns": (re.compile(r"\[.*netns.*\]", re.I), re.compile(r"\bknetns\b", re.I)),
    "watch": (
        re.compile(r"\[watchdogd?\]", re.I),
        re.compile(r"\bwatchdogd\b", re.I),
        re.compile(r"--watch\b", re.I),
        re.compile(r"systemd-tty-ask-password-agent", re.I),
    ),
    "watchdog": (re.compile(r"\[watchdogd?\]", re.I), re.compile(r"\bwatchdogd\b", re.I)),
    "sshd -d": (
        re.compile(r"/usr/sbin/sshd\s+-D\b", re.I),
        re.compile(r"\bsshd\s+-D\b", re.I),
        re.compile(r"\bsshd\.service\b", re.I),
    ),
    "sshd -D": (
        re.compile(r"/usr/sbin/sshd\s+-D\b", re.I),
        re.compile(r"\bsshd\s+-D\b", re.I),
        re.compile(r"\bsshd\.service\b", re.I),
    ),
    "systemd-update": (
        # 官方 systemd 组件：update-done / update-utmp*，非恶意进程名 systemd-update
        re.compile(r"systemd-update-(done|utmp)", re.I),
        re.compile(r"/usr/lib/systemd/systemd-update-", re.I),
        re.compile(r"systemd-update-utmp", re.I),
    ),
    # 过宽内网/回环 IP 规则：合法服务常带 127.0.0.1 / 0.0.0.0
    "127\\.0\\.0\\.1|0\\.0\\.0\\.0|10\\.\\d+\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.": (
        re.compile(r"\bchronyc?\b", re.I),
        re.compile(r"chrony-wait", re.I),
        re.compile(r"/usr/(bin|sbin|lib)/", re.I),
        re.compile(r"\b(sshd|nginx|httpd|named|dnsmasq|redis|mysqld|postgres|cupsd|rpcbind)\b", re.I),
        re.compile(r"ListenStream\s*=\s*127\.0\.0\.1", re.I),
    ),
    "chroot": (
        re.compile(r"--chroot=", re.I),
        re.compile(r"\bwsdd\b", re.I),
    ),
    "systemctl start": (
        re.compile(r"/usr/bin/systemctl\s+start\b", re.I),
        re.compile(r"\.service\b", re.I),
    ),
    "cat /dev/null": (
        re.compile(r"profile\.d/", re.I),
        re.compile(r"/etc/profile\b", re.I),
        re.compile(r"debuginfod", re.I),
        re.compile(r"^\s*#", re.I),
    ),
    "(bash": (
        re.compile(r"/etc/profile", re.I),
        re.compile(r"profile\.d/", re.I),
        re.compile(r"^\s*#", re.I),
    ),
    "(sh": (
        re.compile(r"/etc/profile", re.I),
        re.compile(r"profile\.d/", re.I),
        re.compile(r"lesspipe", re.I),
        re.compile(r"^\s*#", re.I),
    ),
    "fetch": (
        re.compile(r"snap-repair", re.I),
        re.compile(r"apt-get\s+.*fetch", re.I),
        re.compile(r"\bfetchmail\b", re.I),
    ),
    # 过宽 "network"：系统网络栈 / DHCP 客户端
    "network": (
        re.compile(r"\bNetworkManager\b", re.I),
        re.compile(r"\bsystemd-networkd\b", re.I),
        re.compile(r"/usr/(s?bin|libexec)/NetworkManager", re.I),
        re.compile(r"NetworkManager\.service", re.I),
        re.compile(r"\bnm-(applet|online|dispatcher)\b", re.I),
        re.compile(r":67\b.*NetworkManager", re.I),
        re.compile(r":68\b.*NetworkManager", re.I),
    ),
    # nc -l / --listen：发行版合法 *-launch / cockpit
    "nc|ncat|netcat|--listen": (
        re.compile(r"\bdbus-broker-launch\b", re.I),
        re.compile(r"\bat-spi-bus-launcher\b", re.I),
        re.compile(r"\bcockpit-ws\b", re.I),
        re.compile(r"/usr/(bin|libexec)/.*-launch(?:er)?\b", re.I),
        re.compile(r"shell_rc/(bashrc|profile)\b", re.I),
        re.compile(r"#\s*/etc/bashrc\b", re.I),
    ),
    "alias\\s+rm\\s*=": (
        re.compile(r"alias\s+rm\s*=\s*['\"]rm\s+-[fiI]+['\"]", re.I),
    ),
    "getpeername": (
        re.compile(r"getpeername\s+failed:\s*%\.100s", re.I),
        re.compile(r"sshd_bin_meta|strings_ioc", re.I),
    ),
}


def _scrub_collector_noise(text: str) -> str:
    """去掉采集脚本自描述、足迹文件、历史采集 JSON 等噪声行。"""
    if not text:
        return ""
    kept: List[str] = []
    for ln in str(text).splitlines():
        if _COLLECTOR_NOISE_RE.search(ln):
            continue
        # grep 命中行经常是「脚本路径:行号:模式本身」
        if re.search(r"(?i)LinuxSC.*\.(sh|txt|json):\d+", ln):
            continue
        if re.search(r"(?i)\{[^\n]*\"(?:name|command|cmdline)\"\s*:", ln) and (
            "bashrc" in ln.lower() or "LinuxSC" in ln or "collect_" in ln
        ):
            continue
        kept.append(ln)
    return "\n".join(kept)


def _is_fp_evidence_line(pattern: str, line: str) -> bool:
    """已知误报证据行（系统内核线程 / 发行版守护进程等）。"""
    pat = str(pattern or "").strip().lower()
    ln = str(line or "").strip()
    if not ln:
        return False
    # 采集器自命中：任意规则证据行含脚本/足迹路径 → 丢弃
    if _COLLECTOR_NOISE_RE.search(ln) or re.search(r"(?i)LinuxSC.*\.(sh|txt):\d+", ln):
        return True
    if not pat:
        return False
    # 内核线程整体：短 pattern 命中 [kxxx] 基本都是误报
    if _KERNEL_NAME_RE.search(ln) and len(pat) <= 12:
        # 允许规则本身就是完整恶意名且与括号内完全一致
        inner = re.search(r"\[([^\]]+)\]", ln)
        if inner and inner.group(1).lower() == pat:
            return False
        return True
    # nc listen 规则：合法 launch 守护进程
    if any(x in pat for x in ("nc|", "(nc", "ncat", "netcat", "--listen")):
        drops_nc = _FP_PATTERN_DROPS.get("nc|ncat|netcat|--listen")
        if drops_nc and any(rx.search(ln) for rx in drops_nc):
            return True
    if "alias" in pat and "rm" in pat:
        drops_rm = _FP_PATTERN_DROPS.get(r"alias\s+rm\s*=")
        if drops_rm and any(rx.search(ln) for rx in drops_rm):
            return True
    if "getpeername" in pat:
        drops_gp = _FP_PATTERN_DROPS.get("getpeername")
        if drops_gp and any(rx.search(ln) for rx in drops_gp):
            return True
    drops = _FP_PATTERN_DROPS.get(pat)
    if not drops and "systemd-update" in pat:
        drops = _FP_PATTERN_DROPS.get("systemd-update")
    # 内网/回环过宽规则：任意含 127.0.0.1|10.|172.1x 的 regex
    if not drops and ("127.0.0.1" in pat or "127\\.0\\.0\\.1" in pat) and (
        "10\\" in pat or "172\\" in pat or "0\\.0\\.0\\.0" in pat or "0.0.0.0" in pat
    ):
        drops = _FP_PATTERN_DROPS.get(
            r"127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.|172\.(1[6-9]|2[0-9]|3[0-1])\."
        )
    if not drops:
        return False
    return any(rx.search(ln) for rx in drops)


def _filter_fp_evidence_lines(pattern: str, lines: List[str]) -> List[str]:
    return [ln for ln in (lines or []) if not _is_fp_evidence_line(pattern, ln)]


def _add(findings: List[Finding], seen: Set[str], *, category: str, severity: str,
         title: str, evidence: str, rule_id: str = "", extra: Optional[Dict[str, Any]] = None,
         evidence_limit: int = 1200) -> None:
    k = f"{category}|{title}|{evidence[:160]}|linux"
    if k in seen:
        return
    seen.add(k)
    findings.append(Finding(
        category, severity, title, evidence[: max(200, int(evidence_limit))],
        "linux_persistence", rule_id or "linux", "linux_persistence",
        extra=dict(extra or {}),
    ))


def _blob_hit(blob: str, pattern: str, match_type: str, needles: Any) -> bool:
    if needles:
        low = (blob or "").lower()
        return any(str(n) and str(n).lower() in low for n in needles)
    return _hit(blob or "", pattern, match_type)


def _snippet_lines(
    text: str,
    pattern: str,
    match_type: str,
    needles: Any = None,
    *,
    limit: int = 8,
    width: int = 220,
) -> List[str]:
    """从语料中抽出真正命中的行/片段，避免证据只剩规则 reason。"""
    if not text:
        return []
    lines = text.splitlines()
    out: List[str] = []
    seen_l: Set[str] = set()

    def push(s: str) -> None:
        s = re.sub(r"\s+", " ", (s or "").strip())
        if not s or s in seen_l:
            return
        seen_l.add(s)
        out.append(s[:width])

    if needles:
        for n in needles:
            needle = str(n or "")
            if not needle:
                continue
            low_n = needle.lower()
            for ln in lines:
                if low_n in ln.lower():
                    push(ln)
                    if len(out) >= limit:
                        return out
        return out

    mt = (match_type or "contains").lower()
    if mt == "regex":
        rx = _compile(pattern)
        if not rx:
            return []
        for ln in lines:
            if rx.search(ln):
                push(ln)
                if len(out) >= limit:
                    return out
        if not out:
            m = rx.search(text)
            if m:
                a = max(0, m.start() - 80)
                b = min(len(text), m.end() + 80)
                push(text[a:b].replace("\n", " "))
        return out

    # contains / exact：优先整行，其次窗口
    pat = pattern or ""
    if not pat:
        return []
    low_p = pat.lower()
    for ln in lines:
        if low_p in ln.lower():
            push(ln)
            if len(out) >= limit:
                return out
    if not out:
        idx = text.lower().find(low_p)
        if idx >= 0:
            a = max(0, idx - 80)
            b = min(len(text), idx + len(pat) + 80)
            push(text[a:b].replace("\n", " "))
    return out


def _structured_evidence(
    report: Dict,
    pattern: str,
    match_type: str,
    needles: Any,
) -> Tuple[List[str], str]:
    """优先从进程/服务/任务/启动项抽结构化证据与路径。"""
    lines: List[str] = []
    best_path = ""

    def take_path(*vals: Any) -> None:
        nonlocal best_path
        if best_path:
            return
        for v in vals:
            s = str(v or "").strip()
            if s.startswith("/") and len(s) < 260:
                best_path = s
                return

    for p in report.get("processes") or []:
        if not isinstance(p, dict):
            continue
        blob = " ".join(str(p.get(k) or "") for k in (
            "name", "comm", "cmdline", "command", "path", "exe", "cwd",
        ))
        if not _blob_hit(blob, pattern, match_type, needles):
            continue
        name = str(p.get("name") or p.get("comm") or "")
        cmd = str(p.get("cmdline") or p.get("command") or p.get("exe") or p.get("path") or "")
        lines.append(f"[进程] {name} pid={p.get('pid') or '?'} → {cmd}"[:500])
        take_path(p.get("exe"), p.get("path"), p.get("cwd"))
        if len(lines) >= 8:
            return lines, best_path

    for s in report.get("services") or []:
        if not isinstance(s, dict):
            continue
        blob = " ".join(str(s.get(k) or "") for k in (
            "name", "description", "path", "command", "status", "start_type", "fragment_path",
        ))
        if not _blob_hit(blob, pattern, match_type, needles):
            continue
        name = str(s.get("name") or "")
        cmd = str(s.get("command") or s.get("path") or "")
        st = str(s.get("status") or "")
        lines.append(f"[服务] {name} ({st or '-'}) → {cmd}"[:500])
        take_path(s.get("path"), s.get("command"), s.get("fragment_path"))
        if len(lines) >= 8:
            return lines, best_path

    for t in report.get("scheduled_tasks") or []:
        if not isinstance(t, dict):
            continue
        blob = " ".join(str(t.get(k) or "") for k in (
            "task_name", "name", "command", "path", "user", "status",
        ))
        if not _blob_hit(blob, pattern, match_type, needles):
            continue
        name = str(t.get("task_name") or t.get("name") or "")
        cmd = str(t.get("command") or t.get("path") or "")
        lines.append(f"[计划任务] {name} → {cmd}"[:500])
        take_path(t.get("path"), t.get("command"))
        if len(lines) >= 8:
            return lines, best_path

    for si in report.get("startup_items") or []:
        if not isinstance(si, dict):
            continue
        blob = " ".join(str(si.get(k) or "") for k in (
            "location", "name", "path", "command", "user",
        ))
        if not _blob_hit(blob, pattern, match_type, needles):
            continue
        loc = str(si.get("location") or "")
        name = str(si.get("name") or "")
        cmd = str(si.get("command") or si.get("path") or "")
        lines.append(f"[启动项] {loc}/{name} → {cmd}"[:500])
        take_path(si.get("path"), si.get("command"))
        if len(lines) >= 8:
            return lines, best_path

    # 端口 / 连接：避免证据变成「67 68 22 53…」数字糊
    port_lines, port_path = _port_or_net_evidence(report, pattern, match_type, needles)
    if port_lines and not lines:
        return port_lines, port_path or best_path
    if port_lines:
        lines.extend(port_lines)
        if not best_path:
            best_path = port_path

    return lines[:8], best_path


def _conn_port(c: Dict[str, Any]) -> str:
    for k in ("local_port", "remote_port", "port"):
        if c.get(k) not in (None, ""):
            return str(c.get(k)).strip()
    for k in ("local_addr", "local_address", "remote_addr", "remote_address", "remote", "peer"):
        s = str(c.get(k) or "")
        if ":" in s:
            return s.rsplit(":", 1)[-1].strip("[]")
    return ""


def _port_or_net_evidence(
    report: Dict,
    pattern: str,
    match_type: str,
    needles: Any,
) -> Tuple[List[str], str]:
    """端口/网络类规则：列出具体监听或连接。"""
    pat = str(pattern or "").strip()
    want_ports: Set[str] = set()
    if pat.isdigit():
        want_ports.add(pat)
    if needles:
        for n in needles:
            if str(n).strip().isdigit():
                want_ports.add(str(n).strip())

    lines: List[str] = []
    best_path = ""

    def push(s: str) -> None:
        s = re.sub(r"\s+", " ", (s or "").strip())
        if s and s not in lines:
            lines.append(s[:500])

    # 精确端口
    if want_ports:
        for c in (report.get("open_ports") or report.get("listening_ports") or []):
            if isinstance(c, dict):
                p = _conn_port(c) or str(c.get("port") or "")
                if p not in want_ports:
                    continue
                proc = str(c.get("process_name") or c.get("process") or c.get("name") or c.get("exe") or "")
                addr = str(c.get("local_addr") or c.get("local_address") or c.get("address") or "")
                push(f"[监听] :{p} {addr} {proc}".strip())
                if not best_path and proc.startswith("/"):
                    best_path = proc
            else:
                if str(c).strip() in want_ports:
                    push(f"[监听] :{c}")
            if len(lines) >= 8:
                return lines, best_path
        for c in report.get("established_connections") or []:
            if not isinstance(c, dict):
                continue
            lp = str(c.get("local_port") or "")
            rp = str(c.get("remote_port") or "")
            # 也从地址里拆
            if not lp:
                lp = _conn_port({"local_addr": c.get("local_addr") or c.get("local_address")})
            if not rp:
                rp = _conn_port({"remote_addr": c.get("remote_addr") or c.get("remote_address")})
            if lp not in want_ports and rp not in want_ports:
                continue
            proc = str(c.get("process_name") or c.get("process") or c.get("name") or "")
            la = str(c.get("local_addr") or c.get("local_address") or "")
            ra = str(c.get("remote_addr") or c.get("remote_address") or c.get("remote") or "")
            pid = c.get("pid") or ""
            proc_s = f"{proc} (PID {pid})" if proc and pid else (proc or (f"PID {pid}" if pid else ""))
            push(f"[连接] {la or (':' + lp)} → {ra or (':' + rp)} {proc_s}".strip())
            if len(lines) >= 8:
                return lines, best_path
        if lines:
            return lines, best_path

    # 非数字 pattern：在连接串里找命中行
    for c in report.get("established_connections") or []:
        if not isinstance(c, dict):
            continue
        blob = " ".join(str(c.get(k) or "") for k in c.keys())
        if not _blob_hit(blob, pattern, match_type, needles):
            continue
        proc = str(c.get("process_name") or c.get("process") or c.get("name") or "")
        la = str(c.get("local_addr") or c.get("local_address") or "")
        ra = str(c.get("remote_addr") or c.get("remote_address") or c.get("remote") or "")
        pid = c.get("pid") or ""
        proc_s = f"{proc} (PID {pid})" if proc and pid else (proc or (f"PID {pid}" if pid else ""))
        push(f"[连接] {la} → {ra} {proc_s}".strip())
        if len(lines) >= 8:
            break
    return lines, best_path


def _evidence_for_rule(
    report: Dict,
    text: str,
    pattern: str,
    match_type: str,
    needles: Any,
    reason: str,
    *,
    bucket: str = "",
) -> Tuple[str, Dict[str, Any]]:
    struct, path = _structured_evidence(report, pattern, match_type, needles)
    # 网络/端口桶优先走连接/监听明细，避免 chronyc -h 127.0.0.1 等服务行抢证据
    if bucket in ("network", "port") or (str(pattern).strip().isdigit() and (match_type or "").lower() == "exact"):
        port_lines, port_path = _port_or_net_evidence(report, pattern, match_type, needles)
        if port_lines:
            struct = port_lines
            path = path or port_path
    snippets = struct or _snippet_lines(text, pattern, match_type, needles)
    # 丢弃「纯数字空格」糊证据
    snippets = [
        s for s in snippets
        if s and not re.fullmatch(r"[\d\s./:]+", s.strip())
    ]
    raw_hit_n = len(snippets)
    # 系统内核线程 / 发行版守护进程等误报行
    snippets = _filter_fp_evidence_lines(pattern, snippets)
    if raw_hit_n > 0 and not snippets:
        # 命中行全是误报 → 整条规则跳过（勿再用 reason 兜底）
        return "", {"pattern": pattern or "", "match_type": match_type or "contains", "fp_filtered": True}
    parts: List[str] = []
    if snippets:
        parts.extend(snippets[:8])
    elif reason and not _is_fp_evidence_line(pattern, reason):
        parts.append(reason)
    show_pat = pattern if pattern else (", ".join(str(n) for n in (needles or [])[:6]))
    if show_pat and parts and show_pat not in "\n".join(parts):
        parts.append(f"匹配模式: {show_pat}")
    if not parts:
        return "", {"pattern": pattern or "", "match_type": match_type or "contains", "fp_filtered": True}
    extra: Dict[str, Any] = {
        "pattern": pattern or "",
        "match_type": match_type or "contains",
    }
    if path:
        extra["path"] = path
    elif pattern.startswith("/") and " " not in pattern.strip():
        extra["path"] = pattern.strip()
    return "\n".join(parts)[:1200], extra


# 开头的 .* 对 re.search 无意义（search 本就扫描所有起点），却会让引擎在大语料上
# 退化成 O(n²)：实测 ".*(ngrok\.com|...)" 匹配 320KB 文本要 43 秒，且全程持有 GIL，
# 会冻住整个进程（含 FastAPI 事件循环）。编译前统一剥掉，语义不变。
_LEADING_STAR_RE = re.compile(r"^(?:\.\*\??)+")


def _stripped_leading_star(pat: str) -> str:
    """去掉开头多余的 .*。只处理两种可证明等价的形态，其余原样返回。

    1) 整个 pattern 以 .* 开头        → 直接剥掉（search 本就扫描所有起点）
    2) 顶层纯 alternation 且无 ( 和 ^ → 每个分支各自剥掉

    带 ^ 或分组时按 | 切分会误伤（如 "^(x|.*y)" 切开后剥离会改变语义），一律不动。
    """
    if ".*" not in pat:
        return pat
    if "^" not in pat and "(" not in pat and "|" in pat:
        segs = [_LEADING_STAR_RE.sub("", s) or s for s in pat.split("|")]
        return "|".join(segs)
    if pat.startswith(".*"):
        return _LEADING_STAR_RE.sub("", pat) or pat
    return pat


def _compile(pat: str) -> Optional[re.Pattern]:
    if pat in _REGEX_CACHE:
        return _REGEX_CACHE[pat]
    try:
        rx = re.compile(_stripped_leading_star(pat), re.I)
    except re.error:
        rx = None
    _REGEX_CACHE[pat] = rx
    return rx


# 单条规则匹配耗时超过此阈值即告警，便于尽早发现下一个"正则炸弹"。
# 健康规则在 600KB 语料上是个位数毫秒；50ms 已属异常，需在它随语料增长放大成秒级前发现。
_SLOW_RULE_MS = 50.0
_slow_reported: Set[str] = set()


def _hit(text: str, pattern: str, match_type: str) -> bool:
    if not text or not pattern:
        return False
    mt = (match_type or "contains").lower()
    if mt == "exact":
        return pattern.lower() == text.lower() or pattern.lower() in {
            p.strip().lower() for p in re.split(r"[\s,/|]+", text) if p.strip()
        }
    if mt == "regex":
        rx = _compile(pattern)
        if not rx:
            return False
        t0 = time.perf_counter()
        try:
            return bool(rx.search(text))
        finally:
            el = (time.perf_counter() - t0) * 1000.0
            if el >= _SLOW_RULE_MS and pattern not in _slow_reported:
                _slow_reported.add(pattern)
                try:
                    from .. import applog
                    applog.warn(
                        "rules",
                        f"slow regex {el:.0f}ms on {len(text)}B corpus: {pattern[:160]}",
                        ms=round(el, 1),
                        corpus=len(text),
                        pattern=pattern[:300],
                    )
                except Exception:
                    pass
    # contains / wildcard fallback
    return pattern.lower() in text.lower()


def _linux_packs(store: RuleStore) -> List[Dict[str, Any]]:
    packs: List[Dict[str, Any]] = []
    raw = getattr(store, "raw", None)
    if isinstance(raw, dict):
        for k, v in raw.items():
            if not isinstance(v, dict):
                continue
            kn = str(k).replace("\\", "/")
            if "linux" in kn.lower() or (isinstance(v.get("meta"), dict)
                                         and str(v["meta"].get("os_family") or "").lower() == "linux"):
                packs.append(v)
    linux = getattr(store, "linux", None)
    if isinstance(linux, dict) and linux not in packs:
        packs.append(linux)
    return packs


_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _iter_rules(packs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    keys = (
        "textRules", "processRules", "commandRules", "networkRules",
        "portRules", "moduleRules", "sigmaRules",
    )
    # 第一趟：按 id 去重（与历史行为一致）
    picked: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()
    for doc in packs:
        for key in keys:
            for rule in doc.get(key) or []:
                if not isinstance(rule, dict) or rule.get("enabled") is False:
                    continue
                rid = str(rule.get("id") or "")
                if rid and rid in seen_ids:
                    continue
                if rid:
                    seen_ids.add(rid)
                picked.append(rule)

    # 第二趟：语义去重。多个规则包互为副本时（0707 覆盖了 process/signatures/network/kernel），
    # id 不同但 (语料桶, match_type, pattern) 相同 —— 匹配结果必然一致，跑 N 遍纯属浪费。
    # 同指纹保留 severity 最高的那份，因此相对第一趟只会去重、不会降级。
    out: List[Dict[str, Any]] = []
    by_fp: Dict[tuple, int] = {}
    for rule in picked:
        pattern = rule.get("pattern")
        if not pattern:
            out.append(rule)
            continue
        fp = (
            _cat_bucket(rule),
            str(rule.get("match_type") or "contains").lower(),
            str(pattern),
        )
        prev = by_fp.get(fp)
        if prev is None:
            by_fp[fp] = len(out)
            out.append(rule)
            continue
        cur_rank = _SEV_RANK.get(str(rule.get("severity") or "").lower(), 0)
        old_rank = _SEV_RANK.get(str(out[prev].get("severity") or "").lower(), 0)
        if cur_rank > old_rank:
            out[prev] = rule
    return out


def _cat_bucket(rule: Dict[str, Any]) -> str:
    cat = str(rule.get("category") or "").lower()
    rid = str(rule.get("id") or "").lower()
    if "port" in rid or cat == "port":
        return "port"
    # 危险进程名（如 *_proc_*_network）优先进程语料，勿因 id 含 network 误进网络桶
    if cat in ("process", "可疑进程") or "_proc_" in rid:
        return "process"
    if cat in ("c2", "mining", "ddns", "network") or "network" in rid or "c2" in rid or "pool" in rid or "ddns" in rid:
        return "network"
    if cat in ("kernel",) or "lkm" in rid or "module" in rid or "rootkit" in cat:
        return "module"
    # 持久化 / 计划任务 / 启动项 / 服务 / 日志痕迹 / 反弹壳 → 命令语料（含 cron/systemd/history/进程 cmdline）
    # 须在 id 含 shell → file 之前，否则 *_sig_reverse_shell_* 会进 file 桶且打不到进程行
    if cat in ("command", "log", "auditd", "journal", "history", "持久化", "计划任务", "启动项", "服务", "可疑命令", "后门") \
            or "cmd" in rid or "cron" in rid or "systemd" in rid or "startup" in rid \
            or "persist" in rid or "timer" in rid or "alias" in rid or "boot" in rid \
            or "history" in rid or "log" in rid \
            or "reverse_shell" in rid or "revshell" in rid or "backdoor" in rid:
        return "command"
    if cat in ("file", "system", "webshell") or "webshell" in cat or "skidmap" in rid or "rkdir" in rid \
            or "rkfile" in rid or "ld_" in rid or "ws_" in rid:
        return "file"
    # 路径类 ssh/shell 痕迹；反弹壳已上提。authorized_keys 等仍走 file（含 ssh_keys 预览）
    if "ssh" in rid or "shell" in rid:
        return "file"
    return "process"


def _build_corpora(report: Dict) -> Dict[str, str]:
    raw = report.get("linuxsc_raw") if isinstance(report.get("linuxsc_raw"), dict) else {}
    se = report.get("security_extras") if isinstance(report.get("security_extras"), dict) else {}

    proc_parts: List[str] = []
    for p in report.get("processes") or []:
        if not isinstance(p, dict):
            continue
        proc_parts.append(" ".join(str(p.get(k) or "") for k in (
            "name", "comm", "cmdline", "command", "path", "exe", "cwd",
        )))

    net_parts: List[str] = []
    ports: List[str] = []
    for c in report.get("established_connections") or []:
        if not isinstance(c, dict):
            continue
        blob = " ".join(str(c.get(k) or "") for k in (
            "remote_addr", "remote_address", "remote_ip", "local_addr", "local_address",
            "remote", "peer", "process", "process_name", "process_path", "pid", "name", "state",
        ))
        net_parts.append(blob)
        for addr in (c.get("remote_addr"), c.get("remote_address"), c.get("local_addr"), c.get("local_address")):
            s = str(addr or "")
            if ":" in s:
                ports.append(s.rsplit(":", 1)[-1].strip("[]"))
        if c.get("remote_port"):
            ports.append(str(c.get("remote_port")))
        if c.get("local_port"):
            ports.append(str(c.get("local_port")))
    for c in report.get("open_ports") or report.get("listening_ports") or []:
        if isinstance(c, dict):
            ports.append(str(c.get("port") or c.get("local_port") or ""))
            net_parts.append(" ".join(str(c.get(k) or "") for k in c.keys()))
        else:
            ports.append(str(c))

    cmd_parts: List[str] = []
    for t in report.get("scheduled_tasks") or []:
        if isinstance(t, dict):
            cmd_parts.append(" ".join(str(t.get(k) or "") for k in (
                "task_name", "name", "command", "path", "user", "status",
            )))
    for s in report.get("services") or []:
        if isinstance(s, dict):
            cmd_parts.append(" ".join(str(s.get(k) or "") for k in (
                "name", "description", "path", "command", "status", "start_type", "fragment_path",
            )))
    for si in report.get("startup_items") or []:
        if isinstance(si, dict):
            cmd_parts.append(" ".join(str(si.get(k) or "") for k in (
                "location", "name", "path", "command", "user",
            )))

    ps = report.get("ps_artifacts") if isinstance(report.get("ps_artifacts"), dict) else {}
    # 采集导入键为 history_entries（见 linux_sc_import._parse_shell_history）
    hist = (
        ps.get("history_entries")
        or ps.get("history")
        or ps.get("shell_history")
        or ps.get("items")
        or []
    )
    if isinstance(hist, dict):
        for v in hist.values():
            cmd_parts.append(str(v)[:8000])
    elif isinstance(hist, list):
        for h in hist[:12000]:
            if isinstance(h, dict):
                cmd_parts.append(str(h.get("line") or h.get("command") or h)[:500])
            else:
                cmd_parts.append(str(h)[:500])
    elif isinstance(hist, str):
        cmd_parts.append(hist[:50_000])

    # raw network dumps
    for k in ("ss_tuanp", "netstat_tuanp", "network"):
        v = raw.get(k)
        if isinstance(v, str):
            net_parts.append(v[:80_000])
        elif isinstance(v, dict):
            net_parts.append(str(v)[:80_000])
    net_obj = report.get("network")
    if isinstance(net_obj, dict):
        net_parts.append(str(net_obj)[:80_000])
    elif isinstance(net_obj, str):
        net_parts.append(net_obj[:80_000])

    mod_parts: List[str] = [
        # 采集 JSON 键为 module_source_diff；旧 raw/zip 可能带 .txt 后缀
        str(se.get("module_source_diff") or se.get("module_source_diff.txt") or ""),
        str(raw.get("lsmod") or ""),
        str(raw.get("modules") or ""),
    ]
    for p in report.get("processes") or []:
        if isinstance(p, dict):
            for m in p.get("modules") or []:
                if isinstance(m, dict):
                    mod_parts.append(str(m.get("name") or m.get("path") or ""))
                else:
                    mod_parts.append(str(m))

    file_parts: List[str] = [
        str(raw.get("preload") or ""),
        str(se.get("ld.so.preload") or ""),
        str(report.get("firewall_rules") or "")[:20_000],
        str(raw.get("environ_ld") or "")[:20_000],
        str(raw.get("deleted_exe") or "")[:20_000],
    ]
    remote = report.get("remote_access") if isinstance(report.get("remote_access"), dict) else {}
    for key in remote.get("ssh_keys") or []:
        if isinstance(key, dict):
            file_parts.append(f"{key.get('path')} {key.get('preview')}")
    # sshd 生效配置（PermitRootLogin 等）进 file/command 语料
    sshd_cfg = str(remote.get("sshd_config") or "")[:80_000]
    if sshd_cfg:
        file_parts.append(sshd_cfg)
        cmd_parts.append(sshd_cfg)

    # Hunt / 安全扩展：软链、webshell、alias、PROMPT_COMMAND、inetd、sshd wrapper、账户异常等
    for k in (
        "ssh_symlink_backdoor", "ssh_symlink_runtime", "ssh_symlink_find", "webshell_hits",
        "hacker_tools", "miner_procs", "risk_ports", "alias", "prompt_command", "inetd_xinetd",
        "sshd_wrapper", "ssh_client_config", "pam_security_sos", "pam_d_extra",
        "path_hijack", "cred_drop_paths", "systemd_sus_exec", "fake_binaries",
        "uid0_accounts", "empty_password_users", "sshd_bin_meta", "rpm_va_keypkgs",
        "services_high_ports", "loaded_unsigned_so", "disk_unsigned_so",
    ):
        v = se.get(k)
        if isinstance(v, str) and v.strip():
            scrubbed = _scrub_collector_noise(v[:40_000])
            if scrubbed.strip():
                file_parts.append(scrubbed)
                cmd_parts.append(scrubbed)

    # journal / last：供 category=journal|log 规则命中（与 eventlog/linux_journal 互补）
    for ev in report.get("event_logs") or []:
        if isinstance(ev, dict):
            msg = str(ev.get("message") or "").strip()
            if msg:
                cmd_parts.append(msg[:800])
        elif isinstance(ev, str) and ev.strip():
            cmd_parts.append(ev[:800])

    return {
        "process": "\n".join(proc_parts)[:400_000],
        "network": "\n".join(net_parts)[:400_000],
        "command": _scrub_collector_noise("\n".join(cmd_parts + proc_parts)[:400_000]),
        "module": "\n".join(mod_parts)[:200_000],
        "file": _scrub_collector_noise("\n".join(file_parts + cmd_parts)[:200_000]),
        "port": " ".join(ports),
        "all": "",  # filled below
    }


def _run_pack_rules(report: Dict, store: RuleStore, findings: List[Finding], seen: Set[str]) -> int:
    packs = _linux_packs(store)
    rules = _iter_rules(packs)
    if not rules:
        return 0
    corpora = _build_corpora(report)
    corpora["all"] = "\n".join(corpora[k] for k in ("process", "network", "command", "module", "file"))[:600_000]

    hits = 0
    # 限制单次分析告警量，避免爆炸
    max_hits = 200
    # 语料预降小写一次；否则每条规则都对最大 600KB 的文本重算一遍
    corpora_low = {k: v.lower() for k, v in corpora.items()}
    for rule in rules:
        if hits >= max_hits:
            break
        if rule.get("heuristicOnly"):
            continue
        pattern = str(rule.get("pattern") or "")
        needles = rule.get("containsAny")
        mt = str(rule.get("match_type") or "contains")
        bucket = _cat_bucket(rule)
        text = corpora.get(bucket) or corpora["all"]
        ok = False
        if needles:
            low = corpora_low.get(bucket) or corpora_low["all"]
            ok = any(str(n) and str(n).lower() in low for n in needles)
        elif pattern:
            ok = _hit(text, pattern, mt)
        if not ok:
            continue
        sev = str(rule.get("severity") or "medium").lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        cat_map = {
            "process": "可疑进程",
            "network": "网络IOC",
            "command": "可疑命令",
            "module": "Rootkit线索",
            "file": "持久化",
            "port": "高危端口",
        }
        reason = str(rule.get("reason") or "")
        evidence, extra = _evidence_for_rule(
            report, text, pattern, mt, needles, reason, bucket=bucket,
        )
        if not evidence or (isinstance(extra, dict) and extra.get("fp_filtered")):
            continue
        hits += 1
        rule_cat = str(rule.get("category") or "").strip()
        known_cats = {
            "持久化", "启动项", "计划任务", "服务", "可疑命令", "Rootkit线索",
            "后门", "账户异常", "注入", "隐藏进程", "网络IOC", "高危端口", "可疑进程",
        }
        if rule_cat in known_cats:
            category = "持久化" if rule_cat in ("启动项", "服务", "计划任务") else rule_cat
        else:
            category = cat_map.get(bucket, rule_cat or "Linux规则")
        if not isinstance(extra, dict):
            extra = {}
        # 规则溯源：分析结果可引用 rule_id / pack / source
        if rule.get("pack"):
            extra.setdefault("pack", rule.get("pack"))
        if rule.get("source"):
            extra.setdefault("rule_source", rule.get("source"))
        if rule.get("tags"):
            extra.setdefault("tags", rule.get("tags"))
        if rule.get("reason"):
            extra.setdefault("reason", rule.get("reason"))
        extra.setdefault("rule_name", str(rule.get("name") or ""))
        _add(
            findings, seen,
            category=category,
            severity=sev,
            title=str(rule.get("name") or rule.get("id") or "linux_rule"),
            evidence=evidence,
            rule_id=str(rule.get("id") or "linux_text"),
            extra=extra,
        )
    return hits


def _rule_by_id(store: RuleStore, rule_id: str) -> Optional[Dict[str, Any]]:
    rid = str(rule_id or "").strip()
    if not rid:
        return None
    for rule in _iter_rules(_linux_packs(store)):
        if str(rule.get("id") or "") == rid:
            return rule
    return None


def _finding_evidence_weak(item: Dict[str, Any]) -> bool:
    """证据几乎等于标题/说明，缺少命中上下文。"""
    mid = str(item.get("matcher") or item.get("source") or "").lower()
    if "linux" not in mid and str(item.get("source") or "") != "linux_persistence":
        return False
    title = str(item.get("title") or item.get("name") or "").strip()
    reason = str(item.get("reason") or "").strip()
    raw = item.get("evidence")
    if isinstance(raw, list):
        lines = [str(x).strip() for x in raw if str(x or "").strip()]
    elif raw:
        lines = [ln.strip() for ln in str(raw).splitlines() if ln.strip()]
    else:
        lines = []
    if not lines:
        return True
    # 纯端口数字糊成一串 → 视为弱证据，触发补全
    if all(re.fullmatch(r"[\d\s./:]+", ln or "") for ln in lines):
        return True
    for ln in lines:
        if ln.startswith("[") or "→" in ln or "->" in ln:
            return False
        if ln.startswith("/") and ln != title:
            return False
    return all(ln == title or ln == reason or ln.startswith("匹配模式:") for ln in lines)


def enrich_linux_finding_items(report: Dict, items: List[Any], store: Optional[RuleStore] = None) -> List[Any]:
    """读取时补全旧 Linux 告警的命中证据（不改库，仅响应侧）。"""
    if not report or not items:
        return items
    try:
        from ..rules_loader import get_store
        st = store or get_store()
    except Exception:
        return items

    corpora = None
    out: List[Any] = []
    for it in items:
        if not isinstance(it, dict) or not _finding_evidence_weak(it):
            out.append(it)
            continue
        rule = _rule_by_id(st, str(it.get("rule_id") or ""))
        if not rule:
            # 无 rule_id 时仍尽量用标题当 pattern 搜不到；跳过
            out.append(it)
            continue
        pattern = str(rule.get("pattern") or "")
        needles = rule.get("containsAny")
        mt = str(rule.get("match_type") or "contains")
        reason = str(rule.get("reason") or it.get("title") or "")
        if corpora is None:
            corpora = _build_corpora(report)
            corpora["all"] = "\n".join(
                corpora[k] for k in ("process", "network", "command", "module", "file")
            )[:600_000]
        bucket = _cat_bucket(rule)
        text = corpora.get(bucket) or corpora["all"]
        evidence, extra = _evidence_for_rule(report, text, pattern, mt, needles, reason, bucket=bucket)
        lines = [ln.strip() for ln in str(evidence).splitlines() if ln.strip()]
        if not lines:
            out.append(it)
            continue
        fresh = dict(it)
        fresh["evidence"] = lines
        fresh["reason"] = lines[0]
        ex = dict(fresh.get("extra") or {}) if isinstance(fresh.get("extra"), dict) else {}
        ex.update(extra or {})
        fresh["extra"] = ex
        if ex.get("path") and not fresh.get("path"):
            fresh["path"] = ex["path"]
        out.append(fresh)
    return out


def _run_heuristics(report: Dict, findings: List[Finding], seen: Set[str], matched: List[Dict]) -> None:
    raw = report.get("linuxsc_raw") if isinstance(report.get("linuxsc_raw"), dict) else {}
    preload = str(raw.get("preload") or "").strip()
    se = report.get("security_extras") if isinstance(report.get("security_extras"), dict) else {}
    if not preload and isinstance(se.get("ld.so.preload"), str):
        preload = se.get("ld.so.preload") or ""

    if preload:
        _add(
            findings, seen,
            category="持久化", severity="critical",
            title="ld.so.preload 非空",
            evidence=f"/etc/ld.so.preload →\n{preload[:800]}",
            rule_id="linux_ld_preload",
        )
        matched.append({"id": "linux_ld_preload"})

    for t in report.get("scheduled_tasks") or []:
        if not isinstance(t, dict):
            continue
        name = str(t.get("task_name") or t.get("name") or "")
        cmd = str(t.get("command") or "")
        path = str(t.get("path") or "")
        # crontab 用 \r 把恶意载荷藏到 cat 不可见区域（需采集保留原始字节）
        if "\r" in cmd or "\x0d" in cmd:
            _add(
                findings, seen,
                category="持久化", severity="high",
                title="cron 任务含回车隐藏字符",
                evidence=f"{name}: {cmd[:500]!r}",
                rule_id="linux_cron_cr_hide",
            )
            matched.append({"id": "linux_cron_cr_hide"})
        if _SUS_CRON.search(cmd) or _SUS_PATH.search(cmd) or _SUS_PATH.search(path):
            _add(
                findings, seen,
                category="持久化", severity="high",
                title="可疑 cron/timer 任务",
                evidence=f"{name}: {cmd[:500]}",
                rule_id="linux_cron_sus",
            )
        elif name.endswith(".timer") and re.search(r"(tmp|shm|miner|xmr|kinsing|redis)", name, re.I):
            _add(
                findings, seen,
                category="持久化", severity="high",
                title="可疑 systemd timer 名称",
                evidence=f"{name}: {cmd}"[:500],
                rule_id="linux_timer_sus_name",
            )

    for u in report.get("users") or []:
        if not isinstance(u, dict):
            continue
        try:
            uid_val = u.get("uid")
            uid = int(uid_val) if uid_val is not None and str(uid_val).strip() != "" else -1
        except (TypeError, ValueError):
            continue
        uname = str(u.get("name") or u.get("username") or "").strip()
        if uid == 0 and uname and uname.lower() != "root":
            _add(
                findings, seen,
                category="账户异常", severity="critical",
                title="非 root 账户 UID 为 0",
                evidence=f"{uname}: uid={uid} home={u.get('home') or ''} shell={u.get('shell') or ''}",
                rule_id="linux_uid0_duplicate",
            )
            matched.append({"id": "linux_uid0_duplicate"})

    for s in report.get("services") or []:
        if not isinstance(s, dict):
            continue
        blob = " ".join(str(s.get(k) or "") for k in (
            "name", "description", "path", "command", "status", "fragment_path",
        ))
        path = str(s.get("path") or s.get("command") or "")
        if _SUS_UNIT.search(blob) or _SUS_PATH.search(path):
            _add(
                findings, seen,
                category="持久化", severity="high",
                title="可疑 systemd 单元",
                evidence=blob[:600],
                rule_id="linux_systemd_sus",
            )
        elif path.startswith("/") and _SUS_PATH.search(path) and s.get("signed") is not True:
            _add(
                findings, seen,
                category="持久化", severity="medium",
                title="systemd 单元路径异常且无包签名",
                evidence=blob[:600],
                rule_id="linux_systemd_unsigned_path",
            )

    for si in report.get("startup_items") or []:
        if not isinstance(si, dict):
            continue
        loc = str(si.get("location") or si.get("name") or "")
        cmd = str(si.get("command") or "")
        path = str(si.get("path") or "")
        blob = f"{loc} {si.get('name') or ''} {path} {cmd}"
        if "ld.so.preload" in loc.lower() and cmd and cmd != "(empty)":
            continue
        if re.search(r"bashrc|\.profile|bash_profile|bash_login|bash_logout|zshrc|zprofile|zshenv|shell_rc", loc + " " + path, re.I):
            if _SUS_CRON.search(cmd) or _SUS_CRON.search(path):
                _add(
                    findings, seen,
                    category="持久化", severity="high",
                    title="bashrc/profile 含可疑命令",
                    evidence=blob[:500],
                    rule_id="linux_startup_bashrc_sus",
                )
                matched.append({"id": "linux_startup_bashrc_sus"})
        if _SUS_CRON.search(cmd) or _SUS_CRON.search(path) or _SUS_PATH.search(path) or _SUS_PATH.search(cmd):
            _add(
                findings, seen,
                category="持久化", severity="medium",
                title="可疑启动项",
                evidence=blob[:500],
                rule_id="linux_startup_sus",
            )

    remote = report.get("remote_access") if isinstance(report.get("remote_access"), dict) else {}
    sshd_cfg = str(remote.get("sshd_config") or "")
    if re.search(r"(?im)^\s*PermitRootLogin\s+yes\b", sshd_cfg):
        _add(
            findings, seen,
            category="账户异常", severity="high",
            title="sshd 允许 root 远程登录",
            evidence="PermitRootLogin yes\n" + sshd_cfg[:600],
            rule_id="linux_sshd_permit_root_yes",
        )
        matched.append({"id": "linux_sshd_permit_root_yes"})

    for key in remote.get("ssh_keys") or []:
        if not isinstance(key, dict):
            continue
        n = int(key.get("count") or 0)
        preview = str(key.get("preview") or "")
        if n >= 5:
            _add(
                findings, seen,
                category="账户异常", severity="medium",
                title="authorized_keys 条目偏多",
                evidence=f"{key.get('path')}: {n} keys\n{preview[:400]}",
                rule_id="linux_ssh_keys_many",
            )
        if re.search(r"(from=\*|command=.*curl|command=.*wget)", preview, re.I):
            _add(
                findings, seen,
                category="账户异常", severity="high",
                title="authorized_keys 含可疑限制/命令",
                evidence=f"{key.get('path')}\n{preview[:500]}",
                rule_id="linux_ssh_keys_sus",
            )

    deleted = str(raw.get("deleted_exe") or "")
    if deleted.strip() and len(deleted.strip()) > 10:
        _add(
            findings, seen,
            category="隐藏进程", severity="high",
            title="检测到 (deleted) 可执行映射",
            evidence=deleted[:800],
            rule_id="linux_deleted_exe",
        )
        if re.search(r"memfd:", deleted, re.I):
            _add(
                findings, seen,
                category="隐藏进程", severity="critical",
                title="检测到 memfd 匿名内存可执行",
                evidence=deleted[:800],
                rule_id="linux_memfd_deleted",
            )
            matched.append({"id": "linux_memfd_deleted"})

    environ_ld = str(raw.get("environ_ld") or "")
    if "LD_PRELOAD" in environ_ld:
        _add(
            findings, seen,
            category="注入", severity="high",
            title="进程环境含 LD_PRELOAD",
            evidence=environ_ld[:800],
            rule_id="linux_env_ld_preload",
        )

    mod_diff = str(se.get("module_source_diff") or se.get("module_source_diff.txt") or "")
    if mod_diff.strip() and _module_diff_indicates_hidden_lkm(mod_diff):
        _add(
            findings, seen,
            category="Rootkit线索", severity="high",
            title="疑似隐藏内核模块（sysfs live ∉ /proc/modules）",
            evidence=mod_diff[:1200],
            rule_id="linux_module_diff",
        )

    packet = str(se.get("proc_stack_packet_recvmsg.txt") or "")
    if packet.strip() and "packet_recvmsg" in packet:
        _add(
            findings, seen,
            category="Rootkit线索", severity="critical",
            title="进程栈出现 packet_recvmsg",
            evidence=packet[:800],
            rule_id="linux_packet_recvmsg",
        )

    # —— 对照 OpenSSH/PAM/软链/Wrapper 公开手法的结构化检测 ——
    _heur_ssh_symlink_runtime(report, findings, seen, matched)
    _heur_security_hunt_hits(se, findings, seen, matched)
    _heur_sshd_wrapper(se, findings, seen, matched)
    _heur_prompt_command(se, report, findings, seen, matched)
    _heur_account_extras(se, findings, seen, matched)
    _heur_sshd_bin_and_pkg(se, findings, seen, matched)
    _heur_suid_and_sudoers(se, raw, findings, seen, matched)
    _heur_loaded_unsigned_so(report, findings, seen, matched)


_DANGEROUS_SUID_BASENAME = re.compile(
    r"(?i)^(?:bash|dash|sh|csh|tcsh|zsh|ksh|fish|find|env|python(?:\d+(?:\.\d+)?)?|"
    r"perl|ruby|php(?:\d+(?:\.\d+)?)?|lua|node|nodejs|busybox|vim|nvim|nano|"
    r"less|more|man|awk|gawk|nmap|tcpdump|strace|gdb|rsync|scp|sftp|"
    r"docker|podman|nice|ionice|taskset|stdbuf|timeout|xargs|expect|"
    r"script|screen|tmux|socat|ash)\b"
)


def _heur_suid_and_sudoers(
    se: Dict[str, Any],
    raw: Dict[str, Any],
    findings: List[Finding],
    seen: Set[str],
    matched: List[Dict],
) -> None:
    """危险 SUID 解释器 / sudoers NOPASSWD:ALL（blogs 提权清单收紧版）。"""
    suid_blob = str(se.get("suid_sgid_files") or raw.get("suid_sgid") or "")
    hits: List[str] = []
    for ln in suid_blob.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        # 行可能是纯路径，或 ls -l 风格；取末段 basename
        path = s.split()[-1] if " " in s and s[0] in "-dltc" else s
        path = path.replace("\\", "/")
        base = path.rsplit("/", 1)[-1]
        if not _DANGEROUS_SUID_BASENAME.match(base):
            continue
        # 常见合法 SUID：pass 掉 mount/su/sudo/ping 等（不在危险名单）
        hits.append(path[:240])
        if len(hits) >= 30:
            break
    if hits:
        _add(
            findings, seen,
            category="权限提升", severity="high",
            title="危险 SUID/SGID 解释器或提权工具",
            evidence="\n".join(hits),
            rule_id="linux_suid_dangerous_bin",
            extra={"count": len(hits)},
        )
        matched.append({"id": "linux_suid_dangerous_bin"})

    sudo_blob = str(
        se.get("sudoers")
        or se.get("sudoers_d")
        or raw.get("sudoers")
        or ""
    )
    if not sudo_blob.strip():
        return
    nopass_hits: List[str] = []
    for ln in sudo_blob.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if re.search(
            r"(?i)\bALL\s*=\s*\(\s*ALL(?:\s*:\s*ALL)?\s*\)\s+NOPASSWD\s*:\s*ALL\b",
            s,
        ) or re.search(
            r"(?i)NOPASSWD\s*:\s*/usr/bin/\*\s*,\s*/usr/sbin/\*",
            s,
        ):
            nopass_hits.append(s[:240])
        elif re.search(r"(?i)Defaults\s+timestamp_timeout\s*=\s*-1", s) or re.search(
            r"(?i)Defaults(?:\s*:?\S*)?\s+!authenticate",
            s,
        ):
            nopass_hits.append(s[:240])
    if nopass_hits:
        _add(
            findings, seen,
            category="权限提升", severity="high",
            title="sudoers 过度授权(NOPASSWD:ALL/永久缓存)",
            evidence="\n".join(nopass_hits[:20]),
            rule_id="linux_sudoers_overbroad",
        )
        matched.append({"id": "linux_sudoers_overbroad"})


def _is_so_module_path(path: str) -> bool:
    """路径是否像动态库（含 libfoo.so.1.2、(deleted) 后缀）。"""
    p = str(path or "").strip()
    if not p:
        return False
    # 去掉 maps 的 (deleted) 再取 basename
    bare = re.sub(r"\s*\(deleted\)\s*$", "", p, flags=re.I).strip()
    base = bare.rsplit("/", 1)[-1]
    return bool(re.search(r"(?i)\.so(?:\.[0-9]+)*$", base) or re.search(r"(?i)\.so\b", base))


_UNSIGNED_SO_SKIP_PREFIX = (
    "/snap/",
    "/var/lib/flatpak/",
    "/var/lib/docker/",
    "/var/lib/containers/",
    "/run/",
    "/usr/lib/modules/",
    "/usr/src/",
    "/usr/lib/debug/",
)
_UNSIGNED_SO_SKIP_SUBSTR = (
    "/site-packages/",
    "/dist-packages/",
    "/node_modules/",
    "/.venv/",
    "/venv/",
    "/virtualenvs/",
    "/.local/lib/",
    "/.local/share/",
    "/opt/google/",
    "/opt/microsoft/",
)


def _unsigned_so_risk(path: str) -> Optional[str]:
    """仅高风险落点返回 'high'，其余返回 None（避免 /opt、pip、本地编译误报）。"""
    p = str(path or "").replace("\\", "/").strip()
    if not p or not _is_so_module_path(p):
        return None
    pl = p.lower()
    if any(pl.startswith(x) for x in _UNSIGNED_SO_SKIP_PREFIX):
        return None
    if any(x in pl for x in _UNSIGNED_SO_SKIP_SUBSTR):
        return None
    if "(deleted)" in pl:
        return "high"
    if re.search(r"(?i)^/(?:tmp|var/tmp|dev/shm)/", p):
        return "high"
    # 家目录隐藏路径/隐藏文件（.cache/.config/.x.so），排除已在 skip 的 .local/lib
    if re.search(r"(?i)^/(?:home/[^/]+|root)/", p) and re.search(r"/\.[^/]+(/|$)", p):
        return "high"
    # 系统库目录无包归属 → 常见 rootkit 落点（ebury 等）
    if re.search(r"(?i)^/(?:usr/)?lib(?:64)?/", p) and "/python" not in pl:
        return "high"
    return None


def _module_is_unsigned(m: Dict[str, Any]) -> bool:
    st = str(m.get("sig_status") or "").strip().lower()
    if m.get("signed") is True or st in ("signed", "n/a"):
        return False
    if st == "unsigned" or m.get("signed") is False:
        return True
    # unchecked：仅在高风险路径仍纳入（tmp 等本就不会有包）
    return st in ("", "unchecked", "unknown")


def _hash_index_from_report(report: Dict) -> Dict[str, Dict[str, str]]:
    """path → {md5,sha256,size}；来自 Hunt 清单 / file_scans / 模块字段。"""
    out: Dict[str, Dict[str, str]] = {}

    def put(path: str, *, md5: str = "", sha256: str = "", size: str = "") -> None:
        p = re.sub(r"\s*\(deleted\)\s*$", "", str(path or "").strip(), flags=re.I)
        if not p.startswith("/"):
            return
        cur = out.setdefault(p, {})
        if md5 and not cur.get("md5"):
            cur["md5"] = md5.lower()
        if sha256 and not cur.get("sha256"):
            cur["sha256"] = sha256.lower()
        if size and not cur.get("size"):
            cur["size"] = str(size)

    se = report.get("security_extras") if isinstance(report.get("security_extras"), dict) else {}
    hunt = str(se.get("loaded_unsigned_so") or "")
    for ln in hunt.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split("\t")
        if len(parts) >= 3 and parts[0].startswith("/"):
            put(parts[0], md5=parts[1].strip(), sha256=parts[2].strip(),
                size=(parts[3].strip() if len(parts) > 3 else ""))
            continue
        # 旧格式纯路径
        if s.startswith("/"):
            put(s)

    for fs in report.get("file_scans") or []:
        if not isinstance(fs, dict):
            continue
        fp = str(fs.get("full_path") or fs.get("path") or "")
        put(
            fp,
            md5=str(fs.get("md5") or ""),
            sha256=str(fs.get("sha256") or ""),
            size=str(fs.get("size") or ""),
        )

    for p in report.get("processes") or []:
        if not isinstance(p, dict):
            continue
        for m in p.get("modules") or []:
            if not isinstance(m, dict):
                continue
            put(
                str(m.get("path") or ""),
                md5=str(m.get("md5") or ""),
                sha256=str(m.get("sha256") or m.get("hash") or ""),
                size=str(m.get("size") or ""),
            )
    return out


def _heur_loaded_unsigned_so(
    report: Dict,
    findings: List[Finding],
    seen: Set[str],
    matched: List[Dict],
) -> None:
    """进程 maps 已加载 .so：无 rpm/dpkg 归属（Linux「未签名」）且落点高风险 → 列举。"""
    hash_idx = _hash_index_from_report(report)
    # path → [(pid, proc_name), ...]
    by_path: Dict[str, List[str]] = {}
    for p in report.get("processes") or []:
        if not isinstance(p, dict):
            continue
        pid = p.get("pid") or "?"
        pname = str(p.get("name") or p.get("comm") or "").strip()[:80]
        ppath = str(p.get("path") or p.get("exe") or "").strip()[:200]
        for m in p.get("modules") or []:
            if not isinstance(m, dict):
                continue
            path = str(m.get("path") or "").strip()
            if not path or not _is_so_module_path(path):
                continue
            if not _module_is_unsigned(m):
                continue
            if _unsigned_so_risk(path) != "high":
                continue
            # 进程名有时是哈希串（样本以 sha256 命名），勿与 pid 混淆
            bits = [f"pid={pid}"]
            if pname:
                bits.append(f"name={pname}")
            if ppath and ppath != pname:
                bits.append(f"exe={ppath}")
            tag = " ".join(bits)
            lst = by_path.setdefault(path, [])
            if tag not in lst and len(lst) < 8:
                lst.append(tag)

    if not by_path:
        return

    lines: List[str] = []
    paths_out: List[str] = []
    files_meta: List[Dict[str, str]] = []
    for path in sorted(by_path.keys())[:80]:
        bare = re.sub(r"\s*\(deleted\)\s*$", "", path, flags=re.I).strip()
        h = hash_idx.get(bare) or hash_idx.get(path) or {}
        md5 = h.get("md5") or ""
        sha = h.get("sha256") or ""
        hash_bits = []
        if md5:
            hash_bits.append(f"md5={md5}")
        if sha:
            hash_bits.append(f"sha256={sha}")
        if not hash_bits:
            if "(deleted)" in path.lower():
                hash_bits.append("hash=(unavailable:deleted，map_files未取到；进程存活时用 LinuxSC≥1.39 重采)")
            else:
                hash_bits.append("hash=(none)")
        procs = ", ".join(by_path[path][:4])
        lines.append(f"{path}  {' '.join(hash_bits)}  ←  {procs}")
        paths_out.append(path)
        # 解析首个关联进程，便于前端表格直接用 extra.files
        pid0 = pname0 = ppath0 = ""
        if by_path[path]:
            m_pid = re.search(r"\bpid=(\S+)", by_path[path][0])
            m_name = re.search(r"\bname=(\S+)", by_path[path][0])
            m_exe = re.search(r"\bexe=(\S+)", by_path[path][0])
            pid0 = m_pid.group(1) if m_pid else ""
            pname0 = m_name.group(1) if m_name else ""
            ppath0 = m_exe.group(1) if m_exe else ""
        files_meta.append({
            "path": path,
            "md5": md5,
            "sha256": sha,
            "size": h.get("size") or "",
            "deleted": "(deleted)" in path.lower(),
            "pid": pid0,
            "process": pname0,
            "exe": ppath0,
            "hash_note": "" if (md5 or sha) else (
                "unavailable:deleted，需 LinuxSC≥1.36 map_files 重采"
                if "(deleted)" in path.lower() else "none"
            ),
        })

    _add(
        findings, seen,
        category="注入",
        severity="high",
        title="已加载未签名(无包归属) .so",
        evidence=(
            f"共 {len(by_path)} 个唯一路径（仅 tmp/shm/家目录隐藏路径/系统库孤儿/(deleted)）\n"
            + "\n".join(lines)
        ),
        rule_id="linux_loaded_unsigned_so",
        extra={"paths": paths_out, "count": len(by_path), "files": files_meta},
        evidence_limit=4500,
    )
    matched.append({"id": "linux_loaded_unsigned_so", "count": len(by_path)})


def _proc_exe_blob(p: Dict[str, Any]) -> str:
    return " ".join(str(p.get(k) or "") for k in (
        "name", "comm", "cmdline", "command", "path", "exe", "cwd",
    ))


def _listen_ports(report: Dict) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in report.get("open_ports") or report.get("listening_ports") or []:
        if isinstance(c, dict):
            out.append(c)
        else:
            out.append({"local_port": str(c), "port": str(c)})
    for c in report.get("established_connections") or []:
        if not isinstance(c, dict):
            continue
        st = str(c.get("state") or "").upper()
        if st in ("LISTEN", "LISTENING"):
            out.append(c)
    return out


def _heur_ssh_symlink_runtime(
    report: Dict,
    findings: List[Finding],
    seen: Set[str],
    matched: List[Dict],
) -> None:
    """非 22 监听 + 伪装进程/-oPort/临时路径（不含正常 sshd 端口转发与 X11）。"""
    hits: List[str] = []
    for p in report.get("processes") or []:
        if not isinstance(p, dict):
            continue
        blob = _proc_exe_blob(p)
        if not re.search(r"(?i)sshd|/usr/s?bin/sshd", blob):
            continue
        if re.search(r"(?i)-oPort\s*=\s*(?!22\b)\d+", blob):
            hits.append(f"[进程] {blob[:400]}")
            continue
        # 软链到临时名：path/exe 不在标准 sshd 路径，但 cmdline/name 含 sshd 或反向
        path = str(p.get("path") or p.get("exe") or "")
        name = str(p.get("name") or p.get("comm") or "").strip()
        name_l = name.lower().rstrip(":")
        if re.search(r"(?i)/(tmp|var/tmp|dev/shm)/", path) and re.search(r"(?i)sshd", blob):
            hits.append(f"[进程临时路径] {blob[:400]}")
        elif (
            name
            and name_l not in ("sshd", "sshd-session", "sshd-session:")
            and not name_l.startswith("sshd")
            and re.search(r"(?i)/usr/s?bin/sshd\b", path)
        ):
            # 进程名伪装(su/java)但 exe 仍是 sshd
            hits.append(f"[进程名伪装] name={name} → {path[:200]} | {blob[:200]}")

    for lp in _listen_ports(report):
        port = str(lp.get("local_port") or lp.get("port") or "").strip()
        if not port or port == "22":
            continue
        try:
            port_n = int(re.sub(r"\D", "", port) or "0")
        except ValueError:
            port_n = 0
        # X11 转发常用 6000+display
        if 6000 <= port_n <= 6063:
            continue
        proc = str(lp.get("process") or lp.get("name") or lp.get("process_name") or "")
        # 正常 sshd / sshd-session 在非 22 上监听多为转发，单独不算软链后门
        if re.search(r"(?i)\b(sshd-session|sshd)\b", proc) and not re.search(
            r"(?i)\b(su|java|postgres|oracle|mysql|nginx|httpd)\b", proc
        ):
            continue
        if re.search(r"(?i)\b(su|java|postgres|oracle|mysql)\b.*pid", proc):
            # ss 常显示 users:(("su",pid=..)) 而实际为 sshd 软链
            hits.append(f"[监听] :{port} {proc[:300]}")

    # 去重截断
    uniq: List[str] = []
    seen_l: Set[str] = set()
    for h in hits:
        if h in seen_l:
            continue
        seen_l.add(h)
        uniq.append(h)
    if not uniq:
        return
    _add(
        findings, seen,
        category="后门", severity="critical",
        title="疑似 SSH 软链接后门(非22端口/伪装进程)",
        evidence="\n".join(uniq[:12]),
        rule_id="linux_ssh_symlink_runtime",
        extra={"kind": "ssh_symlink", "count": len(uniq)},
    )
    matched.append({"id": "linux_ssh_symlink_runtime", "n": len(uniq)})


def _heur_security_hunt_hits(
    se: Dict[str, Any],
    findings: List[Finding],
    seen: Set[str],
    matched: List[Dict],
) -> None:
    """LinuxSC Hunt 已有结果但此前未自动告警。"""
    mapping = (
        ("ssh_symlink_backdoor", "后门", "critical", "Hunt: SSH 软链接/sshd 路径异常"),
        ("ssh_symlink_find", "后门", "critical", "Hunt: 发现指向 sshd 的软链/非标 exe"),
        ("webshell_hits", "后门", "high", "Hunt: 检出 WebShell 特征"),
        ("hacker_tools", "可疑进程", "high", "Hunt: 检出黑客工具特征"),
        ("miner_procs", "可疑进程", "high", "Hunt: 检出挖矿相关进程"),
        ("inetd_xinetd", "后门", "high", "Hunt: inetd/xinetd 可疑配置"),
        ("pam_d_extra", "后门", "high", "Hunt: 异常 pam.d 服务名(软链后门配套)"),
        ("cred_drop_paths", "后门", "critical", "Hunt: 凭据落盘路径命中"),
        ("path_hijack", "后门", "medium", "Hunt: profile PATH 抢占痕迹"),
        ("vimrc_shell", "后门", "high", "Hunt: vimrc :silent ! 执行 shell"),
        ("ld_library_path", "后门", "high", "Hunt: LD_LIBRARY_PATH 指向可写目录"),
        ("authorized_keys_file", "后门", "high", "Hunt: AuthorizedKeysFile 非默认路径"),
        ("systemd_sus_exec", "持久化", "critical", "Hunt: systemd 可疑 ExecStart"),
        ("fake_binaries", "后门", "high", "Hunt: su/login 等关键命令异常"),
    )
    for key, cat, sev, title in mapping:
        text = str(se.get(key) or "").strip()
        if not text or len(text) < 8:
            continue
        low = text.lower()
        if low in ("true", "false", "none", "n/a"):
            continue
        if key == "inetd_xinetd":
            if not re.search(r"(?i)server\s*=\s*/bin/(?:ba)?sh|stream\s+tcp\s+nowait.*/bin/(?:ba)?sh|EXTRA_", text):
                continue
        if key == "pam_d_extra":
            if "EXTRA_PAM_D" not in text and "SAME_AS_PAM_D_SU" not in text:
                continue
        if key == "cred_drop_paths":
            if not re.search(r"(?i)\bHIT\s+/|\.sshlog|sshwd|\.ILOG|sshd\.mm", text):
                continue
        if key == "path_hijack":
            # 旧逻辑把「--- suspicious_prepend ---」标题本身也当命中，
            # 且 PATH="$HOME/bin:$PATH"（Ubuntu 默认）匹配 home/ → 大量误报。
            # 仅当 PATH 前插 /tmp|/var/tmp|/dev/shm 或家目录隐藏路径时告警。
            hits: List[str] = []
            for ln in text.splitlines():
                s = ln.strip()
                if not s or s.startswith("---") or s.startswith("#"):
                    continue
                if re.search(
                    r"(?i)\$HOME/(?:bin|\.local/bin)|/\$HOME/(?:bin|\.local/bin)|"
                    r"snap_bin_path|/snap/bin|apps-bin-path",
                    s,
                ):
                    continue
                if re.search(
                    r"(?i)PATH\s*=.*(/(?:tmp|var/tmp|dev/shm)(?:/|:|\"|'|\s|$))",
                    s,
                ):
                    hits.append(s)
                    continue
                # 家目录下隐藏目录插 PATH 前（非 bin/.local/bin）
                if re.search(
                    r"(?i)PATH\s*=.*(?:\$HOME|home/[^/:=\s]+)/\.[^/:=\s]+",
                    s,
                ) and not re.search(r"(?i)\.local/bin", s):
                    hits.append(s)
            if not hits:
                continue
            text = "\n".join(hits[:40])
        if key == "vimrc_shell":
            if not re.search(r"(?i)silent\s+!|:!.*(?:bash|sh|curl|wget|nc|python|perl)", text):
                continue
        if key == "ld_library_path":
            hits_ld: List[str] = []
            for ln in text.splitlines():
                s = ln.strip()
                if not s or s.startswith("---") or s.startswith("#"):
                    continue
                if re.search(
                    r"(?i)LD_LIBRARY_PATH\s*=.*(/(?:tmp|var/tmp|dev/shm|home/)[^:\s\"']*)",
                    s,
                ):
                    hits_ld.append(s)
            if not hits_ld:
                continue
            text = "\n".join(hits_ld[:40])
        if key == "authorized_keys_file":
            hits_ak: List[str] = []
            for ln in text.splitlines():
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                if not re.search(r"(?i)authorizedkeysfile", s):
                    continue
                if re.search(r"(?i)authorizedkeysfile\s+\.ssh/authorized_keys\b", s):
                    continue
                if re.search(
                    r"(?i)authorizedkeysfile\s+(?:\.cache\b|/tmp/|/var/tmp/|/dev/shm/|\.config/|/var/lib/|/opt/)",
                    s,
                ):
                    hits_ak.append(s)
            if not hits_ak:
                continue
            text = "\n".join(hits_ak[:20])
        if key == "systemd_sus_exec":
            if not re.search(r"(?i)ExecStart=", text):
                continue
        if key == "fake_binaries":
            if not (
                re.search(r"(?i)(script text|ASCII text|Perl script|Python script)", text)
                or re.search(r"(?m)^\s*[.SM5sm?]{8,}\s+\S+", text)
                or re.search(r"(?i)\b(FAILED|missing|not installed)\b", text)
            ):
                continue
        if key == "ssh_symlink_find":
            interesting: List[str] = []
            for ln in text.splitlines():
                s = ln.strip()
                if not s or s.startswith("==="):
                    continue
                if "->" in s and re.search(r"(?i)sshd", s):
                    interesting.append(s)
                    continue
                if not re.search(r"pid=\d+", s):
                    continue
                # 正常 sshd 主监听进程
                if re.search(r"(?i)exe=/usr/(?:s)?bin/sshd\b", s) and re.search(
                    r"(?i)(\[listener\]|sshd\s+-D\b|sshd:\s*/usr)", s
                ):
                    continue
                if re.search(r"(?i)exe=/(?:tmp|var/tmp|dev/shm)/\S+", s) and re.search(
                    r"(?i)sshd|-oPort=", s
                ):
                    interesting.append(s)
                elif re.search(r"(?i)-oPort=", s):
                    interesting.append(s)
                elif re.search(r"(?i)exe=\S*sshd", s) and not re.search(
                    r"(?i)exe=/usr/(?:s)?bin/sshd\b", s
                ):
                    interesting.append(s)
                elif re.search(r"(?i)\bname=(?!sshd\b)\S+", s) and re.search(
                    r"(?i)exe=/usr/(?:s)?bin/sshd\b", s
                ):
                    interesting.append(s)
            if not interesting:
                continue
            text = "\n".join(interesting[:40])
        if key == "ssh_symlink_backdoor":
            # 正常 ls/readlink 系统 sshd 不算；需异常软链或非 ELF/脚本
            if not re.search(r"(?i)(->|script|ASCII text|NOT ELF|broken symbolic)", text):
                continue
            if "->" in text and not re.search(
                r"(?i)/(?:tmp|var/tmp|dev/shm|home|opt)/\S*\s*->\s*.*sshd|"
                r"(?i)\S+\s*->\s*/(?:tmp|var/tmp|dev/shm)/|"
                r"(?i)(script|ASCII text|NOT ELF|broken)",
                text,
            ):
                if not re.search(r"(?i)(script|ASCII text|NOT ELF|broken)", text):
                    continue
        if re.match(r"(?is)^\s*(ls:|total\s+\d+|cannot|not found)", text):
            if key == "ssh_symlink_backdoor":
                if "->" not in text and not re.search(r"(?i)tmp/|not a|script", text):
                    continue
            else:
                continue
        # Hunt 文本也可能吸入采集脚本自描述
        text = _scrub_collector_noise(text)
        if not text.strip() or len(text) < 8:
            continue
        _add(
            findings, seen,
            category=cat, severity=sev,
            title=title,
            evidence=text[:900],
            rule_id=f"linux_hunt_{key}",
            extra={"hunt_key": key},
        )
        matched.append({"id": f"linux_hunt_{key}"})


def _heur_sshd_wrapper(
    se: Dict[str, Any],
    findings: List[Finding],
    seen: Set[str],
    matched: List[Dict],
) -> None:
    """file sshd 非 ELF / 脚本包装。"""
    text = str(se.get("sshd_wrapper") or "").strip()
    if not text:
        return
    if re.search(r"(?i)(POSIX shell|Bourne|Perl script|Python script|ASCII text|script)", text) \
            and not re.search(r"(?i)ELF\s+\d+-bit", text):
        _add(
            findings, seen,
            category="后门", severity="critical",
            title="sshd 非 ELF(疑似 SSH Wrapper 后门)",
            evidence=text[:800],
            rule_id="linux_sshd_wrapper_not_elf",
        )
        matched.append({"id": "linux_sshd_wrapper_not_elf"})


def _heur_prompt_command(
    se: Dict[str, Any],
    report: Dict,
    findings: List[Finding],
    seen: Set[str],
    matched: List[Dict],
) -> None:
    blobs = [
        _scrub_collector_noise(str(se.get("prompt_command") or "")),
        _scrub_collector_noise(str(se.get("alias") or "")),
    ]
    raw = report.get("linuxsc_raw") if isinstance(report.get("linuxsc_raw"), dict) else {}
    blobs.append(_scrub_collector_noise(str(raw.get("environ_ld") or "")[:20_000]))
    text = "\n".join(b for b in blobs if b).strip()
    if not text:
        return
    if re.search(
        r"(?i)PROMPT_COMMAND\s*=.*(?:ln\s+-sf.*/sshd|-oPort=|/dev/tcp/|curl\s|wget\s|nc\s|bash\s+-i)",
        text,
    ):
        _add(
            findings, seen,
            category="后门", severity="high",
            title="PROMPT_COMMAND 含可疑持久化命令",
            evidence=text[:900],
            rule_id="linux_prompt_command_sus",
        )
        matched.append({"id": "linux_prompt_command_sus"})


def _heur_account_extras(
    se: Dict[str, Any],
    findings: List[Finding],
    seen: Set[str],
    matched: List[Dict],
) -> None:
    """空口令用户名 / UID0 摘要（仅用户名，不含哈希）。"""
    empty_txt = str(se.get("empty_password_users") or "")
    empty_users = [
        ln.strip()
        for ln in empty_txt.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if empty_users:
        _add(
            findings, seen,
            category="账户异常", severity="critical",
            title="存在空口令账户(仅用户名)",
            evidence="\n".join(empty_users[:40]),
            rule_id="linux_empty_password_users",
            extra={"count": len(empty_users)},
        )
        matched.append({"id": "linux_empty_password_users", "n": len(empty_users)})

    uid0_txt = str(se.get("uid0_accounts") or "")
    extras = []
    for ln in uid0_txt.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        name = ln.split(":", 1)[0].strip()
        if name and name.lower() != "root":
            extras.append(ln)
    if extras:
        _add(
            findings, seen,
            category="账户异常", severity="critical",
            title="passwd 中存在非 root 的 UID0 账户",
            evidence="\n".join(extras[:40]),
            rule_id="linux_uid0_accounts_file",
            extra={"count": len(extras)},
        )
        matched.append({"id": "linux_uid0_accounts_file", "n": len(extras)})


def _heur_sshd_bin_and_pkg(
    se: Dict[str, Any],
    findings: List[Finding],
    seen: Set[str],
    matched: List[Dict],
) -> None:
    """sshd strings IOC + openssh/pam 包校验异常。"""
    meta = str(se.get("sshd_bin_meta") or "")
    if re.search(r"(?i)SECRETPW|sshbd|hackers|/tmp/\.sshlog|ILOG", meta):
        # 过滤掉标题行噪声：必须出现在 strings_ioc 段或独立命中行
        ioc_lines = [
            ln for ln in meta.splitlines()
            if re.search(r"(?i)SECRETPW|sshbd|hackers|/tmp/\.sshlog|\bILOG\b", ln)
        ]
        if ioc_lines or re.search(r"(?i)strings_ioc[\s\S]{0,200}(?:SECRETPW|sshbd|hackers)", meta):
            _add(
                findings, seen,
                category="后门", severity="critical",
                title="sshd 二进制含后门特征字符串",
                evidence=(ioc_lines and "\n".join(ioc_lines[:20]) or meta[:900]),
                rule_id="linux_sshd_strings_ioc",
            )
            matched.append({"id": "linux_sshd_strings_ioc"})

    pam = str(se.get("pam_security_sos") or "")
    if re.search(r"(?i)SECRETPW|hackers|/tmp/\.sshlog", pam):
        _add(
            findings, seen,
            category="后门", severity="critical",
            title="pam_unix.so strings 含后门特征",
            evidence=pam[:900],
            rule_id="linux_pam_strings_ioc",
        )
        matched.append({"id": "linux_pam_strings_ioc"})

    rpm = str(se.get("rpm_va_keypkgs") or se.get("rpm_Va_keypkgs") or "")
    if rpm.strip() and re.search(r"(?i)openssh|pam|/usr/sbin/sshd|pam_unix", rpm):
        # rpm -V 有输出即表示校验差异；debsums 失败行也算
        if re.search(r"(?m)^\s*[.SM5smUPGT?]{8,}\s+\S+", rpm) or re.search(
            r"(?i)FAILED|missing|缺失|modified|changed", rpm
        ):
            _add(
                findings, seen,
                category="Rootkit线索", severity="high",
                title="openssh/pam 关键包文件校验异常",
                evidence=rpm[:900],
                rule_id="linux_rpm_va_keypkgs",
            )
            matched.append({"id": "linux_rpm_va_keypkgs"})


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    matched: List[Dict[str, Any]] = []
    try:
        from ..linux_sc_import import enrich_linux_startups
        report = enrich_linux_startups(report)
    except Exception:
        pass
    _run_heuristics(report, findings, seen, matched)
    pack_hits = _run_pack_rules(report, store, findings, seen)
    return findings, {
        "matched": matched,
        "count": len(findings),
        "pack_hits": pack_hits,
        "linux_packs": len(_linux_packs(store)),
    }
