"""分析管线：入库瘦身 → 多规则匹配 → 聚合定级 →（可选）AI → 时间线"""
from __future__ import annotations
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .models import Finding, empty_analysis, summarize
from .ingest import slim_report
from .rules_loader import RuleStore, get_store
from .aggregate import aggregate_findings
from .matchers import (
    files, ioc, network, keywords, wininfosc, persistence, windows_process,
    artifacts, browsers, aux_rules, eventlog, linux_persistence,
    driver as driver_matcher, ransom as ransom_matcher,
    remote_tools as remote_tools_matcher,
    lateral as lateral_matcher, cred_theft as cred_theft_matcher,
    beacon as beacon_matcher, defense_weaken as defense_weaken_matcher,
    exfil as exfil_matcher,
)
from .platform import build_timeline
from .os_detect import detect_os_family


class JobCancelled(Exception):
    """任务已取消，匹配中止。"""


# 可并行组（各自独立 seen，最后合并去重）
PARALLEL_MATCHERS = [
    ("files", files.run, ["rules-files.json"]),
    ("ioc", ioc.run, ["rules-ioc.json"]),
    ("network", network.run, []),
    ("keywords", keywords.run, ["rules-keywords.json"]),
    ("wininfosc", wininfosc.run, ["rules-wininfosc.json"]),
    ("remote_tools", remote_tools_matcher.run, []),  # rules/remote_tools.json，自管远控档案
    ("lateral", lateral_matcher.run, []),
    ("cred_theft", cred_theft_matcher.run, []),
    ("beacon", beacon_matcher.run, []),
    ("defense_weaken", defense_weaken_matcher.run, []),
    ("exfil", exfil_matcher.run, []),
    ("persistence", persistence.run, ["rules-windows-system.json", "rules-high-risk.json", "rules-windows-apt-persist.json"]),
    ("driver", driver_matcher.run, []),
    ("windows_process", windows_process.run, ["rules-windows-system.json", "rules-windows-process.json"]),
    ("linux_persistence", linux_persistence.run, [
        "rules-linux-system.json",
        "rules-linux-sigma.json",
        "rules-linux-signatures.json",
        "rules-linux-process.json",
        "rules-linux-network.json",
        "rules-linux-kernel.json",
        "rules-linux-persistence.json",
        "rules-linux-0707.json",
        "rules-tools_rules.json",
    ]),
    ("browsers", browsers.run, ["rules-browsers.json"]),
    ("artifacts", artifacts.run, ["rules-windows-system.json", "rules-windows-apt-persist.json"]),
    ("aux_rules", aux_rules.run, ["rules-email.json", "rules-encryption.json", "rules-file-types.json"]),
    ("ransom", ransom_matcher.run, []),  # rules/ransom_families.json，自管家族后缀库
    ("eventlog", eventlog.run, []),  # log_rules/rules Sigma，自管规则目录
]
MATCHERS = PARALLEL_MATCHERS  # 兼容旧引用

# 分级匹配：fast 先出告警，full 再跑文件/兴趣点等重模块
FAST_MATCHER_NAMES = {
    "ioc", "network", "persistence", "driver", "windows_process", "linux_persistence",
    "keywords", "wininfosc", "remote_tools", "lateral", "cred_theft", "beacon",
    "defense_weaken", "exfil",
}
HEAVY_MATCHER_NAMES = {"files", "browsers", "artifacts", "aux_rules", "ransom", "eventlog", "ioc"}
FULL_MATCHER_NAMES = {n for n, _, _ in PARALLEL_MATCHERS}

# Windows-only matchers skipped when os_family == linux
# eventlog 对 Linux 走 linux_journal 引擎，故不再整段跳过
_WINDOWS_ONLY_MATCHERS = frozenset({
    "wininfosc", "remote_tools", "persistence", "driver", "windows_process",
    "artifacts", "browsers", "lateral", "cred_theft", "defense_weaken",
})
_LINUX_ONLY_MATCHERS = frozenset({"linux_persistence"})



# Finding.matcher 历史别名 → 管线模块 id（分栏计数归并）
MATCHER_BUCKET_ALIASES = {
    "windows": "persistence",
    "registry": "artifacts",
    "recycle": "artifacts",
    "hosts": "artifacts",
    "email": "aux_rules",
    "encryption": "aux_rules",
    "file_types": "aux_rules",
    "ioc_db": "ioc",
}


def _ioc_can_run(store: Optional[RuleStore] = None) -> bool:
    """IOC：有 rules-ioc.json 或本地 ioc_data.db 即可跑。"""
    st = store or get_store()
    if st.file_active("rules-ioc.json"):
        return True
    try:
        from . import ioc_db
        return bool((ioc_db.stats() or {}).get("enabled"))
    except Exception:
        return False


def skipped_matchers(store: Optional[RuleStore] = None) -> List[str]:
    """规则文件已删/禁用/下线时，对应 matcher 不再跑。"""
    st = store or get_store()
    dead = ["interesting"]
    for name, _fn, rules in PARALLEL_MATCHERS:
        if name == "ioc":
            if not _ioc_can_run(st) and name not in dead:
                dead.append(name)
            continue
        if not rules:
            continue
        active = any(st.file_active(f) for f in rules)
        if name == "linux_persistence" and not active:
            linux = getattr(st, "linux", None) or {}
            if isinstance(linux, dict) and any(
                linux.get(k) for k in (
                    "processRules", "textRules", "commandRules",
                    "networkRules", "portRules", "moduleRules", "sigmaRules",
                )
            ):
                active = True
        if not active and name not in dead:
            dead.append(name)
    return dead


def _matchers_for_stage(
    stage: str,
    only_matchers: Optional[List[str]] = None,
    store: Optional[RuleStore] = None,
    report: Optional[Dict[str, Any]] = None,
):
    stage = (stage or "full").lower()
    st = store or get_store()
    fam = detect_os_family(report) if report is not None else "windows"
    if only_matchers:
        want = {str(x).strip() for x in only_matchers if str(x).strip()}
        raw = [m for m in PARALLEL_MATCHERS if m[0] in want]
    elif stage == "fast":
        raw = [m for m in PARALLEL_MATCHERS if m[0] in FAST_MATCHER_NAMES]
    else:
        raw = [m for m in PARALLEL_MATCHERS if m[0] in FULL_MATCHER_NAMES]
    out = []
    for name, fn, rules in raw:
        if name == "interesting":
            continue
        if fam == "linux" and name in _WINDOWS_ONLY_MATCHERS:
            continue
        if fam != "linux" and name in _LINUX_ONLY_MATCHERS:
            continue
        if name == "ioc":
            if not _ioc_can_run(st):
                continue
            used = [f for f in rules if st.file_active(f)] if rules else []
            out.append((name, fn, used))
            continue
        if rules and not any(st.file_active(f) for f in rules):
            continue
        used = [f for f in rules if st.file_active(f)] if rules else []
        out.append((name, fn, used))
    return out


def prune_inactive_modules(analysis: Optional[Dict[str, Any]], store: Optional[RuleStore] = None) -> Dict[str, Any]:
    """从分析结果里拿掉已下线/已删规则模块，避免旧报告继续显示。"""
    if not analysis:
        return analysis or {}
    dead = set(skipped_matchers(store))
    by = dict(analysis.get("findings_by_module") or {})
    for k in list(by.keys()):
        if k in dead:
            by.pop(k, None)
    analysis["findings_by_module"] = by
    pipe = dict(analysis.get("pipeline") or {})
    pipe["matchers"] = [
        x for x in (pipe.get("matchers") or [])
        if not (isinstance(x, dict) and (x.get("matcher") or "") in dead)
    ]
    st = store or get_store()
    pipe["rules_used"] = [x for x in (pipe.get("rules_used") or []) if st.file_active(x)]
    analysis["pipeline"] = pipe

    def keep(f: Dict[str, Any]) -> bool:
        m = str(f.get("matcher") or "").lower()
        cat = str(f.get("category") or f.get("type") or "")
        if m in dead or m == "interesting" or cat == "RMM":
            return False
        return True

    for key in ("findings", "findings_aggregated"):
        lst = analysis.get(key)
        if isinstance(lst, list):
            analysis[key] = [x for x in lst if isinstance(x, dict) and keep(x)]
    return analysis


def list_matcher_steps() -> List[Dict[str, Any]]:
    """前端可插拔步骤清单。"""
    return [
        {
            "id": name,
            "label": {
                "files": "可疑文件",
                "ioc": "IOC情报",
                "network": "网络外联",
                "keywords": "关键词/PS",
                "wininfosc": "系统信息",
                "remote_tools": "远控软件",
                "lateral": "登录横向",
                "cred_theft": "凭据威胁",
                "beacon": "外联画像",
                "defense_weaken": "防护弱化",
                "exfil": "外传同步",
                "persistence": "持久化",
                "windows_process": "Windows进程",
                "linux_persistence": "Linux持久化",
                "browsers": "浏览器",
                "artifacts": "Prefetch/注册表",
                "aux_rules": "邮件/加密/类型",
                "eventlog": "系统日志",
            }.get(name, name),
            "fast": name in FAST_MATCHER_NAMES,
            "rules": list(rules),
        }
        for name, _fn, rules in PARALLEL_MATCHERS
    ]


def _run_one(name, fn, rule_files, report, store, cancel_check=None) -> Tuple[str, List[Finding], Dict, List[str], Optional[str], int]:
    seen: Set[str] = set()
    t0 = time.perf_counter()
    try:
        if cancel_check and cancel_check():
            raise JobCancelled()
        findings, bucket = fn(report, store, seen)
        ms = int((time.perf_counter() - t0) * 1000)
        return name, findings, bucket or {}, rule_files, None, ms
    except JobCancelled:
        raise
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        return name, [], {}, rule_files, str(e), ms


def _retry_failed_matchers(
    matchers,
    by_name: Dict,
    report,
    store,
    cancel_check=None,
) -> Dict:
    """对异常失败的 matcher 重试一次，避免瞬时错误导致整模块无输出。"""
    out = dict(by_name)
    for name, fn, rule_files in matchers:
        prev = out.get(name)
        if not prev:
            continue
        _findings, _bucket, _rf, err, _ms = prev
        if not err:
            continue
        print(f"[pipeline] retry matcher={name} after error: {err}")
        name2, findings, bucket, rf, err2, ms2 = _run_one(
            name, fn, rule_files, report, store, cancel_check
        )
        out[name2] = (findings, bucket, rf, err2, ms2)
        if err2:
            print(f"[pipeline] retry still failed matcher={name}: {err2}")
        else:
            print(f"[pipeline] retry ok matcher={name} findings={len(findings)} ms={ms2}")
    return out


def _finding_from_dict(d: Dict[str, Any]) -> Optional[Finding]:
    try:
        from .models import infer_anchor_from_extra
        ev = d.get("evidence") or d.get("reason") or ""
        if isinstance(ev, list):
            ev = "; ".join(str(x) for x in ev[:3])
        extra = d.get("extra") if isinstance(d.get("extra"), dict) else {
            k: d[k] for k in ("kind", "path", "file_count", "members", "file", "members_truncated", "persist_kind", "sha256", "md5", "hostname", "pack_file") if k in d
        }
        host = str(d.get("hostname") or (extra or {}).get("hostname") or (extra or {}).get("host") or "")
        anchor = d.get("anchor") if isinstance(d.get("anchor"), dict) else None
        if not anchor:
            anchor = infer_anchor_from_extra(
                extra, evidence=str(ev), source=str(d.get("source") or ""), host=host,
            )
        elif host and not anchor.get("host"):
            anchor = {**anchor, "host": host}
        return Finding(
            category=d.get("category") or d.get("type") or "",
            title=d.get("title") or d.get("name") or "",
            severity=d.get("severity") or "medium",
            evidence=str(ev)[:2000],
            source=d.get("source") or "",
            matcher=d.get("matcher") or "",
            rule_id=d.get("rule_id") or "",
            extra=extra,
            anchor=anchor,
        )
    except Exception:
        return None


def _merge_partial(
    base: Optional[Dict[str, Any]],
    partial: Dict[str, Any],
    only_matchers: List[str],
) -> Dict[str, Any]:
    """局部重跑 / fast+heavy：用新结果替换指定 matcher，其余模块完整保留。"""
    if not base:
        return partial
    out = dict(base)
    want = set(only_matchers)
    old_by = dict((base.get("findings_by_module") or {}))
    new_by = dict((partial.get("findings_by_module") or {}))
    merged_mod = dict(old_by)
    for name in want:
        if name in new_by:
            merged_mod[name] = new_by[name]
        else:
            # 明确跑过但无命中：占位，避免前端以为模块未执行
            merged_mod[name] = {
                "matcher": name, "count": 0, "high": 0, "findings": [],
            }
    # 重建 flat findings / aggregated
    all_dicts: List[Dict] = []
    for name, block in merged_mod.items():
        if not isinstance(block, dict):
            continue
        for f in block.get("findings") or []:
            if isinstance(f, dict):
                all_dicts.append(f)
    # Finding 对象重建聚合
    findings_objs: List[Finding] = []
    for d in all_dicts:
        fobj = _finding_from_dict(d)
        if fobj:
            findings_objs.append(fobj)
    agg = aggregate_findings(findings_objs)
    out["findings"] = all_dicts[: max(100, len(all_dicts))]
    out["_findings_total"] = len(all_dicts)
    out["findings_aggregated"] = agg["findings_aggregated"]
    out["summary_aggregated"] = agg["summary_aggregated"]
    out["summary"] = summarize(findings_objs, out.get("ioc_hits") or {})
    out["findings_by_module"] = merged_mod
    # pipeline 记录：保留 base 中未重跑模块的执行记录 + partial 新记录
    pipe = dict(out.get("pipeline") or {})
    ran = [x for x in (pipe.get("matchers") or []) if isinstance(x, dict) and x.get("matcher") not in want]
    ran.extend((partial.get("pipeline") or {}).get("matchers") or [])
    pipe["matchers"] = ran
    pipe["stage"] = "partial"
    pipe["only_matchers"] = list(only_matchers)
    # 合并数据就绪信息（以较新 partial 为准）
    ready = dict(pipe.get("match_ready") or {})
    ready.update((partial.get("pipeline") or {}).get("match_ready") or {})
    if ready:
        pipe["match_ready"] = ready
    out["pipeline"] = pipe
    meta = dict(out.get("meta") or {})
    meta.update(partial.get("meta") or {})
    meta["stage"] = "partial"
    meta["only_matchers"] = list(only_matchers)
    if ready:
        meta["match_ready"] = ready
    # 汇总两阶段 matcher 错误
    errs = []
    for x in ran:
        if isinstance(x, dict) and not x.get("ok"):
            errs.append({"matcher": x.get("matcher"), "error": x.get("error")})
    if errs:
        meta["matcher_errors"] = errs
    else:
        meta.pop("matcher_errors", None)
    out["meta"] = meta
    # 保留原 AI（局部重跑默认不重算 AI）
    if base.get("ai") and not partial.get("ai"):
        out["ai"] = base["ai"]
    # ioc_hits：若重跑了 ioc，用新的
    if "ioc" in want:
        out["ioc_hits"] = partial.get("ioc_hits") or {}
        if partial.get("meta"):
            for k in ("ioc_db", "ioc_scan", "hashed_files"):
                if k in (partial.get("meta") or {}):
                    out.setdefault("meta", {})[k] = partial["meta"][k]
    return prune_inactive_modules(out)


class AnalysisPipeline:
    def __init__(self, store: Optional[RuleStore] = None, with_ai: bool = False):
        self.store = store or get_store()
        self.with_ai = with_ai

    def run(
        self,
        report: Dict[str, Any],
        with_ai: Optional[bool] = None,
        stage: str = "full",
        only_matchers: Optional[List[str]] = None,
        base_analysis: Optional[Dict[str, Any]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        if cancel_check and cancel_check():
            raise JobCancelled()
        report = slim_report(report)
        a = empty_analysis()
        all_findings: List[Finding] = []
        used_rules: List[str] = []
        ran = []
        global_seen: Set[str] = set()
        matchers = _matchers_for_stage(stage, only_matchers, store=self.store, report=report)

        workers = min(2, max(1, len(matchers))) or 1
        t_stage = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [
                ex.submit(_run_one, name, fn, rules, report, self.store, cancel_check)
                for name, fn, rules in matchers
            ]
            by_name = {}
            for fut in as_completed(futs):
                time.sleep(0)
                if cancel_check and cancel_check():
                    for pending in futs:
                        pending.cancel()
                    raise JobCancelled()
                name, findings, bucket, rule_files, err, ms = fut.result()
                by_name[name] = (findings, bucket, rule_files, err, ms)

        # 失败模块重试一次（入库后瞬时锁/IO 错误不应让整模块空白）
        if any((by_name.get(n) or (None, None, None, "x", 0))[3] for n, _, _ in matchers):
            by_name = _retry_failed_matchers(
                matchers, by_name, report, self.store, cancel_check
            )

        timing_parts = []
        for name, fn, rule_files in matchers:
            findings, bucket, rf, err, ms = by_name.get(name, ([], {}, rule_files, "missing", 0))
            timing_parts.append(f"{name}={ms}ms")
            if err:
                ran.append({"matcher": name, "ok": False, "error": err, "ms": ms})
                continue
            kept = 0
            for f in findings:
                key = f"{f.category}|{f.title}|{(f.evidence or '')[:160]}|{f.source}"
                if key in global_seen:
                    continue
                global_seen.add(key)
                all_findings.append(f)
                kept += 1
            for k, v in (bucket or {}).items():
                if k == "ioc_hits" and isinstance(v, dict):
                    for ik, iv in v.items():
                        a["ioc_hits"].setdefault(ik, []).extend(iv or [])
                elif k in a and isinstance(a[k], list) and isinstance(v, list):
                    a[k].extend(v)
                elif k == "collection_coverage":
                    a.setdefault("meta", {})["collection_coverage"] = v
                elif k in ("ioc_db", "ioc_scan", "hashed_files"):
                    a.setdefault("meta", {})[k] = v
                elif k == "eventlog_meta":
                    a.setdefault("meta", {})["eventlog"] = v
                elif k == "eventlog_hit_index" and isinstance(v, dict):
                    a.setdefault("meta", {})["eventlog_hit_index"] = v
                elif k == "eventlog_hit_by_ce" and isinstance(v, dict):
                    a.setdefault("meta", {})["eventlog_hit_by_ce"] = v
                elif k == "ransom_analysis" and isinstance(v, dict):
                    a.setdefault("meta", {})["ransom_analysis"] = v
            used_rules.extend(rf)
            ran.append({"matcher": name, "ok": True, "findings": kept, "ms": ms})

        stage_ms = int((time.perf_counter() - t_stage) * 1000)
        if timing_parts:
            print(f"[pipeline] stage={stage} wall={stage_ms}ms " + " ".join(timing_parts))
            try:
                from . import applog
                applog.info(
                    "pipeline",
                    f"stage={stage} wall={stage_ms}ms " + " ".join(timing_parts),
                    stage=stage,
                    wall_ms=stage_ms,
                )
            except Exception:
                pass

            # 干净系统基线：过滤已知正常服务/计划任务/启动项
        bl_stats: Dict[str, Any] = {}
        try:
            from . import baseline
            all_findings, bl_stats = baseline.filter_findings(all_findings)
        except Exception as e:
            bl_stats = {}
            print(f"[pipeline] baseline filter: {e}")

            # 全局黑白名单：白名单丢弃，黑名单抬高
        bw_stats: Dict[str, int] = {}
        op_meta: Dict[str, Any] = {}
        try:
            from . import bw_list
            all_findings, bw_stats = bw_list.filter_findings(all_findings)
        except Exception as e:
            bw_stats = {}
            print(f"[pipeline] bw_list filter: {e}")

        # 匹配器之后：operators（跨主机共享哈希 / USN 时间聚类等）
        host_name = str(report.get("hostname") or "").strip()
        if not only_matchers:
            try:
                from .operators import run_operators
                from .models import infer_anchor_from_extra
                op_findings, op_meta = run_operators(report)
                for f in op_findings:
                    if not f.anchor:
                        f.anchor = infer_anchor_from_extra(
                            f.extra,
                            evidence=f.evidence or "",
                            source=f.source or "",
                            host=host_name,
                        )
                    elif host_name and isinstance(f.anchor, dict) and not f.anchor.get("host"):
                        f.anchor["host"] = host_name
                    key = f"{f.category}|{f.title}|{(f.evidence or '')[:160]}|{f.source}"
                    if key in global_seen:
                        continue
                    global_seen.add(key)
                    all_findings.append(f)
            except Exception as e:
                op_meta = {"error": str(e)}
                print(f"[pipeline] operators: {e}")

        # 为仍无锚点的 finding 尽量补全（含 host / pack_file）
        try:
            from .models import infer_anchor_from_extra
            for f in all_findings:
                if f.anchor:
                    if host_name and isinstance(f.anchor, dict) and not f.anchor.get("host"):
                        f.anchor["host"] = host_name
                    if isinstance(f.anchor, dict) and f.anchor.get("pack") and not f.anchor.get("pack_file"):
                        f.anchor["pack_file"] = f.anchor["pack"]
                    continue
                f.anchor = infer_anchor_from_extra(
                    f.extra,
                    evidence=f.evidence or "",
                    source=f.source or "",
                    host=host_name,
                )
        except Exception:
            pass

        a["findings"] = [f.to_dict() for f in all_findings]
        a["summary"] = summarize(all_findings, a["ioc_hits"])
        agg = aggregate_findings(all_findings)
        a["findings_aggregated"] = agg["findings_aggregated"]
        a["summary_aggregated"] = agg["summary_aggregated"]
        by_mod: Dict[str, List[Dict]] = {}
        for f in all_findings:
            mid = MATCHER_BUCKET_ALIASES.get(f.matcher or "", f.matcher or "other")
            by_mod.setdefault(mid, []).append(f.to_dict())
        for name, _fn, _rf in matchers:
            by_mod.setdefault(name, [])
        a["findings_by_module"] = {
            k: {
                "matcher": k,
                "count": len(v),
                "high": sum(1 for x in v if str(x.get("severity", "")).lower() in ("high", "critical")),
                "findings": v,
            }
            for k, v in by_mod.items()
        }
        a["pipeline"] = {
            "matchers": ran,
            "rules_used": sorted(set(used_rules)),
            "stage": "partial" if only_matchers else stage,
            "only_matchers": list(only_matchers) if only_matchers else None,
            "bw_list": bw_stats,
            "baseline": bl_stats,
            "match_ready": report.get("_match_ready") or {},
            "operators": (op_meta or {}).get("operators") if op_meta else [],
        }
        if op_meta:
            a.setdefault("meta", {})["operators"] = op_meta
        a["timeline"] = build_timeline(report, a)
        a["meta"] = a.get("meta") or {}
        a["meta"]["collection_quality"] = report.get("collection_quality")
        a["meta"]["stage"] = a["pipeline"]["stage"]
        try:
            from .quality_gate import attach_gate_to_analysis
            a = attach_gate_to_analysis(a, report)
        except Exception as e:
            print(f"[pipeline] quality_gate: {e}")
        if report.get("_match_ready"):
            a["meta"]["match_ready"] = report["_match_ready"]
        failed = [x for x in ran if isinstance(x, dict) and not x.get("ok")]
        if failed:
            a["meta"]["matcher_errors"] = [
                {"matcher": x.get("matcher"), "error": x.get("error")} for x in failed
            ]
            print(f"[pipeline] matcher errors: {a['meta']['matcher_errors']}")
        if bw_stats:
            a["meta"]["bw_list"] = bw_stats
        if bl_stats:
            a["meta"]["baseline"] = bl_stats
        if only_matchers:
            a["meta"]["only_matchers"] = list(only_matchers)

        report["suspicious_items"] = [
            {
                "type": x["category"],
                "name": x["title"],
                "reason": x.get("reason") or x["title"],
                "severity": x.get("severity", "medium"),
                "count": x.get("count", 1),
            }
            for x in a["findings_aggregated"]
        ]

        if only_matchers:
            a = _merge_partial(base_analysis, a, list(only_matchers))
            # 局部重跑后刷新时间线
            a["timeline"] = build_timeline(report, a)
        a = prune_inactive_modules(a, self.store)

        do_ai = self.with_ai if with_ai is None else with_ai
        if do_ai and (stage == "full" and not only_matchers):
            from .ai.analyzer import analyze_with_ai
            a["ai"] = analyze_with_ai(report, a)

        return a


def analyze_report(
    report: Dict[str, Any],
    with_ai: bool = False,
    stage: str = "full",
    only_matchers: Optional[List[str]] = None,
    base_analysis: Optional[Dict[str, Any]] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    return AnalysisPipeline(with_ai=with_ai).run(
        report,
        with_ai=with_ai,
        stage=stage,
        only_matchers=only_matchers,
        base_analysis=base_analysis,
        cancel_check=cancel_check,
    )
