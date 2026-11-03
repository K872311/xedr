# -*- coding: utf-8 -*-
"""一次性就绪：Elastic catalog + Wazuh SCA bundle + 可选 Elastic 入门规则导入。"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

_STARTER = Path(config.ROOT) / "config" / "elastic_detection_starter.json"
_MARKER = Path(config.RULES_DIR) / "published" / ".detection_corpus_ready.json"
_EVM = Path(config.ROOT) / "config" / "elastic_evm_import.json"
_SCA_BUNDLE = Path(config.ROOT) / "config" / "agent_sca_bundle.json"


def _read_json(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _pick_starter_rule_ids(starter: Dict[str, Any]) -> List[str]:
    explicit = starter.get("explicit_rule_ids")
    if isinstance(explicit, list) and explicit:
        return [str(x).strip() for x in explicit if str(x).strip()]
    if str(starter.get("pick") or "").strip().lower() == "precision":
        from . import elastic_precision as ep

        auto = starter.get("precision") if isinstance(starter.get("precision"), dict) else {}
        return ep.pick_precision_rule_ids(
            platform=str(auto.get("platform") or "windows"),
            min_score=int(auto.get("min_score") or 100),
            max_rules=int(auto.get("max_rules") or 20),
        )
    auto = starter.get("auto_pick") if isinstance(starter.get("auto_pick"), dict) else {}
    from . import elastic_detection_import as edi

    cat = edi.load_catalog()
    items = list(cat.get("items") or [])
    plats = {str(x).lower() for x in (auto.get("platforms") or ["windows"])}
    sevs = {str(x).lower() for x in (auto.get("severity") or ["high", "critical"])}
    max_n = int(auto.get("max_rules") or 48)
    req = str(auto.get("require") or "has_evm_or_agent")
    path_need = [str(x).lower() for x in (auto.get("path_contains") or []) if str(x).strip()]
    out: List[str] = []
    for it in items:
        if str(it.get("status") or "") != "convertible":
            continue
        if plats and str(it.get("platform") or "").lower() not in plats:
            continue
        if sevs and str(it.get("severity") or "").lower() not in sevs:
            continue
        if req == "has_evm" and not it.get("has_evm"):
            continue
        if req == "has_agent" and not it.get("has_agent"):
            continue
        if req == "has_evm_or_agent" and not (it.get("has_evm") or it.get("has_agent")):
            continue
        rel = str(it.get("rel_path") or "").lower()
        if path_need and not any(p in rel for p in path_need):
            continue
        rid = str(it.get("id") or "").strip()
        if rid:
            out.append(rid)
        if len(out) >= max_n:
            break
    return out


def ensure_detection_corpus(
    *,
    force: bool = False,
    skip_elastic_import: bool = False,
) -> Dict[str, Any]:
    """幂等：catalog、SCA bundle、Elastic 入门 EVM（默认仅启用 EVM 侧）。"""
    if os.getenv("FORENSIC_SKIP_CORPUS_BOOTSTRAP", "").strip().lower() in ("1", "true", "yes"):
        return {"ok": True, "skipped": "FORENSIC_SKIP_CORPUS_BOOTSTRAP"}

    from . import agent_sync, elastic_detection_import as edi, wazuh_ruleset as wr

    report: Dict[str, Any] = {"ok": True, "steps": []}

    def step(name: str, detail: Any) -> None:
        report["steps"].append({"step": name, "detail": detail})

    # 1) Elastic catalog
    cat_path = Path(config.RULES_DIR) / "published" / "elastic-detection-catalog.json"
    if force or not cat_path.is_file():
        cat = edi.scan_catalog()
        cat_path = edi.save_catalog(cat)
    step("elastic_catalog", str(cat_path))

    # 2) Wazuh catalog
    sca_cat_path = Path(config.RULES_DIR) / "published" / "wazuh-sca-catalog.json"
    if force or not sca_cat_path.is_file():
        sca_cat = wr.scan_catalog()
        sca_cat_path = wr.save_catalog(sca_cat)
    step("wazuh_catalog", str(sca_cat_path))

    # 3) SCA agent bundle
    if force or not _SCA_BUNDLE.is_file():
        doc = wr.export_agent_bundle_document()
        wr.save_agent_bundle(doc)
    step("sca_bundle", str(_SCA_BUNDLE))

    # 3b) Elastic protections-artifacts 精选（YARA + EVM + PTM）
    try:
        from . import protections_import as pi

        prot_marker = Path(config.RULES_DIR) / "published" / ".protections_bundle_applied.json"
        _cfg = Path(config.ROOT) / "config"
        need_prot = force or not (_cfg / "protections_evm_import.json").is_file()
        if need_prot:
            prot = pi.apply_bundle(write=True, dry_run=False)
            step("protections_bundle", prot)
            if prot.get("ok"):
                prot_marker.parent.mkdir(parents=True, exist_ok=True)
                prot_marker.write_text(
                    json.dumps({"applied_at": time.strftime("%Y-%m-%dT%H:%M:%S"), **prot}, ensure_ascii=False, indent=2)
                    + "\n",
                    encoding="utf-8",
                )
        else:
            step("protections_bundle", "skipped (protections_evm_import.json exists)")
    except Exception as e:
        step("protections_bundle", str(e))

    # 4) Elastic starter import
    imp_summary: Optional[Dict[str, Any]] = None
    starter = _read_json(_STARTER)
    imp_cfg = starter.get("import") if isinstance(starter.get("import"), dict) else {}
    if not skip_elastic_import and starter:
        need_import = force or not _EVM.is_file()
        if not need_import and _MARKER.is_file():
            try:
                mk = _read_json(_MARKER)
                if mk.get("starter_version") != starter.get("version"):
                    need_import = True
            except Exception:
                need_import = True
        if need_import:
            ids = _pick_starter_rule_ids(starter)
            if ids:
                imp_summary = edi.import_rules(
                    ids,
                    mode=str(imp_cfg.get("mode") or "both"),
                    dry_run=False,
                    enable=False,
                    enable_agent=bool(imp_cfg.get("enable_agent_rules", False)),
                    enable_evm=bool(imp_cfg.get("enable_evm_rules", True)),
                )
                step("elastic_starter_import", {"ids": len(ids), **(imp_summary or {})})
                try:
                    agent_sync.bump_sync("evm")
                    agent_sync.bump_sync("rules")
                except Exception:
                    pass
            else:
                step("elastic_starter_import", "no ids matched")
        else:
            step("elastic_starter_import", "skipped (evm file exists)")

    _MARKER.parent.mkdir(parents=True, exist_ok=True)
    _MARKER.write_text(
        json.dumps(
            {
                "ready_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "starter_version": starter.get("version"),
                "elastic_evm": str(_EVM) if _EVM.is_file() else "",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    # 5) Elasticsearch EDR 索引 + 规则发布（ES 已启用时）
    try:
        from . import es_client
        from . import elastic_detection_es as edes

        es_client.reset()
        if edes.detection_enabled():
            idx_ok = edes.ensure_edr_indices()
            pub = edes.publish_detection_rules_to_es(max_rules=800)
            step("elasticsearch_edr", {"indices": idx_ok, **pub})
        else:
            step("elasticsearch_edr", "skipped (edr_detection_enabled=false 或 ES 未启用)")
    except Exception as e:
        step("elasticsearch_edr", str(e))

    report["marker"] = str(_MARKER)
    report["elastic_evm"] = str(_EVM) if _EVM.is_file() else ""
    report["import"] = imp_summary
    return report


def ensure_elasticsearch_edr(*, publish_max: int = 800, run_once: bool = False) -> Dict[str, Any]:
    """单独初始化 ES 端点索引与 EQL 规则库。"""
    from . import es_client
    from . import elastic_detection_es as edes

    es_client.reset()
    out: Dict[str, Any] = {"ok": True}
    if not edes.detection_enabled():
        out["ok"] = False
        out["error"] = "请在 db_config.elasticsearch 设置 enabled=true 且 edr_detection_enabled=true"
        return out
    if not es_client.is_available():
        out["ok"] = False
        out["error"] = es_client.probe_status(reprobe=True).get("error") or "ES 不可连接"
        return out
    out["indices"] = edes.ensure_edr_indices()
    out["publish"] = edes.publish_detection_rules_to_es(max_rules=publish_max)
    out["status"] = edes.status()
    if run_once:
        out["cycle"] = edes.run_detection_cycle(force=True)
    return out


def corpus_status() -> Dict[str, Any]:
    from . import agent_sync, elastic_detection_import as edi, wazuh_ruleset as wr

    evm_n = 0
    evm_en = 0
    if _EVM.is_file():
        try:
            doc = json.loads(_EVM.read_text(encoding="utf-8"))
            rules = doc.get("rules") or []
            evm_n = len(rules)
            evm_en = sum(1 for r in rules if isinstance(r, dict) and r.get("enabled", True))
        except Exception:
            pass
    sca_checks = 0
    try:
        b = wr.export_agent_bundle_document()
        sca_checks = sum(len(p.get("checks") or []) for p in (b.get("policies") or []) if isinstance(p, dict))
    except Exception:
        pass
    ecat = edi.load_catalog()
    wcat = wr.load_catalog()
    es_det: Dict[str, Any] = {}
    try:
        from . import elastic_detection_es as edes
        es_det = edes.status()
    except Exception:
        es_det = {}
    return {
        "ok": True,
        "sync_rev": agent_sync.sync_revision(),
        "elastic": {
            "catalog_rules": (ecat.get("stats") or {}).get("total"),
            "convertible": (ecat.get("stats") or {}).get("convertible"),
            "evm_file": str(_EVM) if _EVM.is_file() else "",
            "evm_rules": evm_n,
            "evm_enabled": evm_en,
            "engine_mode": "platform_lite",
            "full_stack_note": "完整 EQL/esql 需 Elastic Stack（Elasticsearch + Kibana Detection）；本平台为 TOML→EVM/快照轻量转换。",
            "es_detection": es_det,
        },
        "wazuh": {
            "catalog_policies": (wcat.get("stats") or {}).get("policies"),
            "sca_bundle_checks": sca_checks,
            "sca_bundle": str(_SCA_BUNDLE) if _SCA_BUNDLE.is_file() else "",
        },
        "marker": str(_MARKER) if _MARKER.is_file() else "",
    }
