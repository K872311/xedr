# -*- coding: utf-8 -*-
"""EDR 通知渠道：Webhook / 飞书 / 钉钉。威胁事件（high/critical）异步推送。"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

_lock = threading.RLock()
_DEFAULT = {
    "enabled": False,
    "min_severity": "high",  # high / critical
    "webhook_url": "",
    "feishu_webhook": "",
    "dingtalk_webhook": "",
    "dingtalk_secret": "",
    "timeout_sec": 8,
}


def _cfg_path() -> Path:
    d = Path(getattr(config, "CONFIG_DIR", None) or (Path(config.ROOT) / "config"))
    d.mkdir(parents=True, exist_ok=True)
    return d / "agent_notify.json"


def get_notify_config() -> Dict[str, Any]:
    p = _cfg_path()
    data = dict(_DEFAULT)
    if p.is_file():
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                data.update({k: raw.get(k, data[k]) for k in _DEFAULT})
        except Exception:
            pass
    return {"ok": True, "config": data}


def set_notify_config(payload: Dict[str, Any]) -> Dict[str, Any]:
    cur = get_notify_config()["config"]
    for k in _DEFAULT:
        if k in (payload or {}):
            cur[k] = payload[k]
    cur["enabled"] = bool(cur.get("enabled"))
    cur["min_severity"] = str(cur.get("min_severity") or "high").lower()
    if cur["min_severity"] not in ("medium", "high", "critical"):
        cur["min_severity"] = "high"
    cur["timeout_sec"] = max(3, min(int(cur.get("timeout_sec") or 8), 30))
    for key in ("webhook_url", "feishu_webhook", "dingtalk_webhook", "dingtalk_secret"):
        cur[key] = str(cur.get(key) or "").strip()
    _cfg_path().write_text(json.dumps(cur, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "config": cur}


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _pass_sev(sev: str, min_sev: str) -> bool:
    return _SEV_RANK.get(str(sev).lower(), 0) >= _SEV_RANK.get(str(min_sev).lower(), 3)


def notify_event(event: Dict[str, Any]) -> None:
    """非阻塞：后台线程推送。"""
    cfg = get_notify_config()["config"]
    if not cfg.get("enabled"):
        return
    if not _pass_sev(event.get("severity") or "", cfg.get("min_severity") or "high"):
        return
    if event.get("deduped"):
        return
    threading.Thread(target=_dispatch, args=(cfg, event), daemon=True).start()


def _dispatch(cfg: Dict[str, Any], event: Dict[str, Any]) -> List[Dict[str, Any]]:
    title = str(event.get("title") or "威胁事件")
    host = str(event.get("hostname") or event.get("agent_id") or "")
    sev = str(event.get("severity") or "")
    module = str(event.get("module") or "")
    eid = event.get("id")
    text = f"[EDR][{sev}] {title}\n主机: {host}\n模块: {module}\n事件ID: {eid}"
    results: List[Dict[str, Any]] = []
    if cfg.get("webhook_url"):
        results.append({"channel": "webhook", **_post_json(cfg["webhook_url"], {
            "text": text,
            "title": title,
            "severity": sev,
            "hostname": host,
            "module": module,
            "event_id": eid,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }, int(cfg.get("timeout_sec") or 8))})
    if cfg.get("feishu_webhook"):
        results.append({"channel": "feishu", **_post_json(cfg["feishu_webhook"], {
            "msg_type": "text",
            "content": {"text": text},
        }, int(cfg.get("timeout_sec") or 8))})
    if cfg.get("dingtalk_webhook"):
        body = {
            "msgtype": "text",
            "text": {"content": text},
        }
        url = cfg["dingtalk_webhook"]
        # 签名可选
        secret = cfg.get("dingtalk_secret") or ""
        if secret:
            import hashlib
            import hmac
            import base64
            import urllib.parse
            ts = str(int(time.time() * 1000))
            string_to_sign = f"{ts}\n{secret}"
            sign = urllib.parse.quote_plus(
                base64.b64encode(
                    hmac.new(secret.encode("utf-8"), string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
                )
            )
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}timestamp={ts}&sign={sign}"
        results.append({"channel": "dingtalk", **_post_json(url, body, int(cfg.get("timeout_sec") or 8))})
    return results


def _post_json(url: str, payload: Dict[str, Any], timeout: int) -> Dict[str, Any]:
    try:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"ok": True, "status": getattr(resp, "status", 200)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def test_notify() -> Dict[str, Any]:
    cfg = get_notify_config()["config"]
    if not any(cfg.get(k) for k in ("webhook_url", "feishu_webhook", "dingtalk_webhook")):
        return {"ok": False, "error": "未配置任何通知渠道"}
    fake = {
        "id": 0,
        "title": "通知渠道测试",
        "severity": "high",
        "hostname": "test-host",
        "module": "notify",
        "deduped": False,
    }
    results = _dispatch(cfg, fake)
    return {"ok": all(r.get("ok") for r in results), "results": results}
