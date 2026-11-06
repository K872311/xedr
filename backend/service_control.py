# -*- coding: utf-8 -*-
"""分析 / ES / Kibana 等服务探测、状态与单独重启（管理员）。"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import ssl
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config

_LIST_CACHE: Optional[Dict[str, Any]] = None
_LIST_CACHE_AT = 0.0
_LIST_TTL = 8.0


def install_root() -> Path:
    return Path(getattr(config, "ROOT", None) or Path(__file__).resolve().parent.parent).resolve()


def start_script() -> Path:
    return install_root() / "start.ps1"


def ensure_stack_script() -> Path:
    return install_root() / "scripts" / "ensure-stack.ps1"


def detect_port() -> int:
    env = (os.getenv("FORENSIC_PORT") or "").strip()
    if env.isdigit():
        return int(env)
    try:
        import psutil  # type: ignore

        p = psutil.Process(os.getpid())
        cmdline = " ".join(p.cmdline() or [])
        for token in ("--port", "-p"):
            if token in cmdline:
                parts = cmdline.split()
                for i, x in enumerate(parts):
                    if x in (token, f"{token}=") or x.startswith(f"{token}="):
                        raw = x.split("=", 1)[-1] if "=" in x else (parts[i + 1] if i + 1 < len(parts) else "")
                        if raw.isdigit():
                            return int(raw)
    except Exception:
        pass
    return 8000


def _port_listening(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=0.4):
            return True
    except OSError:
        return False


def _cfg_homes() -> Tuple[str, str]:
    es_home = (os.getenv("FORENSIC_ES_HOME") or "").strip()
    kb_home = (os.getenv("FORENSIC_KIBANA_HOME") or "").strip()
    # 优先 stack_paths.json（服务管理页可改）
    try:
        sp = _load_stack_paths()
        es_home = es_home or str(sp.get("elasticsearch_home") or "").strip()
        kb_home = kb_home or str(sp.get("kibana_home") or "").strip()
    except Exception:
        pass
    try:
        from .cache_config import es_config

        cfg = es_config() or {}
        es_home = es_home or str(cfg.get("home") or cfg.get("es_home") or "").strip()
        kb_home = kb_home or str(cfg.get("kibana_home") or "").strip()
    except Exception:
        pass
    return es_home, kb_home


def _stack_paths_file() -> Path:
    return install_root() / "config" / "stack_paths.json"


def _load_stack_paths() -> Dict[str, Any]:
    p = _stack_paths_file()
    if not p.is_file():
        return {}
    try:
        import json as _json
        data = _json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_stack_paths(patch: Dict[str, Any]) -> Dict[str, Any]:
    """保存 ES/Kibana 安装路径；同步写入 db_config.elasticsearch，供 start.ps1 / ensure-stack 共用。"""
    import json as _json

    cur = _load_stack_paths()
    for k in ("elasticsearch_home", "elasticsearch_script", "kibana_home", "kibana_script"):
        if k in patch:
            cur[k] = str(patch.get(k) or "").strip()
    if "logs" in patch:
        logs = cur.get("logs") if isinstance(cur.get("logs"), dict) else {}
        incoming = patch.get("logs") if isinstance(patch.get("logs"), dict) else {}
        merged = dict(logs)
        for sid, val in incoming.items():
            key = _norm_service_id(str(sid))
            if key:
                merged[key] = str(val or "").strip()
        cur["logs"] = merged
    path = _stack_paths_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_json.dumps(cur, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 同步到 db_config.json，避免两处配置不一致
    try:
        from . import mysql_db
        from .cache_config import reload_cache_config

        dbp = mysql_db._db_config_path() if hasattr(mysql_db, "_db_config_path") else (install_root() / "config" / "db_config.json")
        raw: Dict[str, Any] = {}
        if Path(dbp).is_file():
            raw = _json.loads(Path(dbp).read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raw = {}
        block = raw.get("elasticsearch") if isinstance(raw.get("elasticsearch"), dict) else {}
        block = dict(block)
        if "elasticsearch_home" in patch:
            block["home"] = cur.get("elasticsearch_home") or ""
        if "kibana_home" in patch:
            block["kibana_home"] = cur.get("kibana_home") or ""
        raw["elasticsearch"] = block
        Path(dbp).write_text(_json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        reload_cache_config()
    except Exception as e:
        print(f"[service_control] sync db_config home: {e!r}")

    return cur


def _validate_stack_script(home: str, script: str, bat_name: str) -> Optional[str]:
    """校验自定义启动脚本：必须是 .bat/.cmd，且落在安装目录下。返回错误文案或 None。"""
    script = (script or "").strip()
    if not script:
        return None
    low = script.lower()
    if not (low.endswith(".bat") or low.endswith(".cmd")):
        return "自定义脚本仅允许 .bat / .cmd"
    sp = Path(script)
    try:
        sp_res = sp.resolve()
    except Exception:
        return "脚本路径无效"
    if not sp_res.is_file():
        return f"脚本不存在: {script}"
    home = (home or "").strip()
    if home:
        try:
            home_res = Path(home).resolve()
            if home_res not in sp_res.parents and sp_res.parent != home_res:
                return "自定义脚本必须位于该服务安装目录内"
        except Exception:
            return "安装路径无效"
    else:
        # 未填 home 时，至少要求文件名匹配官方 bat
        if sp_res.name.lower() != bat_name.lower():
            return f"未指定安装目录时，脚本文件名须为 {bat_name}"
    return None


def update_service_path(service_id: str, *, path: str = "", script: str = "") -> Dict[str, Any]:
    """更新可编辑服务的安装路径/启动脚本。分析服务路径固定为程序目录，不可改。"""
    sid = (service_id or "").strip().lower()
    path = (path or "").strip()
    script = (script or "").strip()

    if sid in ("analysis", "web", "app"):
        return {
            "ok": False,
            "error": "分析服务路径固定为当前程序目录，随安装位置自动变化，无需也不应手动改 start.ps1",
        }

    if sid in ("elasticsearch", "es"):
        err = _validate_stack_script(path, script, "elasticsearch.bat")
        if err:
            return {"ok": False, "error": err}
        if path:
            bat = Path(path) / "bin" / "elasticsearch.bat"
            if not script and path and not bat.is_file():
                return {"ok": False, "error": f"未找到 {bat}，请确认是 ES 安装根目录（含 bin\\elasticsearch.bat）"}
        saved = _save_stack_paths({
            "elasticsearch_home": path,
            "elasticsearch_script": script,
        })
        return {"ok": True, "service": "elasticsearch", "saved": saved, "message": "已保存 Elasticsearch 路径（start.ps1 / 服务管理共用，无需改脚本）"}

    if sid in ("kibana", "kb"):
        err = _validate_stack_script(path, script, "kibana.bat")
        if err:
            return {"ok": False, "error": err}
        if path:
            bat = Path(path) / "bin" / "kibana.bat"
            if not script and path and not bat.is_file():
                return {"ok": False, "error": f"未找到 {bat}，请确认是 Kibana 安装根目录（含 bin\\kibana.bat）"}
        saved = _save_stack_paths({
            "kibana_home": path,
            "kibana_script": script,
        })
        return {"ok": True, "service": "kibana", "saved": saved, "message": "已保存 Kibana 路径（start.ps1 / 服务管理共用，无需改脚本）"}

    return {"ok": False, "error": f"服务 {service_id} 不支持修改路径"}


def _norm_service_id(service_id: str) -> str:
    raw = (service_id or "").strip()
    sid = raw.lower()
    alias = {
        "es": "elasticsearch", "kb": "kibana", "web": "analysis", "app": "analysis",
        "cache": "redis", "db": "mysql",
        "核心服务": "analysis", "分析服务": "analysis",
        "存储服务": "elasticsearch", "elasticsearch": "elasticsearch",
        "后台服务": "kibana", "kibana": "kibana",
        "高速缓存": "redis", "redis": "redis",
        "数据库": "mysql", "mysql": "mysql",
    }
    return alias.get(raw, alias.get(sid, sid))


_LOG_SERVICE_NAMES: Tuple[Tuple[str, str], ...] = (
    ("analysis", "分析服务"),
    ("redis", "Redis"),
    ("mysql", "MySQL"),
)

_LOG_FILE_EXTS = {".log", ".out", ".err"}
_LOG_DENY_NAMES = {
    "db_config.json",
    "ai_config.json",
    "platform_settings.json",
    "platform_secret.key",
    "redis_config.json",
    "es_config.json",
    "credentials.json",
    "secrets.json",
    ".env",
}
_LOG_DENY_SUFFIXES = {
    ".key", ".pem", ".p12", ".pfx", ".jks", ".kdbx",
    ".sqlite", ".db", ".json", ".yml", ".yaml",
    ".ini", ".conf", ".cnf", ".env", ".ps1", ".bat", ".cmd", ".exe",
}


def _looks_like_log_file(path: Path, *, saved: bool = False) -> bool:
    name = path.name.lower()
    suf = path.suffix.lower()
    if name in _LOG_DENY_NAMES or name.startswith(".env") or "platform_secret" in name:
        return False
    if suf in _LOG_DENY_SUFFIXES and not (suf == ".json" and not saved):
        return False
    if suf in _LOG_FILE_EXTS:
        return True
    if suf == ".txt" and "log" in name:
        return True
    if suf == ".json" and not saved:
        parent = path.parent.name.lower()
        return parent in ("logs", "log") and name not in _LOG_DENY_NAMES
    return False


def log_path_error(raw: str) -> Optional[str]:
    """日志路径白名单：文件须为日志类扩展名，且不得指向配置/密钥。"""
    s = (raw or "").strip().strip('"')
    if not s:
        return None
    try:
        p = Path(s).resolve()
    except Exception:
        return "日志路径无效"
    name = p.name.lower()
    if name in _LOG_DENY_NAMES or name.startswith(".env") or "platform_secret" in name:
        return "不允许将配置或密钥文件作为日志"
    if p.is_dir():
        return None
    if p.is_file() or p.suffix:
        if not _looks_like_log_file(p, saved=True):
            return "仅允许日志文件（.log / .out / .err，或文件名含 log 的 .txt）"
    return None


def _save_log_paths(sid: str, path: str) -> None:
    import json as _json
    cur = _load_stack_paths()
    logs = dict(cur.get("logs") or {}) if isinstance(cur.get("logs"), dict) else {}
    key = _norm_service_id(sid)
    if not key:
        return
    logs[key] = str(path or "").strip()
    cur["logs"] = logs
    fp = _stack_paths_file()
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(_json.dumps(cur, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def get_saved_log_path(service_id: str) -> str:
    sid = _norm_service_id(service_id)
    logs = _load_stack_paths().get("logs")
    if not isinstance(logs, dict):
        return ""
    return str(logs.get(sid) or "").strip()


def list_saved_log_paths() -> Dict[str, str]:
    return {sid: get_saved_log_path(sid) for sid, _n in _LOG_SERVICE_NAMES}


def update_all_log_paths(logs: Dict[str, Any]) -> Dict[str, Any]:
    """批量保存服务日志路径。空字符串表示该服务改回自动探测。"""
    if not isinstance(logs, dict):
        return {"ok": False, "error": "service_logs 格式无效"}
    names = {k: n for k, n in _LOG_SERVICE_NAMES}
    pending: List[Tuple[str, str]] = []
    errors: List[str] = []
    for raw_id, raw_path in logs.items():
        sid = _norm_service_id(str(raw_id))
        if sid not in names:
            continue
        path = str(raw_path or "").strip().strip('"')
        if path:
            err = log_path_error(path)
            if err:
                errors.append(f"{names[sid]}：{err}")
                continue
            p = Path(path)
            if not p.exists():
                errors.append(f"{names[sid]}：路径不存在 {path}")
                continue
            if not (p.is_file() or p.is_dir()):
                errors.append(f"{names[sid]}：请填写日志文件或所在目录")
                continue
            path = str(p.resolve())
        pending.append((sid, path))
    if errors:
        return {"ok": False, "error": "；".join(errors)}
    for sid, path in pending:
        _save_log_paths(sid, path)
    return {"ok": True, "logs": list_saved_log_paths()}


def list_log_path_status(*, detect: bool = False) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    for sid, name in _LOG_SERVICE_NAMES:
        saved = get_saved_log_path(sid)
        rec: Dict[str, Any] = {
            "id": sid,
            "name": name,
            "saved": saved,
            "detected": "",
            "file": "",
            "exists": bool(saved) and Path(saved).exists(),
            "source": "saved" if saved else "auto",
        }
        if detect:
            pack = read_service_logs(sid, lines=8, discover=True, persist=False)
            rec["detected"] = str(pack.get("file") or "")
            rec["file"] = rec["detected"] or saved
            rec["exists"] = bool(rec["file"] and Path(rec["file"]).exists())
            rec["source"] = pack.get("log_path_source") or rec["source"]
        items.append(rec)
    return {"ok": True, "items": items, "logs": {it["id"]: it["saved"] for it in items}}


def update_service_log_path(service_id: str, path: str = "") -> Dict[str, Any]:
    """保存服务日志路径（文件或目录）。空字符串表示改回自动探测。"""
    sid = _norm_service_id(service_id)
    if sid not in ("analysis", "elasticsearch", "kibana", "redis", "mysql"):
        return {"ok": False, "error": f"未知服务: {service_id}"}
    path = (path or "").strip().strip('"')
    if path:
        err = log_path_error(path)
        if err:
            return {"ok": False, "error": err}
        p = Path(path)
        if not p.exists():
            return {"ok": False, "error": f"路径不存在: {path}"}
        if not (p.is_file() or p.is_dir()):
            return {"ok": False, "error": "请填写日志文件或所在目录"}
        path = str(p.resolve())
    _save_log_paths(sid, path)
    return {
        "ok": True,
        "service": sid,
        "log_path": path,
        "message": "已保存日志路径" if path else "已清除，下次将自动探测",
    }


def _candidate_roots() -> List[Path]:
    roots: List[Path] = []
    extra: List[str] = []
    try:
        extra.append(str(install_root() / "hj"))
        extra.append(str(install_root().parent / "hj"))
        extra.append(str(install_root().parent))
    except Exception:
        pass
    for raw in (
        *extra,
        r"D:\GeRen\AI\hj",
        r"C:\elastic",
        r"C:\Program Files\Elastic",
        r"D:\phpstudy_pro\Extensions",
        r"C:\phpstudy_pro\Extensions",
        str(Path.home()),
    ):
        try:
            p = Path(raw)
            if p.is_dir():
                roots.append(p.resolve())
        except Exception:
            pass
    out, seen = [], set()
    for p in roots:
        key = str(p).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _looks_like_home(home: Path, bat_name: str) -> bool:
    return (home / "bin" / bat_name).is_file()


def _discover_home(kind: str, hint: str = "") -> Optional[Path]:
    bat = "elasticsearch.bat" if kind == "elasticsearch" else "kibana.bat"
    if hint:
        p = Path(hint)
        if _looks_like_home(p, bat):
            return p.resolve()
    needle = "elasticsearch" if kind == "elasticsearch" else "kibana"
    for root in _candidate_roots():
        try:
            for child in root.iterdir():
                if not child.is_dir():
                    continue
                name = child.name.lower()
                if needle not in name:
                    continue
                if _looks_like_home(child, bat):
                    return child.resolve()
                try:
                    for nested in child.iterdir():
                        if nested.is_dir() and needle in nested.name.lower() and _looks_like_home(nested, bat):
                            return nested.resolve()
                except OSError:
                    pass
        except OSError:
            pass
    return None


def _es_port_from_cfg() -> int:
    try:
        from .cache_config import es_config

        hosts = (es_config() or {}).get("hosts") or []
        if hosts:
            h0 = str(hosts[0])
            tail = h0.rsplit(":", 1)[-1].rstrip("/")
            if tail.isdigit():
                return int(tail)
    except Exception:
        pass
    return 9200


def stack_status() -> Dict[str, Any]:
    hint_es, hint_kb = _cfg_homes()
    es_home = _discover_home("elasticsearch", hint_es)
    kb_home = _discover_home("kibana", hint_kb)
    es_port = _es_port_from_cfg()
    kb_port = 5601
    sp = _load_stack_paths()
    es_bat = str(sp.get("elasticsearch_script") or "").strip()
    if not es_bat and es_home:
        es_bat = str(es_home / "bin" / "elasticsearch.bat")
    kb_bat = str(sp.get("kibana_script") or "").strip()
    if not kb_bat and kb_home:
        kb_bat = str(kb_home / "bin" / "kibana.bat")
    return {
        "es_home": str(es_home) if es_home else (hint_es or ""),
        "es_bat": es_bat,
        "es_found": bool(es_home) or (bool(es_bat) and Path(es_bat).is_file()),
        "es_port": es_port,
        "es_up": _port_listening(es_port),
        "es_configured": bool(hint_es or sp.get("elasticsearch_home")),
        "kibana_home": str(kb_home) if kb_home else (hint_kb or ""),
        "kibana_bat": kb_bat,
        "kibana_found": bool(kb_home) or (bool(kb_bat) and Path(kb_bat).is_file()),
        "kibana_port": kb_port,
        "kibana_up": _port_listening(kb_port),
        "kibana_configured": bool(hint_kb or sp.get("kibana_home")),
        "kibana_url": f"http://127.0.0.1:{kb_port}",
    }


def _start_bat(home: Path, bat_name: str, script_override: str = "") -> Dict[str, Any]:
    bat = Path(script_override) if script_override else (home / "bin" / bat_name)
    if script_override:
        err = _validate_stack_script(str(home) if home else "", script_override, bat_name)
        if err:
            return {"ok": False, "error": err}
        bat = Path(script_override)
    if not bat.is_file():
        return {"ok": False, "error": f"missing {bat}"}
    try:
        cwd = str(bat.parent)
        title = "Elasticsearch" if "elastic" in bat_name.lower() else (
            "Kibana" if "kibana" in bat_name.lower() else bat.stem
        )
        if os.name == "nt":
            # 新控制台 + cmd /k：完整保留 .bat 启动日志（勿重定向 stdout）
            # 列表参数传 bat，避免 shell 注入
            CREATE_NEW_CONSOLE = 0x00000010
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            subprocess.Popen(
                ["cmd.exe", "/k", str(bat.resolve())],
                cwd=cwd,
                close_fds=True,
                creationflags=CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
            )
        else:
            subprocess.Popen([str(bat)], cwd=cwd, close_fds=True)
        return {"ok": True, "bat": str(bat), "mode": "console", "title": title}
    except Exception as e:
        return {"ok": False, "error": str(e), "bat": str(bat)}


def _kill_port_listeners(port: int) -> Dict[str, Any]:
    """结束占用端口的进程（Windows）。"""
    killed: List[int] = []
    errors: List[str] = []
    if os.name != "nt":
        return {"ok": False, "error": "only windows supported", "killed": killed}
    try:
        r = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    f"$pids=@(); "
                    f"try {{ $pids=@(Get-NetTCPConnection -LocalPort {int(port)} -State Listen "
                    f"-ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique) }} catch {{}}; "
                    f"foreach($p in $pids){{ if($p -and $p -ne 0){{ Stop-Process -Id $p -Force -ErrorAction SilentlyContinue; Write-Output $p }} }}"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if line.isdigit():
                killed.append(int(line))
    except Exception as e:
        errors.append(str(e))
    time.sleep(0.6)
    return {"ok": True, "killed": killed, "errors": errors, "still_up": _port_listening(port)}


def _http_ok(url: str, *, timeout: float = 2.0, headers: Optional[Dict[str, str]] = None) -> Tuple[bool, str]:
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            code = getattr(resp, "status", 200) or 200
            return True, f"HTTP {code}"
    except urllib.error.HTTPError as e:
        # 401/302 等也说明服务在响应
        if e.code and int(e.code) < 500:
            return True, f"HTTP {e.code}"
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, type(e).__name__


def _probe_es(port: int) -> Tuple[str, str]:
    """返回 (health, detail)。health: ok|degraded|down|unknown"""
    if not _port_listening(port):
        return "down", f"端口 {port} 未监听"
    try:
        from . import es_client

        es_client.reset()
        if es_client.is_available():
            try:
                info = es_client.get_client().info()
                ver = (info.get("version") or {}).get("number") or "?"
                name = info.get("cluster_name") or "elasticsearch"
                return "ok", f"{name} · v{ver}"
            except Exception as e:
                return "degraded", f"已配置但 info 失败: {e}"[:160]
        err = getattr(es_client, "_last_error", "") or "业务客户端未连接"
        # 端口在听但客户端失败 → 异常
        return "degraded", str(err)[:160]
    except Exception as e:
        ok, detail = _http_ok(f"https://127.0.0.1:{port}", timeout=2.0)
        if ok:
            return "ok", detail
        return "degraded", f"探活失败（{type(e).__name__}）"


def _probe_kibana(port: int) -> Tuple[str, str]:
    if not _port_listening(port):
        return "down", f"端口 {port} 未监听"
    ok, detail = _http_ok(
        f"http://127.0.0.1:{port}/api/status",
        timeout=2.5,
        headers={"kbn-xsrf": "true"},
    )
    if ok:
        return "ok", detail
    ok2, detail2 = _http_ok(f"http://127.0.0.1:{port}", timeout=2.0)
    if ok2:
        return "ok", detail2
    return "degraded", f"端口在听但探活失败（{detail}）"


def _probe_redis() -> Tuple[str, str, Dict[str, Any]]:
    meta: Dict[str, Any] = {"id": "redis", "name": "Redis", "can_restart": False}
    try:
        from .cache_config import redis_config

        cfg = redis_config() or {}
        meta["path"] = f"{cfg.get('host') or '127.0.0.1'}:{cfg.get('port') or 6379}"
        meta["port"] = int(cfg.get("port") or 6379)
        meta["enabled"] = bool(cfg.get("enabled", True))
        if not meta["enabled"]:
            return "unknown", "配置中已禁用", meta
    except Exception:
        meta["path"] = "127.0.0.1:6379"
        meta["port"] = 6379
    try:
        from .redis_client import is_available, get_client

        if is_available():
            try:
                get_client().ping()
            except Exception:
                pass
            return "ok", "已连接", meta
        up = _port_listening(int(meta.get("port") or 6379))
        if up:
            return "degraded", "端口在听但业务连接失败", meta
        return "down", "不可用", meta
    except Exception as e:
        return "unknown", str(e)[:120], meta


def _probe_mysql() -> Tuple[str, str, Dict[str, Any]]:
    meta: Dict[str, Any] = {"id": "mysql", "name": "MySQL", "can_restart": False}
    host, port = "127.0.0.1", 3306
    try:
        from . import mysql_db

        cfg = mysql_db.load_db_config() if hasattr(mysql_db, "load_db_config") else {}
        host = str(cfg.get("host") or host)
        port = int(cfg.get("port") or port)
        meta["path"] = f"{host}:{port}"
        meta["port"] = port
        if mysql_db.mysql_ready():
            return "ok", "已连接", meta
        if _port_listening(port):
            return "degraded", "端口在听但业务连接失败", meta
        return "down", "不可用", meta
    except Exception as e:
        meta["path"] = f"{host}:{port}"
        meta["port"] = port
        if _port_listening(port):
            return "degraded", f"探活异常: {e}"[:120], meta
        return "unknown", str(e)[:120], meta


def list_services(*, force: bool = False) -> Dict[str, Any]:
    """管理面板用：各服务路径、健康状态、是否可单独重启。"""
    global _LIST_CACHE, _LIST_CACHE_AT
    now = time.time()
    if not force and _LIST_CACHE is not None and (now - _LIST_CACHE_AT) < _LIST_TTL:
        cached = _LIST_CACHE
        return {
            "ok": cached.get("ok", True),
            "services": [dict(s) for s in (cached.get("services") or [])],
            "summary": dict(cached.get("summary") or {}),
            "checked_at": cached.get("checked_at"),
            "cached": True,
        }

    root = install_root()
    port = detect_port()
    services: List[Dict[str, Any]] = []

    # 分析服务（本进程）
    services.append({
        "id": "analysis",
        "name": "分析服务",
        "role": "Web / API",
        "path": str(root),
        "script": str(start_script()),
        "port": port,
        "pid": os.getpid(),
        "health": "ok",
        "health_label": "正常",
        "detail": f"进程 PID {os.getpid()} · 端口 {port}（路径随程序目录自动，不可改）",
        "can_restart": True,
        "path_editable": False,
        "url": f"http://127.0.0.1:{port}",
    })

    # Elasticsearch / Kibana 已从默认运维面移除（检索与 IOC 走 MySQL）
    # 不再调用 stack_status()，避免每次探测 ES/Kibana 目录拖慢页面

    # Redis / MySQL：状态展示，不提供一键重启（路径因安装方式差异大）
    rh, rd, rm = _probe_redis()
    services.append({
        **rm,
        "role": "缓存",
        "health": rh,
        "health_label": _health_label(rh),
        "detail": rd,
        "script": "",
        "url": "",
    })
    mh, md, mm = _probe_mysql()
    services.append({
        **mm,
        "role": "数据库",
        "health": mh,
        "health_label": _health_label(mh),
        "detail": md,
        "script": "",
        "url": "",
    })

    summary = {
        "ok": sum(1 for s in services if s.get("health") == "ok"),
        "abnormal": sum(1 for s in services if s.get("health") in ("down", "degraded", "not_found")),
        "total": len(services),
    }
    out = {"ok": True, "services": services, "summary": summary, "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    _LIST_CACHE = {
        "ok": out["ok"],
        "services": [dict(s) for s in services],
        "summary": dict(summary),
        "checked_at": out["checked_at"],
    }
    _LIST_CACHE_AT = now
    return out


def _health_label(h: str) -> str:
    return {
        "ok": "正常",
        "down": "已停止",
        "degraded": "异常",
        "not_found": "未安装",
        "unknown": "未知",
    }.get(h, h or "未知")


def ensure_es_kibana(*, wait_es_sec: float = 45.0) -> Dict[str, Any]:
    st = stack_status()
    out: Dict[str, Any] = {
        "ok": True,
        "before": dict(st),
        "es_action": "skip",
        "kibana_action": "skip",
        "es_up": st["es_up"],
        "kibana_up": st["kibana_up"],
    }
    if st["es_up"]:
        out["es_action"] = "already_up"
    elif st["es_found"]:
        r = _start_bat(Path(st["es_home"] or "."), "elasticsearch.bat", st.get("es_bat") or "")
        out["es_action"] = "started" if r.get("ok") else "failed"
        out["es_start"] = r
        deadline = time.time() + max(5.0, float(wait_es_sec))
        while time.time() < deadline:
            if _port_listening(int(st["es_port"])):
                break
            time.sleep(1.5)
        out["es_up"] = _port_listening(int(st["es_port"]))
    else:
        out["es_action"] = "not_found"
        out["ok"] = False

    st2 = stack_status()
    if st2["kibana_up"]:
        out["kibana_action"] = "already_up"
        out["kibana_up"] = True
    elif st2["kibana_found"]:
        r = _start_bat(Path(st2["kibana_home"] or "."), "kibana.bat", st2.get("kibana_bat") or "")
        out["kibana_action"] = "started" if r.get("ok") else "failed"
        out["kibana_start"] = r
        deadline = time.time() + 20.0
        while time.time() < deadline:
            if _port_listening(int(st2["kibana_port"])):
                break
            time.sleep(1.5)
        out["kibana_up"] = _port_listening(int(st2["kibana_port"]))
    else:
        out["kibana_action"] = "not_found"

    out["after"] = stack_status()
    return out


def service_info() -> Dict[str, Any]:
    root = install_root()
    script = start_script()
    port = detect_port()
    stack = stack_status()
    return {
        "ok": True,
        "root": str(root),
        "start_script": str(script),
        "start_script_exists": script.is_file(),
        "ensure_stack_script": str(ensure_stack_script()),
        "ensure_stack_script_exists": ensure_stack_script().is_file(),
        "port": port,
        "pid": os.getpid(),
        "python": sys.executable,
        "cwd": str(Path.cwd()),
        "reload_env": os.getenv("FORENSIC_UVICORN_RELOAD") or "",
        "stack": stack,
        **{f"stack_{k}": v for k, v in stack.items()},
    }


def _ps_escape(s: str) -> str:
    return str(s).replace("'", "''")


def _spawn_ps1(script: Path, *, delay_sec: float = 0.8) -> None:
    root = install_root()
    creationflags = 0
    if os.name == "nt":
        creationflags = 0x00000008 | 0x00000200 | 0x08000000

    def _run():
        time.sleep(max(0.2, float(delay_sec)))
        try:
            subprocess.Popen(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script),
                ],
                cwd=str(root),
                close_fds=True,
                creationflags=creationflags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f"[service_control] spawn failed: {e!r}")

    threading.Thread(target=_run, name="service-restart", daemon=True).start()


def schedule_restart_analysis(*, delay_sec: float = 0.8, no_reload: bool = False) -> Dict[str, Any]:
    """仅重启分析服务（不连带 ES/Kibana）。"""
    info = service_info()
    root = install_root()
    port = int(info["port"])
    start = start_script()
    nr = " -NoReload" if no_reload else ""
    tmp = root / "config" / f"_restart_analysis_{os.getpid()}.ps1"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    content = f"""$ErrorActionPreference = 'Continue'
Start-Sleep -Seconds 2
Set-Location -LiteralPath '{_ps_escape(str(root))}'
if (Test-Path -LiteralPath '{_ps_escape(str(start))}') {{
  & '{_ps_escape(str(start))}' -Port {int(port)}{nr} -SkipStack
}} else {{
  $env:FORENSIC_UVICORN_RELOAD = '{"0" if no_reload else "1"}'
  python -m uvicorn server:app --host 0.0.0.0 --port {int(port)} --app-dir '{_ps_escape(str(root))}'
}}
"""
    tmp.write_text(content, encoding="utf-8")
    _spawn_ps1(tmp, delay_sec=delay_sec)
    return {
        "ok": True,
        "scheduled": True,
        "service": "analysis",
        "message": f"已安排重启分析服务（端口 {port}）",
        "restart_script": str(tmp),
        **info,
    }


def schedule_restart(*, delay_sec: float = 0.8, no_reload: bool = False) -> Dict[str, Any]:
    """兼容旧接口：等同于仅重启分析服务。"""
    return schedule_restart_analysis(delay_sec=delay_sec, no_reload=no_reload)


def restart_service(service_id: str, *, no_reload: bool = False) -> Dict[str, Any]:
    """按 id 单独重启：analysis | elasticsearch | kibana。"""
    sid = (service_id or "").strip().lower()
    if sid in ("analysis", "web", "app", "forensic"):
        return schedule_restart_analysis(no_reload=no_reload)

    stack = stack_status()
    if sid in ("elasticsearch", "es"):
        if not stack.get("es_found"):
            return {"ok": False, "error": "未找到 Elasticsearch 安装目录", "stack": stack}
        port = int(stack["es_port"])
        kill = _kill_port_listeners(port) if stack.get("es_up") else {"ok": True, "killed": [], "skipped": True}
        # ES 关停后可能还有残留 java，稍等再启
        time.sleep(1.0)
        started = _start_bat(Path(stack["es_home"] or "."), "elasticsearch.bat", stack.get("es_bat") or "")
        return {
            "ok": bool(started.get("ok")),
            "service": "elasticsearch",
            "message": "已重启 Elasticsearch" if started.get("ok") else (started.get("error") or "启动失败"),
            "kill": kill,
            "start": started,
            "stack": stack_status(),
        }

    if sid in ("kibana", "kb"):
        if not stack.get("kibana_found"):
            return {"ok": False, "error": "未找到 Kibana 安装目录", "stack": stack}
        port = int(stack["kibana_port"])
        kill = _kill_port_listeners(port) if stack.get("kibana_up") else {"ok": True, "killed": [], "skipped": True}
        time.sleep(0.8)
        started = _start_bat(Path(stack["kibana_home"] or "."), "kibana.bat", stack.get("kibana_bat") or "")
        return {
            "ok": bool(started.get("ok")),
            "service": "kibana",
            "message": "已重启 Kibana" if started.get("ok") else (started.get("error") or "启动失败"),
            "kill": kill,
            "start": started,
            "stack": stack_status(),
        }

    return {"ok": False, "error": f"不支持的服务: {service_id}（可选 analysis / elasticsearch / kibana）"}


def _decode_log_bytes(raw: bytes) -> str:
    if not raw:
        return ""
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp936"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _tail_file(path: Path, *, max_bytes: int = 220_000, max_lines: int = 500) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file(),
        "size": 0,
        "mtime": "",
        "text": "",
        "truncated": False,
    }
    if not path.is_file():
        return info
    try:
        st = path.stat()
        info["size"] = int(st.st_size)
        info["mtime"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
        with path.open("rb") as f:
            if st.st_size > max_bytes:
                f.seek(st.st_size - max_bytes)
                raw = f.read()
                cut = raw.find(b"\n")
                if 0 <= cut < len(raw) - 1:
                    raw = raw[cut + 1 :]
                info["truncated"] = True
            else:
                raw = f.read()
        text = _decode_log_bytes(raw).replace("\r\n", "\n").replace("\r", "\n")
        lines = text.split("\n")
        if len(lines) > max_lines:
            lines = lines[-max_lines:]
            info["truncated"] = True
        info["text"] = "\n".join(lines).rstrip() + ("\n" if lines else "")
        info["lines"] = len(lines)
    except Exception as e:
        info["error"] = str(e)
    return info


def _rank_log_files(paths: List[Path]) -> List[Path]:
    def score(p: Path) -> Tuple[int, float]:
        name = p.name.lower()
        pri = 50
        if name.startswith("gc"):
            pri = 10
        elif "deprecation" in name or "audit" in name:
            pri = 20
        elif name.endswith(".json"):
            pri = 30
        elif "elasticsearch" in name or "kibana" in name or name.endswith(".err"):
            pri = 90
        elif name.endswith(".log"):
            pri = 70
        try:
            mt = p.stat().st_mtime
        except Exception:
            mt = 0
        return (-pri, -mt)
    return sorted(paths, key=score)


def _collect_glob_logs(dirs: List[Path], patterns: Tuple[str, ...] = ("*.log", "*.out", "*.err")) -> List[Path]:
    found: List[Path] = []
    seen = set()
    for d in dirs:
        if not d or not d.is_dir():
            continue
        for pat in patterns:
            try:
                for p in d.glob(pat):
                    key = str(p.resolve()).lower()
                    if key in seen or not p.is_file():
                        continue
                    if not _looks_like_log_file(p):
                        continue
                    seen.add(key)
                    found.append(p)
            except Exception:
                continue
    return _rank_log_files(found)[:8]


def _yml_log_dirs(home: Path, names: Tuple[str, ...]) -> List[Path]:
    out: List[Path] = []
    for n in names:
        p = home / "config" / n
        if not p.is_file():
            p = home / n
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("#") or ":" not in s:
                continue
            key, _, val = s.partition(":")
            key = key.strip().lower()
            val = val.strip().strip("'\"")
            if not val:
                continue
            if key in ("path.logs", "logging.dest", "log_path") or "appender" in key and "file" in key:
                q = Path(val)
                if not q.is_absolute():
                    q = home / val
                out.append(q if q.is_dir() else q.parent)
    return out


def _analysis_log_candidates() -> List[Path]:
    root = install_root()
    names = [
        root / "config" / "uvicorn8000.log",
        root / "config" / "uvicorn.log",
        root / "logs" / "analysis.log",
        root / "analysis.log",
    ]
    extra = _collect_glob_logs([root / "logs", root / "config", root], ("*.log",))
    out: List[Path] = []
    seen = set()
    for p in names + extra:
        key = str(p.resolve()).lower() if p.exists() else str(p).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _es_log_candidates() -> List[Path]:
    st = stack_status()
    home = Path(st.get("es_home") or "")
    dirs = [home / "logs", home / "log"] + _yml_log_dirs(home, ("elasticsearch.yml",))
    return _collect_glob_logs(dirs, ("*.log", "*.json"))


def _kibana_log_candidates() -> List[Path]:
    found: List[Path] = []
    st = stack_status()
    home = Path(st.get("kibana_home") or "")
    if home.is_dir():
        for p in (home / "logs" / "kibana.log", home / "log" / "kibana.log"):
            if p.is_file():
                found.append(p)
    dirs = [home / "logs", home / "log", home / "data" / "log", home / "data" / "logs"]
    dirs += _yml_log_dirs(home, ("kibana.yml",))
    found.extend(_collect_glob_logs(dirs, ("*.log",)))
    out, seen = [], set()
    for p in found:
        try:
            key = str(p.resolve()).lower()
        except Exception:
            key = str(p).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def ensure_kibana_logfile() -> str:
    """只查找已有 Kibana 日志，不再改写 kibana.yml。"""
    st = stack_status()
    home = Path(st.get("kibana_home") or "")
    if not home.is_dir():
        return ""
    for p in (home / "logs" / "kibana.log", home / "log" / "kibana.log"):
        try:
            if p.is_file():
                return str(p.resolve())
        except Exception:
            continue
    return ""


def _persist_redis_conf_logfile(conf_path: str, logfile_value: str) -> bool:
    p = Path(conf_path or "")
    if not p.is_file():
        return False
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    lines = text.splitlines()
    out: List[str] = []
    found = False
    for line in lines:
        raw = line.strip()
        if raw.startswith("#"):
            out.append(line)
            continue
        key = raw.split(None, 1)[0].lower() if raw else ""
        if key == "logfile":
            out.append(f"logfile {logfile_value}")
            found = True
        else:
            out.append(line)
    if not found:
        if out and out[-1].strip():
            out.append("")
        out.append("# forensic-platform: enable file logs for service status page")
        out.append(f"logfile {logfile_value}")
        has_loglevel = any(
            (ln.strip().split() or [""])[0].lower() == "loglevel"
            for ln in out
            if ln.strip() and not ln.strip().startswith("#")
        )
        if not has_loglevel:
            out.append("loglevel notice")
    try:
        p.write_text("\n".join(out) + "\n", encoding="utf-8")
        return True
    except Exception:
        return False


def ensure_redis_logfile() -> str:
    """只读取 Redis 已配置的 logfile，不改写 redis.conf。"""
    try:
        from .redis_client import get_client, is_available
        if not is_available():
            return ""
        r = get_client()
        cfg = r.config_get("logfile") or {}
        direc = r.config_get("dir") or {}
        logfile = str(cfg.get("logfile") or "").strip()
        if not logfile:
            return ""
        basedir = str(direc.get("dir") or "").strip()
        p = Path(logfile)
        if not p.is_absolute() and basedir:
            p = Path(basedir) / logfile
        return str(p)
    except Exception:
        return ""


def _redis_log_candidates() -> List[Path]:
    found: List[Path] = []
    homes: List[Path] = []
    ensured = ensure_redis_logfile()
    if ensured:
        found.append(Path(ensured))
    try:
        from .redis_client import get_client, is_available
        if is_available():
            r = get_client()
            cfg = r.config_get("logfile") or {}
            direc = r.config_get("dir") or {}
            logfile = str(cfg.get("logfile") or "").strip()
            basedir = str(direc.get("dir") or "").strip()
            if basedir:
                homes.append(Path(basedir))
            try:
                info = r.info("server") or {}
                cf = str(info.get("config_file") or "").strip()
                if cf:
                    homes.append(Path(cf).parent)
            except Exception:
                pass
            if logfile:
                p = Path(logfile)
                if not p.is_absolute() and basedir:
                    p = Path(basedir) / logfile
                found.append(p)
    except Exception:
        pass
    extras = [
        Path(r"D:\phpstudy_pro\Extensions\redis3.0.504"),
        Path(r"D:\phpstudy_pro\Extensions\Redis3.0.504"),
        Path(r"C:\Program Files\Redis"),
        Path(r"C:\Redis"),
        install_root() / "redis",
    ]
    homes.extend(extras)
    search_dirs: List[Path] = []
    for h in homes:
        if not h:
            continue
        search_dirs.extend([h, h / "Logs", h / "logs", h / "log"])
        found.extend([
            h / "Logs" / "redis_log.txt",
            h / "logs" / "redis_log.txt",
            h / "redis_log.txt",
            h / "redis.log",
            h / "server.log",
        ])
    found.extend(_collect_glob_logs(search_dirs, ("*.log", "*.txt", "*.out")))
    out, seen = [], set()
    for p in found:
        name = p.name.lower()
        if "uvicorn" in name or "elasticsearch" in name or "kibana" in name:
            continue
        try:
            key = str(p.resolve()).lower()
        except Exception:
            key = str(p).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _redis_live_log() -> str:
    """phpstudy Redis 默认 logfile 为空（只打控制台），用 INFO 生成可查看的运行日志。"""
    lines: List[str] = []
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        from .redis_client import get_client, is_available
        if not is_available():
            return f"[{now}] Redis 未连接"
        r = get_client()
        srv = r.info("server") or {}
        cli = r.info("clients") or {}
        mem = r.info("memory") or {}
        st = r.info("stats") or {}
        pers = r.info("persistence") or {}
        ks = r.info("keyspace") or {}
        cfg = r.config_get("logfile") or {}
        direc = r.config_get("dir") or {}
        logfile = str(cfg.get("logfile") or "").strip()
        basedir = str(direc.get("dir") or "").strip()
        pid = srv.get("process_id")
        started = ""
        try:
            import psutil  # type: ignore
            if pid:
                started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(psutil.Process(int(pid)).create_time()))
        except Exception:
            started = ""
        last_save = pers.get("rdb_last_save_time")
        last_save_s = ""
        try:
            if last_save:
                last_save_s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(last_save)))
        except Exception:
            last_save_s = str(last_save or "")
        lines.append(f"[{now}] Redis 运行日志（实时 INFO）")
        lines.append(f"version     : {srv.get('redis_version') or '-'}")
        lines.append(f"os          : {(srv.get('os') or '').strip() or '-'}")
        lines.append(f"pid         : {pid or '-'}")
        lines.append(f"started_at  : {started or '-'}")
        lines.append(f"uptime      : {srv.get('uptime_in_seconds')}s")
        lines.append(f"config_file : {srv.get('config_file') or '-'}")
        lines.append(f"dir         : {basedir or '-'}")
        lines.append(f"logfile     : {logfile or '（未配置，phpstudy 默认只输出到控制台）'}")
        lines.append(f"bind/port   : {srv.get('tcp_port') or '-'}")
        lines.append(f"clients     : {cli.get('connected_clients')}")
        lines.append(f"memory      : used={mem.get('used_memory_human') or '-'}  peak={mem.get('used_memory_peak_human') or '-'}")
        lines.append(f"commands    : total={st.get('total_commands_processed')}  ops/s={st.get('instantaneous_ops_per_sec')}")
        lines.append(f"net         : in={st.get('total_net_input_bytes')}  out={st.get('total_net_output_bytes')}")
        lines.append(f"hits/miss   : {st.get('keyspace_hits')}/{st.get('keyspace_misses')}")
        lines.append(f"expired/evict: {st.get('expired_keys')}/{st.get('evicted_keys')}")
        lines.append(f"rdb         : last_save={last_save_s or '-'}  changes={pers.get('rdb_changes_since_last_save')}")
        if ks:
            for dbn, meta in ks.items():
                if isinstance(meta, dict):
                    lines.append(f"keyspace    : {dbn} keys={meta.get('keys')} expires={meta.get('expires')} avg_ttl={meta.get('avg_ttl')}")
                else:
                    lines.append(f"keyspace    : {dbn} {meta}")
        else:
            lines.append("keyspace    : (empty)")
        try:
            slow = r.slowlog_get(12) or []
            if slow:
                lines.append("slowlog     :")
                for it in slow:
                    cmd = it.get("command") if isinstance(it, dict) else it
                    lines.append("  " + str(cmd)[:220])
            else:
                lines.append("slowlog     : (empty)")
        except Exception as e:
            lines.append(f"slowlog     : {e}")
        if not logfile:
            lines.append("")
            lines.append("说明：当前进程尚未写入文件日志（phpstudy Redis 3.x 需重启后才读取 redis.conf 的 logfile）。")
            lines.append("已尝试在 redis.conf 写入 logs/redis.log。重启 Redis 后「查看日志」会自动读取该文件。")
            lines.append("以上为连接后采集的实时运行信息。")
        return "\n".join(lines) + "\n"
    except Exception as e:
        return f"[{now}] 读取 Redis 运行信息失败: {e}\n"


def _mysql_log_candidates() -> List[Path]:
    found: List[Path] = []
    conn = None
    try:
        from . import mysql_db
        if mysql_db.mysql_ready():
            conn = mysql_db.connect_mysql()
            cur = conn.cursor()
            cur.execute("SHOW VARIABLES LIKE 'log_error'")
            row = cur.fetchone() or {}
            val = (row.get("Value") if isinstance(row, dict) else (row[1] if row else "")) or ""
            if val:
                found.append(Path(str(val)))
            cur.execute("SHOW VARIABLES LIKE 'datadir'")
            row = cur.fetchone() or {}
            datadir = (row.get("Value") if isinstance(row, dict) else (row[1] if row else "")) or ""
            if datadir:
                found.extend(_collect_glob_logs([Path(str(datadir))], ("*.err", "*.log")))
    except Exception:
        pass
    finally:
        if conn is not None:
            try:
                from . import mysql_db
                mysql_db._pool_release(conn)
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
    extras = [
        Path(r"D:\phpstudy_pro\Extensions\MySQL5.7.26\data"),
        Path(r"C:\ProgramData\MySQL"),
        Path(r"C:\Program Files\MySQL"),
    ]
    found.extend(_collect_glob_logs(extras, ("*.err", "*.log")))
    out, seen = [], set()
    for p in found:
        try:
            key = str(p.resolve()).lower()
        except Exception:
            key = str(p).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _runtime_notes(sid: str) -> List[str]:
    notes: List[str] = []
    if sid == "redis":
        try:
            from .redis_client import get_client, is_available
            if is_available():
                info = get_client().info("server") or {}
                notes.append(
                    f"Redis {info.get('redis_version') or ''}  "
                    f"uptime={info.get('uptime_in_seconds')}s  "
                    f"os={info.get('os') or ''}".strip()
                )
                try:
                    slow = get_client().slowlog_get(8) or []
                    if slow:
                        notes.append("Slowlog:")
                        for it in slow:
                            cmd = it.get("command") if isinstance(it, dict) else it
                            notes.append("  " + str(cmd)[:180])
                except Exception:
                    pass
        except Exception as e:
            notes.append(f"Redis INFO 失败: {e}")
    if sid == "mysql":
        try:
            from . import mysql_db
            st = mysql_db.get_status() if hasattr(mysql_db, "get_status") else {}
            notes.append(f"MySQL backend={st.get('backend') or ''} ver={st.get('version') or ''} ok={st.get('ok')}")
        except Exception:
            pass
    return [n for n in notes if n]


def _pid_listening(port: int) -> Optional[int]:
    port = int(port or 0)
    if port <= 0:
        return None
    try:
        import psutil  # type: ignore
        for c in psutil.net_connections(kind="inet"):
            try:
                if c.status == "LISTEN" and c.laddr and int(c.laddr.port) == port and c.pid:
                    return int(c.pid)
            except Exception:
                continue
    except Exception:
        pass
    return None


def _service_pid(sid: str) -> Optional[int]:
    sid = _norm_service_id(sid)
    if sid == "analysis":
        return os.getpid()
    if sid == "redis":
        try:
            from .redis_client import get_client, is_available
            if is_available():
                pid = (get_client().info("server") or {}).get("process_id")
                if pid:
                    return int(pid)
        except Exception:
            pass
        return _pid_listening(6379)
    if sid == "mysql":
        try:
            from . import mysql_db
            cfg = mysql_db.load_db_config() if hasattr(mysql_db, "load_db_config") else {}
            return _pid_listening(int(cfg.get("port") or 3306))
        except Exception:
            return _pid_listening(3306)
    st = stack_status()
    if sid == "elasticsearch":
        return _pid_listening(int(st.get("es_port") or 9200))
    if sid == "kibana":
        return _pid_listening(int(st.get("kibana_port") or 5601))
    return None


def _proc_log_candidates(pid: Optional[int]) -> List[Path]:
    if not pid:
        return []
    found: List[Path] = []
    homes: List[Path] = []
    try:
        import psutil  # type: ignore
        p = psutil.Process(int(pid))
        try:
            for f in p.open_files() or []:
                path = Path(getattr(f, "path", "") or "")
                if path.is_file() and _looks_like_log_file(path):
                    found.append(path)
        except Exception:
            pass
        starts: List[Path] = []
        try:
            starts.append(Path(p.exe()).parent)
        except Exception:
            pass
        try:
            starts.append(Path(p.cwd()))
        except Exception:
            pass
        for s in starts:
            cur = s
            for _ in range(4):
                if not cur or len(cur.parts) <= 2:
                    break
                homes.append(cur)
                nxt = cur.parent
                if nxt == cur:
                    break
                cur = nxt
    except Exception:
        return found
    dirs: List[Path] = []
    seen_d = set()
    for h in homes:
        if not h:
            continue
        for d in (h, h / "logs", h / "log", h / "Logs", h / "data" / "logs", h / "data" / "log"):
            key = str(d).lower()
            if key in seen_d:
                continue
            seen_d.add(key)
            dirs.append(d)
    found.extend(_collect_glob_logs(dirs, ("*.log", "*.err", "*.out", "*.txt")))
    return found


def _expand_log_hint(hint: str) -> List[Path]:
    hint = (hint or "").strip().strip('"')
    if not hint or log_path_error(hint):
        return []
    p = Path(hint)
    if p.is_file():
        return [p] if _looks_like_log_file(p, saved=True) else []
    if p.is_dir():
        return _collect_glob_logs([p, p / "logs", p / "log", p / "Logs"], ("*.log", "*.err", "*.out", "*.txt"))
    return []


def _remember_log_path(sid: str, file_path: str, *, force: bool = False) -> None:
    if not file_path or log_path_error(file_path):
        return
    if not force and get_saved_log_path(sid):
        return
    try:
        _save_log_paths(sid, file_path)
    except Exception:
        pass


def read_service_logs(service_id: str, *, lines: int = 400, discover: bool = False, persist: Optional[bool] = None) -> Dict[str, Any]:
    """读取指定服务最近日志：优先已保存路径，否则自动探测进程/安装目录。

    persist=None 时：普通读取会记住首次找到的路径；discover 探测默认不覆盖已保存项。
    persist=False：只探测，不写入配置（系统设置「探测当前」用）。
    """
    sid = _norm_service_id(service_id)
    pickers = {
        "analysis": _analysis_log_candidates,
        "elasticsearch": _es_log_candidates,
        "kibana": _kibana_log_candidates,
        "redis": _redis_log_candidates,
        "mysql": _mysql_log_candidates,
    }
    fn = pickers.get(sid)
    if not fn:
        return {
            "ok": True,
            "service": sid or (service_id or ""),
            "file": "",
            "log_path": "",
            "log_path_source": "none",
            "text": f"未知服务: {service_id or '（空）'}。可查看：analysis / elasticsearch / kibana / redis / mysql。",
            "files": [],
            "notes": [],
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    configured = "" if discover else get_saved_log_path(sid)
    if configured and log_path_error(configured):
        configured = ""
    saved_ok = bool(configured) and (Path(configured).is_file() or Path(configured).is_dir())
    cands: List[Path] = []
    source = "auto"
    if saved_ok:
        cands.extend(_expand_log_hint(configured))
        source = "saved"
    cands.extend(fn())
    cands.extend(_proc_log_candidates(_service_pid(sid)))
    ordered: List[Path] = []
    seen = set()
    for p in cands:
        try:
            key = str(p.resolve()).lower() if p.exists() else str(p).lower()
        except Exception:
            key = str(p).lower()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(p)
    max_lines = max(50, min(2000, int(lines or 400)))
    files = []
    text = ""
    used = None
    for p in ordered:
        if p.is_file() and not _looks_like_log_file(p, saved=(source == "saved")):
            continue
        pack = _tail_file(p, max_lines=max_lines)
        files.append({k: pack.get(k) for k in ("path", "exists", "size", "mtime", "error", "truncated", "lines")})
        body = (pack.get("text") or "").strip()
        if body and used is None:
            used = pack
            text = pack.get("text") or ""
    do_persist = True if persist is None else bool(persist)
    if used and source != "saved":
        source = "auto"
        if do_persist:
            _remember_log_path(sid, str(used.get("path") or ""), force=bool(discover))
    elif used and source == "saved":
        source = "saved"
    notes = _runtime_notes(sid)
    if configured and not saved_ok:
        notes = [f"指定路径不存在，已改用自动探测：{configured}"] + notes
    if sid == "redis":
        live = _redis_live_log()
        if text:
            text = text.rstrip() + "\n\n----- 实时运行信息 -----\n" + live
        else:
            text = live
    elif not text and notes:
        text = "\n".join(notes) + "\n\n未找到日志文件。可在系统设置 → 数据路径填写日志路径，或点「自动探测」。"
    elif not text:
        text = "未找到日志文件。系统会按进程打开的文件、安装目录 logs/ 自动探测；也可在系统设置里指定日志路径。"
    found = str((used or {}).get("path") or "")
    return {
        "ok": True,
        "service": sid,
        "file": found,
        "log_path": configured or found,
        "log_path_source": source if found else ("saved" if configured else "auto"),
        "mtime": (used or {}).get("mtime") or "",
        "size": (used or {}).get("size") or 0,
        "truncated": bool((used or {}).get("truncated")),
        "files": files[:16],
        "notes": notes,
        "text": text,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
