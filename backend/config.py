import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
# Web 静态页跟程序走，不开放改路径
WEB_DIR = ROOT
ADMIN_WEB_DIR = ROOT / "rules_admin" / "static"

# 运行配置统一放 config/；读时优先新目录，找不到再回退根目录旧文件
CONFIG_DIR = ROOT / "config"
CONFIG_FILENAMES = (
    "platform_settings.json",
    "db_config.json",
    "db_config.example.json",
    "ai_config.json",
    "ai_config.example.json",
    "redis_config.json",
    "es_config.json",
)

# 数据目录：环境变量 > platform_settings.json > 默认（程序根下）
DATA_ROOT = ROOT
RULES_DIR = ROOT / "rules"
REPORTS_DIR = ROOT / "reports"
# 对外名称「结果目录」；历史目录名为 jg，启动时自动迁移
JG_DIR = ROOT / "结果"
BACKUP_DIR = ROOT / "rules" / ".bak"
IOC_DIR = ROOT / "ioc"
RESULTS_DIR_NAME = "结果"
LEGACY_JG_NAME = "jg"


def migrate_jg_to_results(path: Path) -> Path:
    """若路径仍是历史 jg，且同级尚无「结果」，则重命名为「结果」。

    若「结果」已存在且历史 jg 仍有待导入文件，则把文件并入「结果」。
    """
    try:
        p = Path(path).resolve()
    except Exception:
        return Path(path)

    parent = p.parent if p.name in (LEGACY_JG_NAME, RESULTS_DIR_NAME) else p
    legacy = parent / LEGACY_JG_NAME
    target = parent / RESULTS_DIR_NAME

    def _merge_legacy_into(dst: Path) -> None:
        if not legacy.is_dir() or legacy.resolve() == dst.resolve():
            return
        dst.mkdir(parents=True, exist_ok=True)
        for child in list(legacy.iterdir()):
            dest = dst / child.name
            if dest.exists():
                continue
            try:
                child.rename(dest)
            except Exception as e:
                print(f"[config] 合并结果目录文件失败 {child.name}: {e}")
        # 清空后尝试删除旧 jg（保留 .imported 若还在）
        try:
            remain = list(legacy.iterdir())
            if not remain:
                legacy.rmdir()
                print(f"[config] 已移除空目录 {legacy}")
            else:
                print(f"[config] 历史 jg 仍有 {len(remain)} 项，保留 {legacy}")
        except Exception:
            pass

    if p.name == LEGACY_JG_NAME:
        if not target.exists():
            try:
                p.rename(target)
                print(f"[config] 结果目录已迁移: {p} → {target}")
                return target.resolve()
            except Exception as e:
                print(f"[config] 结果目录迁移失败（继续使用 jg）: {e}")
                return p
        _merge_legacy_into(target)
        return target.resolve()

    if p.name == RESULTS_DIR_NAME or path == target:
        if legacy.is_dir():
            _merge_legacy_into(target if target.exists() else p)
        return (target if target.exists() else p).resolve()

    return p


def resolve_config_file(name: str, *, for_write: bool = False) -> Path:
    """配置文件路径：config/ 优先；仅旧根目录有文件时回退；写入一律进 config/。"""
    base = Path(name).name
    if not base or base in (".", ".."):
        raise ValueError("非法配置文件名")
    new_p = CONFIG_DIR / base
    old_p = ROOT / base
    if for_write:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        return new_p
    if new_p.is_file():
        return new_p
    if old_p.is_file():
        return old_p
    return new_p


def migrate_root_configs() -> List[str]:
    """把根目录遗留的 json 配置迁到 config/（目标已存在则跳过）。"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    moved: List[str] = []
    for name in CONFIG_FILENAMES:
        old = ROOT / name
        new = CONFIG_DIR / name
        if old.is_file() and not new.is_file():
            try:
                shutil.move(str(old), str(new))
                moved.append(name)
            except Exception as e:
                print(f"[config] migrate {name} failed: {e}")
        elif old.is_file() and new.is_file() and old.resolve() != new.resolve():
            # 两边都有：保留 config/，清掉根目录残留避免分叉
            try:
                old.unlink()
                moved.append(f"{name}(removed-root-dup)")
            except Exception as e:
                print(f"[config] remove root dup {name} failed: {e}")
    return moved


def _settings_path_file() -> Path:
    return resolve_config_file("platform_settings.json")


def _read_dir_settings() -> Dict[str, str]:
    p = _settings_path_file()
    if not p.is_file():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        out: Dict[str, str] = {}
        for k in ("dir_root", "dir_rules", "dir_reports", "dir_jg", "dir_backup", "dir_ioc"):
            v = str(data.get(k) or "").strip()
            if v:
                out[k] = v
        return out
    except Exception:
        return {}


def _resolve_data_dir(raw: str, default: Path, base: Optional[Path] = None) -> Path:
    s = (raw or "").strip()
    if not s:
        return default.resolve()
    p = Path(s)
    if not p.is_absolute():
        p = (base or ROOT) / p
    return p.resolve()


def program_default_dirs() -> Dict[str, str]:
    """当前程序根下的默认数据路径（搬家后自动跟程序走）。"""
    root = ROOT.resolve()
    rules = root / "rules"
    return {
        "dir_root": str(root),
        "dir_rules": str(rules),
        "dir_reports": str(root / "reports"),
        "dir_jg": str(root / RESULTS_DIR_NAME),
        "dir_backup": str(rules / ".bak"),
        "dir_ioc": str(root / "ioc"),
    }


_DIR_KEYS = ("dir_root", "dir_rules", "dir_reports", "dir_jg", "dir_backup", "dir_ioc")


def _path_missing(raw: str) -> bool:
    s = (raw or "").strip()
    if not s:
        return False
    try:
        p = Path(s)
        if not p.is_absolute():
            return False
        return not p.exists()
    except Exception:
        return True


def _under_prefix(path_s: str, prefix: str) -> bool:
    try:
        p = Path(path_s).resolve()
        root = Path(prefix).resolve()
        p.relative_to(root)
        return True
    except Exception:
        return False


def _remap_under(path_s: str, old_root: str, new_root: str) -> str:
    try:
        p = Path(path_s).resolve()
        old = Path(old_root).resolve()
        rel = p.relative_to(old)
        return str((Path(new_root).resolve() / rel))
    except Exception:
        return path_s


def _load_settings_dict() -> Dict[str, Any]:
    p = resolve_config_file("platform_settings.json")
    if not p.is_file():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_settings_dict(data: Dict[str, Any]) -> None:
    p = resolve_config_file("platform_settings.json", for_write=True)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def heal_stale_dir_settings(
    file_cfg: Dict[str, str],
    *,
    persist: bool = True,
    allow_missing_reset: bool = True,
) -> Dict[str, str]:
    """整包搬家后自动纠正数据路径。

    1) 记录 install_root；程序目录变更时，把仍挂在旧程序根下的绝对路径映射到新根。
    2) 启动时若旧绝对路径已不存在，回退到当前程序默认目录。
    外置数据盘（不在旧程序根下）保持不动；用户保存「将要新建」的路径时不因缺失而清掉。
    """
    cur_root = str(ROOT.resolve())
    data = _load_settings_dict()
    new_cfg = dict(file_cfg)
    changed = False
    prev = str(data.get("install_root") or "").strip()

    remapped_now = False
    if prev:
        try:
            prev_res = str(Path(prev).resolve())
        except Exception:
            prev_res = prev
        if prev_res != cur_root:
            for k in _DIR_KEYS:
                v = (new_cfg.get(k) or "").strip()
                if v and _under_prefix(v, prev_res):
                    new_cfg[k] = _remap_under(v, prev_res, cur_root)
                    changed = True
                    remapped_now = True
            print(f"[config] install moved {prev_res} → {cur_root}; remapped data paths")
            data["install_root"] = cur_root
            changed = True
    else:
        # 首次引入指纹：若 dir_root 仍指向「另一份程序目录」的绝对路径，按搬家处理
        old = (new_cfg.get("dir_root") or "").strip()
        if old:
            try:
                old_p = Path(old)
                if old_p.is_absolute():
                    old_res = str(old_p.resolve())
                    if old_res != cur_root and (
                        _path_missing(old)
                        or (old_p / "backend" / "config.py").is_file()
                        or (old_p / "server.py").is_file()
                    ):
                        for k in _DIR_KEYS:
                            v = (new_cfg.get(k) or "").strip()
                            if v and _under_prefix(v, old_res):
                                new_cfg[k] = _remap_under(v, old_res, cur_root)
                                remapped_now = True
                        if remapped_now:
                            print(f"[config] legacy app paths {old_res} → {cur_root}")
                            changed = True
            except Exception:
                pass
        data["install_root"] = cur_root
        changed = True

    # 仅在「判定为搬家」后，对仍失效的路径回退默认；不要清掉用户故意填写、尚未创建的新目录
    if allow_missing_reset and remapped_now:
        defaults = program_default_dirs()
        if _path_missing(new_cfg.get("dir_root") or ""):
            for k in _DIR_KEYS:
                new_cfg[k] = defaults[k]
            changed = True
            print(f"[config] missing dir_root after move → defaults under {cur_root}")
        else:
            for k in _DIR_KEYS:
                if k == "dir_root":
                    continue
                if _path_missing(new_cfg.get(k) or ""):
                    new_cfg[k] = defaults[k]
                    changed = True

    if changed and persist:
        try:
            for k in _DIR_KEYS:
                if k in new_cfg:
                    data[k] = new_cfg.get(k) or ""
            data["install_root"] = cur_root
            _save_settings_dict(data)
        except Exception as e:
            print(f"[config] persist healed paths failed: {e}")

    return new_cfg


def apply_data_dirs(override: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """刷新数据根 / 规则 / 报告 / 采集 / 备份 / IOC。Web 页面仍在程序目录。"""
    global DATA_ROOT, RULES_DIR, REPORTS_DIR, JG_DIR, BACKUP_DIR, IOC_DIR
    moved = migrate_root_configs()
    if moved:
        print(f"[config] migrated to config/: {', '.join(moved)}")
    file_cfg = _read_dir_settings()
    saving = override is not None
    file_cfg = heal_stale_dir_settings(
        file_cfg,
        persist=not saving,
        allow_missing_reset=not saving,
    )
    if override:
        for k, v in override.items():
            if k in _DIR_KEYS:
                file_cfg[k] = str(v or "").strip()
        try:
            data = _load_settings_dict()
            data["install_root"] = str(ROOT.resolve())
            _save_settings_dict(data)
        except Exception:
            pass

    def pick(env_key: str, setting_key: str, default: Path, base: Optional[Path] = None) -> Tuple[Path, str]:
        env = (os.getenv(env_key) or "").strip()
        if env:
            return _resolve_data_dir(env, default, base), "env"
        raw = file_cfg.get(setting_key) or ""
        if raw:
            return _resolve_data_dir(raw, default, base), "settings"
        return default.resolve(), "default"

    DATA_ROOT, src_root = pick("FORENSIC_DATA_ROOT", "dir_root", ROOT)
    base = DATA_ROOT
    RULES_DIR, src_rules = pick("FORENSIC_RULES_DIR", "dir_rules", base / "rules", base)
    REPORTS_DIR, src_reports = pick("FORENSIC_REPORTS_DIR", "dir_reports", base / "reports", base)
    JG_DIR, src_jg = pick(
        "FORENSIC_JG_DIR",
        "dir_jg",
        base / RESULTS_DIR_NAME,
        base,
    )
    # 兼容 FORENSIC_RESULTS_DIR
    env_results = (os.getenv("FORENSIC_RESULTS_DIR") or "").strip()
    if env_results:
        JG_DIR = _resolve_data_dir(env_results, base / RESULTS_DIR_NAME, base)
        src_jg = "env"
    JG_DIR = migrate_jg_to_results(JG_DIR)
    # 若设置仍指向空的「结果」但历史 jg 有文件，迁过去
    legacy = JG_DIR.parent / LEGACY_JG_NAME
    if JG_DIR.name == RESULTS_DIR_NAME and legacy.is_dir() and JG_DIR.exists():
        try:
            has_new = any(JG_DIR.iterdir())
        except Exception:
            has_new = True
        if not has_new:
            JG_DIR = migrate_jg_to_results(legacy)
    BACKUP_DIR, src_bak = pick("FORENSIC_BACKUP_DIR", "dir_backup", RULES_DIR / ".bak", base)
    IOC_DIR, src_ioc = pick("FORENSIC_IOC_DIR", "dir_ioc", base / "ioc", base)

    for d in (DATA_ROOT, RULES_DIR, REPORTS_DIR, JG_DIR, BACKUP_DIR, IOC_DIR, CONFIG_DIR):
        d.mkdir(parents=True, exist_ok=True)

    return {
        "root": str(ROOT),
        "data_root": str(DATA_ROOT),
        "config": str(CONFIG_DIR),
        "web": str(WEB_DIR),
        "admin_web": str(ADMIN_WEB_DIR),
        "rules": str(RULES_DIR),
        "reports": str(REPORTS_DIR),
        "jg": str(JG_DIR),
        "results": str(JG_DIR),
        "backup": str(BACKUP_DIR),
        "ioc": str(IOC_DIR),
        "source_root": src_root,
        "source_rules": src_rules,
        "source_reports": src_reports,
        "source_jg": src_jg,
        "source_backup": src_bak,
        "source_ioc": src_ioc,
        "defaults": program_default_dirs(),
    }


# 首次导入即生效（含根目录配置迁移）
_PATH_INFO = apply_data_dirs()


def ai_config_file(*, for_write: bool = False) -> Path:
    try:
        from .cache_config import ai_config_path
        if for_write:
            return resolve_config_file("ai_config.json", for_write=True)
        return ai_config_path()
    except Exception:
        return resolve_config_file("ai_config.json", for_write=for_write)


# 兼容旧引用：指向当前实际可读路径（可能是 config/ 或根目录）
AI_CONFIG_PATH = resolve_config_file("ai_config.json")


def _load_ai_file() -> Dict[str, Any]:
    path = ai_config_file()
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _env_first(env_keys) -> str:
    for k in env_keys:
        v = (os.getenv(k) or "").strip()
        if v:
            return v
    return ""


def _env_or_file(env_keys, file_key: str, default: str = "") -> str:
    v = _env_first(env_keys)
    if v:
        return v
    file_cfg = _load_ai_file()
    fv = file_cfg.get(file_key)
    if fv is None:
        return default
    return str(fv).strip() or default


def _file_ai_key(file_cfg: Dict[str, Any]) -> str:
    try:
        from . import platform_store
        return platform_store.file_api_key(file_cfg)
    except Exception:
        return str((file_cfg or {}).get("api_key") or "").strip()


def _scrub_ai_file_plaintext(file_cfg: Dict[str, Any], key: str) -> None:
    """本地 json 去掉明文 api_key，改为 api_key_enc。"""
    if not isinstance(file_cfg, dict) or not str(file_cfg.get("api_key") or "").strip():
        return
    try:
        from . import platform_store
        out = dict(file_cfg)
        if key:
            out["api_key_enc"] = platform_store.encrypt_secret(key)
        out.pop("api_key", None)
        path = ai_config_file(for_write=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print("[config] scrub ai_key:", e)


def reload_ai_config() -> None:
    """环境变量 > MySQL（加密 Key）> ai_config.json。"""
    global AI_API_KEY, AI_BASE_URL, AI_MODEL, AI_TIMEOUT, AI_ENABLED, AI_CONFIG_PATH
    AI_CONFIG_PATH = ai_config_file()
    file_cfg = _load_ai_file()
    mysql_cfg: Dict[str, str] = {}
    try:
        from . import platform_store
        remote = platform_store.load_ai()
        if remote is None:
            platform_store.seed_ai_from_local(
                {
                    "model": str(file_cfg.get("model") or "gpt-4o-mini"),
                    "base_url": str(file_cfg.get("base_url") or "https://api.openai.com/v1"),
                    "api_key": _file_ai_key(file_cfg),
                }
            )
            remote = platform_store.load_ai()
        if isinstance(remote, dict):
            mysql_cfg = remote
    except Exception as e:
        print("[config] mysql ai load:", e)

    AI_API_KEY = (
        _env_first(("FORENSIC_AI_API_KEY", "OPENAI_API_KEY"))
        or str(mysql_cfg.get("api_key") or "").strip()
        or _file_ai_key(file_cfg)
    )
    AI_BASE_URL = (
        _env_first(("FORENSIC_AI_BASE_URL", "OPENAI_BASE_URL"))
        or str(mysql_cfg.get("base_url") or "").strip()
        or str(file_cfg.get("base_url") or "").strip()
        or "https://api.openai.com/v1"
    )
    AI_MODEL = (
        _env_first(("FORENSIC_AI_MODEL", "OPENAI_MODEL"))
        or str(mysql_cfg.get("model") or "").strip()
        or str(file_cfg.get("model") or "").strip()
        or "gpt-4o-mini"
    )
    try:
        AI_TIMEOUT = float(_env_or_file(("FORENSIC_AI_TIMEOUT",), "timeout", "60") or "60")
    except ValueError:
        AI_TIMEOUT = 60.0
    force = (os.getenv("FORENSIC_AI_FORCE") or file_cfg.get("force") or "").strip().lower()
    AI_ENABLED = bool(AI_API_KEY) or force in ("1", "true", "yes")
    if file_cfg.get("api_key"):
        _scrub_ai_file_plaintext(file_cfg, AI_API_KEY)


def save_ai_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """写入 ai_config.json（密钥加密，不覆盖未传入的已有密钥）。"""
    global AI_CONFIG_PATH
    cur = _load_ai_file()
    key = _file_ai_key(cur)
    if "api_key" in data:
        incoming = str(data.get("api_key") or "").strip()
        if incoming and not set(incoming) <= {"*", "•"} and "****" not in incoming:
            key = incoming
    if "base_url" in data and data.get("base_url") is not None:
        cur["base_url"] = str(data.get("base_url") or "").strip() or cur.get("base_url") or "https://api.openai.com/v1"
        try:
            from .ai.analyzer import validate_ai_base_url
            validate_ai_base_url(str(cur["base_url"]))
        except RuntimeError:
            raise
        except Exception as e:
            raise ValueError(f"AI Base URL 校验失败: {e}") from e
    if "model" in data and data.get("model") is not None:
        cur["model"] = str(data.get("model") or "").strip() or cur.get("model") or "gpt-4o-mini"
    if "timeout" in data and data.get("timeout") is not None:
        try:
            cur["timeout"] = float(data.get("timeout"))
        except (TypeError, ValueError):
            pass
    try:
        from . import platform_store
        if key:
            cur["api_key_enc"] = platform_store.encrypt_secret(key)
        elif cur.get("api_key_enc"):
            pass
        cur.pop("api_key", None)
        platform_store.save_ai(
            str(cur.get("model") or "gpt-4o-mini"),
            str(cur.get("base_url") or "https://api.openai.com/v1"),
            key,
        )
    except Exception as e:
        print("[config] mysql ai save:", e)
        if key and "api_key_enc" not in cur:
            cur["api_key"] = key
    path = ai_config_file(for_write=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cur, f, ensure_ascii=False, indent=2)
    AI_CONFIG_PATH = path
    reload_ai_config()
    return ai_public_status()


def ai_public_status() -> Dict[str, Any]:
    key = AI_API_KEY or ""
    masked = ""
    if key:
        masked = "****"
    path = ai_config_file()
    return {
        "configured": bool(key),
        "api_key_masked": masked,
        "model": AI_MODEL,
        "base_url": AI_BASE_URL,
        "timeout": AI_TIMEOUT,
        "config_file": str(path),
        "env_override": bool(os.getenv("FORENSIC_AI_API_KEY") or os.getenv("OPENAI_API_KEY")),
        "hint": "在系统设置保存大模型配置（Key 加密写入 MySQL；本地 json 仅作回退），或设置环境变量 FORENSIC_AI_API_KEY / FORENSIC_AI_BASE_URL / FORENSIC_AI_MODEL",
    }


# 首次加载
AI_API_KEY = ""
AI_BASE_URL = "https://api.openai.com/v1"
AI_MODEL = "gpt-4o-mini"
AI_TIMEOUT = 60.0
AI_ENABLED = False
reload_ai_config()
