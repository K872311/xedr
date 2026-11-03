"""统一加载全部 rules-*.json，并报告哪些已接入管线"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from . import config

_STORE: Optional["RuleStore"] = None
_STORE_GEN: Optional[int] = None

# 已下线、即使磁盘残留也不再匹配
RETIRED_RULE_FILES = {"rules-interesting-files.json"}

# 管线接入状态（给前端/运维看）
PIPELINE_STATUS = {
    "rules-interesting-files.json": "removed",
    "rules-files.json": "active",
    "rules-folders.json": "active",  # 目录聚合 folderRules → files matcher
    "rules-filesscan.json": "active",  # 合并进 files.suspiciousRules
    "rules-simple.json": "active",  # 表单自定义，合并进 files.suspiciousRules
    "rules-high-risk.json": "active",  # High risk_rules → persistence
    "rules-windows-apt-persist.json": "active",  # APT 权限维持精确落点 → persistence + artifacts
    "rules-windows-process.json": "active",  # 0707 进程行为 → windows_process
    "rules-ioc.json": "active",
    "rules-wininfosc.json": "active",
    "rules-keywords.json": "active",
    "rules-windows-system.json": "active",
    "rules-linux-system.json": "active",
    "rules-linux-sigma.json": "active",
    "rules-linux-signatures.json": "active",
    "rules-linux-process.json": "active",
    "rules-linux-network.json": "active",
    "rules-linux-kernel.json": "active",
    "rules-linux-persistence.json": "active",
    "rules-linux-0707.json": "active",  # LinuxEmergencyTool 0707 统一包
    "rules/driver/1.json": "active",  # LOLDrivers 驱动黑名单 → driver matcher
    "rules-tools_rules.json": "active",
    "rules-browsers.json": "active",  # SQL抽取(采集) + 后端匹配
    "rules-file-types.json": "partial",  # 路径/扩展名级；魔数需原文件走 /api
    "rules-encryption.json": "partial",  # 容器扩展名+interesting；熵/BitLocker卷需原盘
    "rules-yara-hash.json": "config_only",
    "rules-timeline.json": "partial",  # 平台时间线；Plaso SQL需外部DB
    "rules-email.json": "partial",  # 路径发现；MBOX/PST深解析需附件
    "rules-central-repo.json": "active",  # 经 ioc/*.db SQLite 情报库落地
    "rules-dftimewolf.json": "idle",  # 云取证编排，非本机应急
}


class RuleStore:
    def __init__(self, root: Optional[Path] = None):
        # 优先 rules/ 子目录，其次项目根（兼容未迁移）
        self.root = Path(root or config.RULES_DIR)
        self._search_roots = []
        for p in (self.root, config.ROOT):
            if p not in self._search_roots:
                self._search_roots.append(p)
        self.raw: Dict[str, Any] = {}
        self.index: Dict = {}
        self.file_types: Dict = {}
        self.browsers: Dict = {}
        self.windows: Dict = {}
        self.interesting: Dict = {}
        self.keywords: Dict = {}
        self.encryption: Dict = {}
        self.yara_hash: Dict = {}
        self.central_repo: Dict = {}
        self.timeline: Dict = {}
        self.email: Dict = {}
        self.wininfosc: Dict = {}
        self.ioc: Dict = {}
        self.files: Dict = {}
        self.simple: Dict = {}
        self.dftimewolf: Dict = {}
        self._rmm_index = None
        self.load_all()

    def _disabled_files(self) -> set:
        names = set(RETIRED_RULE_FILES)
        for base in self._search_roots:
            p = base / ".disabled.json"
            if not p.is_file():
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                files = data.get("files") if isinstance(data, dict) else data
                for x in files or []:
                    n = str(x or "").strip()
                    if n.startswith("rules-") and n.endswith(".json"):
                        names.add(n)
            except Exception:
                pass
        try:
            from .rule_index import list_tombstones
            names.update(list_tombstones())
        except Exception:
            pass
        return names

    def _load(self, name: str) -> Dict:
        from .rule_families import versioned_filenames

        disabled = getattr(self, "_disabled", set()) | set(RETIRED_RULE_FILES)
        if name in RETIRED_RULE_FILES:
            return {}
        # 兼容 rules-foo.json ↔ rules-foo-v3.json / -v2.2.json；以及 rules/linux/ 子目录
        # 规范名被墓碑时仍尝试版本别名，避免整包空载
        candidates = [name]
        n = str(name or "")
        if n.startswith("rules-") and n.endswith(".json") and "-v3.json" not in n:
            candidates.append(n[:-5] + "-v3.json")
        elif n.endswith("-v3.json"):
            candidates.append(n[:-8] + ".json")
        for extra in versioned_filenames(n):
            if extra not in candidates:
                candidates.append(extra)
        if n in ("rules-windows-system.json", "rules-windows-system-v3.json"):
            # 发布变体时会同步规范名；这里再兜底旧文件名
            candidates.append("rules-windows-system-v3.2-edr-production.json")
        rel_names = list(candidates)
        for cand in list(candidates):
            if "/" not in cand and "\\" not in cand:
                rel_names.append(f"linux/{cand}")
        for base in self._search_roots:
            for cand in rel_names:
                if cand in disabled:
                    continue
                p = base / cand
                if p.exists():
                    try:
                        with open(p, encoding="utf-8-sig") as f:
                            data = json.load(f)
                        return data if isinstance(data, dict) else {}
                    except Exception as e:
                        print(f"[RuleStore] skip {p.name}: {e}")
                        continue
        return {}

    def file_active(self, name: str) -> bool:
        n = str(name or "").strip()
        if not n:
            return True
        if n in RETIRED_RULE_FILES:
            return False
        data = self.raw.get(n)
        if isinstance(data, dict) and data:
            return True
        if n in getattr(self, "_disabled", set()):
            return False
        return False

    def load_all(self):
        self._disabled = self._disabled_files()
        mapping = {
            "rules-file-types.json": "file_types",
            "rules-browsers.json": "browsers",
            "rules-windows-system.json": "windows",
            "rules-linux-system.json": "linux",
            "rules-interesting-files.json": "interesting",
            "rules-keywords.json": "keywords",
            "rules-encryption.json": "encryption",
            "rules-yara-hash.json": "yara_hash",
            "rules-central-repo.json": "central_repo",
            "rules-timeline.json": "timeline",
            "rules-email.json": "email",
            "rules-wininfosc.json": "wininfosc",
            "rules-files.json": "files",
            "rules-dftimewolf.json": "dftimewolf",
        }
        for fname, attr in mapping.items():
            data = self._load(fname)
            setattr(self, attr, data)
            self.raw[fname] = data

        ioc_doc = self._load("rules-ioc.json")
        self.ioc = ioc_doc.get("indicators", {}) if ioc_doc else {}
        self.raw["rules-ioc.json"] = ioc_doc
        self._rmm_index = None

        # 简单自定义规则合并进 files.suspiciousRules（不改坏内置 JSON）
        if "rules-simple.json" in self._disabled:
            self.simple = {}
            self.raw["rules-simple.json"] = {}
        else:
            self._merge_simple_rules()
        self._merge_custom_file_packs()
        self._merge_folder_rules()
        self._merge_windows_extra_packs()
        self._merge_linux_packs()

        print(f"[RuleStore] dir={self.root} loaded {len(self.raw)} rule files")
        from . import ioc_db
        db = ioc_db.stats()
        linux_n = 0
        if isinstance(self.linux, dict):
            for k in ("textRules", "processRules", "commandRules", "networkRules", "portRules", "moduleRules"):
                linux_n += len(self.linux.get(k) or [])
        print(f"  interesting={self.interesting.get('meta', {}).get('totalRules', 0)} "
              f"ioc_md5={len(self.ioc.get('md5', []))} files_sus={len(self.files.get('suspiciousRules', []))} "
              f"folder_rules={len(self.files.get('folderRules', []))} linux_rules={linux_n}")
        if db.get("enabled"):
            print(f"  ioc_db={db.get('path')} total={db.get('total')} by_type={db.get('by_type')}")
        else:
            print("  ioc_db=未找到（请放置 ioc/ioc_data.db 或 ioc_data_sample.db）")
        self._rebuild_rule_id_index()

    def _rebuild_rule_id_index(self) -> None:
        """扁平 id → 规则，供 ATT&CK / 详情回查。"""
        idx: Dict[str, Dict[str, Any]] = {}

        def walk(obj: Any) -> None:
            if isinstance(obj, dict):
                rid = str(obj.get("id") or "").strip()
                if rid and ("mitre" in obj or "attackStage" in obj or "name" in obj):
                    # 保留首次（通常更具体的包先合并也可被后写覆盖——后写优先）
                    idx[rid] = obj
                for v in obj.values():
                    walk(v)
            elif isinstance(obj, list):
                for x in obj:
                    walk(x)

        for attr in (
            "windows", "files", "linux", "interesting", "keywords",
            "encryption", "wininfosc", "simple", "browsers",
        ):
            walk(getattr(self, attr, None))
        # raw 包兜底（high-risk / apt-persist 等已 merge 进 windows，再扫 raw 无妨）
        for doc in (self.raw or {}).values():
            walk(doc)
        self._rule_by_id = idx

    def rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        rid = str(rule_id or "").strip()
        if not rid:
            return None
        idx = getattr(self, "_rule_by_id", None)
        if not isinstance(idx, dict):
            self._rebuild_rule_id_index()
            idx = self._rule_by_id
        hit = idx.get(rid)
        return hit if isinstance(hit, dict) else None

    def _merge_simple_rules(self) -> None:
        from . import simple_rules
        simple_doc = simple_rules.load_doc()
        self.simple = simple_doc
        self.raw["rules-simple.json"] = simple_doc
        extra = simple_rules.enabled_rules_for_matcher(simple_doc)
        if not isinstance(self.files, dict):
            self.files = {}
        base = list(self.files.get("suspiciousRules") or [])
        # 去掉上次合并残留的 source=simple，再追加当前启用项
        base = [r for r in base if not (isinstance(r, dict) and r.get("source") == "simple")]
        if extra:
            base.extend(extra)
        self.files = dict(self.files)
        self.files["suspiciousRules"] = base
        self.raw["rules-files.json"] = self.files

    def _merge_windows_extra_packs(self) -> None:
        """合并独立 Windows 规则包到 windows.task/service/startup/process/registryRules。

        主文件 rules-windows-system.json 若被停用，仍可通过此类小包启用高价值规则。
        """
        if not isinstance(self.windows, dict):
            self.windows = {}
        disabled = getattr(self, "_disabled", set())
        packs = (
            "rules-high-risk.json",
            "rules-high-tasks-risk.json",
            "rules-windows-process.json",
            "rules-windows-apt-persist.json",
        )
        keys = ("taskRules", "serviceRules", "startupRules", "processRules", "registryRules")
        for fname in packs:
            if fname in disabled:
                continue
            doc = self._load(fname)
            if not doc:
                # 直接读磁盘（_load 可能因主名映射错过）
                for base in self._search_roots:
                    p = base / fname
                    if p.is_file():
                        try:
                            doc = json.loads(p.read_text(encoding="utf-8-sig"))
                        except Exception as e:
                            print(f"[RuleStore] skip {fname}: {e}")
                            doc = {}
                        break
            if not isinstance(doc, dict):
                continue
            self.raw[fname] = doc
            merged_n = 0
            for key in keys:
                extra = [r for r in (doc.get(key) or []) if isinstance(r, dict) and r.get("enabled") is not False]
                if not extra:
                    continue
                cur = [r for r in (self.windows.get(key) or []) if isinstance(r, dict)]
                ids = {str(r.get("id") or "") for r in cur}
                for r in extra:
                    rid = str(r.get("id") or "")
                    item = dict(r)
                    item.setdefault("source", fname)
                    if rid and rid in ids:
                        # 同 id 用独立包覆盖（运营新增优先）
                        cur = [x for x in cur if str(x.get("id") or "") != rid]
                    cur.insert(0, item)
                    if rid:
                        ids.add(rid)
                    merged_n += 1
                self.windows[key] = cur
            if merged_n:
                print(f"[RuleStore] merged {merged_n} windows rules from {fname}")

    def _merge_linux_packs(self) -> None:
        """合并 rules/linux/rules-*.json 与根目录 rules-linux-*.json 到 store.linux。"""
        if not isinstance(self.linux, dict):
            self.linux = {}
        keys = (
            "textRules", "processRules", "commandRules",
            "networkRules", "portRules", "moduleRules",
        )
        packs = [
            "rules-linux-sigma.json",
            "rules-linux-signatures.json",
            "rules-linux-process.json",
            "rules-linux-network.json",
            "rules-linux-kernel.json",
            "rules-linux-persistence.json",
            "rules-linux-0707.json",
            "rules-tools_rules.json",
        ]
        # 再扫一遍 linux/ 下其它 rules-*.json
        discovered: List[str] = list(packs)
        for base in self._search_roots:
            linux_dir = base / "linux"
            if not linux_dir.is_dir():
                continue
            for p in sorted(linux_dir.glob("rules-*.json")):
                if p.name not in discovered:
                    discovered.append(p.name)

        from .rule_families import canonical_for

        total = 0
        loaded_family: Set[str] = set()
        for fname in discovered:
            family = canonical_for(fname) or fname
            if family in loaded_family and fname != family:
                continue
            doc = self._load(fname)
            if not isinstance(doc, dict) or not doc:
                continue
            loaded_family.add(family)
            self.raw[fname] = doc
            # 别名实文件也挂到规范名，便于 file_active("rules-linux-persistence.json")
            if family != fname and family.endswith(".json"):
                self.raw.setdefault(family, doc)
            merged_n = 0
            for key in keys:
                extra = [r for r in (doc.get(key) or []) if isinstance(r, dict) and r.get("enabled") is not False]
                if not extra:
                    continue
                cur = [r for r in (self.linux.get(key) or []) if isinstance(r, dict)]
                ids = {str(r.get("id") or "") for r in cur}
                for r in extra:
                    rid = str(r.get("id") or "")
                    item = dict(r)
                    item.setdefault("source", fname)
                    if rid and rid in ids:
                        cur = [x for x in cur if str(x.get("id") or "") != rid]
                    cur.append(item)
                    if rid:
                        ids.add(rid)
                    merged_n += 1
                self.linux[key] = cur
            total += merged_n
            if merged_n:
                print(f"[RuleStore] merged {merged_n} linux rules from {fname}")
        # 保证入口文件也在 raw 中
        if "rules-linux-system.json" not in self.raw:
            self.raw["rules-linux-system.json"] = self.linux
        else:
            # 把合并后的列表写回入口，便于 matcher 从 store.linux 读取
            base_doc = dict(self.raw.get("rules-linux-system.json") or {})
            if not isinstance(base_doc, dict):
                base_doc = {}
            for key in keys:
                if self.linux.get(key):
                    base_doc[key] = self.linux[key]
            meta = dict(base_doc.get("meta") or {})
            meta.setdefault("os_family", "linux")
            base_doc["meta"] = meta
            self.raw["rules-linux-system.json"] = base_doc
            self.linux = base_doc
        if total:
            print(f"[RuleStore] linux packs total rules={total}")

    def _merge_custom_file_packs(self) -> None:
        """把磁盘上其它带 suspiciousRules 的 rules-*.json 并入文件匹配。"""
        core = {
            "rules-files.json", "rules-files-v3.json", "rules-simple.json", "rules-ioc.json",
            "rules-interesting-files.json", "rules-keywords.json", "rules-wininfosc.json",
            "rules-windows-system.json", "rules-browsers.json", "rules-file-types.json",
            "rules-encryption.json", "rules-email.json", "rules-timeline.json",
            "rules-yara-hash.json", "rules-central-repo.json", "rules-dftimewolf.json",
            "rules-linux-system.json", "rules-linux-sigma.json", "rules-linux-signatures.json",
            "rules-linux-process.json", "rules-linux-network.json", "rules-linux-kernel.json",
            "rules-linux-persistence.json", "rules-linux-0707.json", "rules-tools_rules.json",
            "rules-high-risk.json",
            "rules-windows-process.json",
            "rules-windows-apt-persist.json",
        }
        disabled = getattr(self, "_disabled", set())
        if not isinstance(self.files, dict):
            self.files = {}
        base = list(self.files.get("suspiciousRules") or [])
        base = [r for r in base if not (isinstance(r, dict) and str(r.get("source") or "").startswith("custom:"))]
        added = 0
        seen = set()
        for root in self._search_roots:
            if not root.is_dir():
                continue
            for p in sorted(root.glob("rules-*.json")):
                if p.name in core or p.name in disabled or p.name in seen:
                    continue
                seen.add(p.name)
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if not isinstance(data, dict):
                    continue
                lst = data.get("suspiciousRules")
                if not isinstance(lst, list) or not lst:
                    continue
                self.raw[p.name] = data
                for r in lst:
                    if not isinstance(r, dict) or r.get("enabled") is False:
                        continue
                    item = dict(r)
                    item["source"] = "custom:" + p.name
                    base.append(item)
                    added += 1
        if added:
            self.files = dict(self.files)
            self.files["suspiciousRules"] = base
            print(f"[RuleStore] merged {added} custom file rules")

    def _merge_folder_rules(self) -> None:
        """合并 rules-folders.json 及自定义包中的 folderRules。"""
        if not isinstance(self.files, dict):
            self.files = {}
        base: List[Dict[str, Any]] = []
        seen_names: set = set()
        disabled = getattr(self, "_disabled", set())

        def _add_pack(fname: str, data: Dict[str, Any], source: str) -> int:
            n = 0
            lst = data.get("folderRules")
            if not isinstance(lst, list):
                return 0
            self.raw[fname] = data
            for r in lst:
                if not isinstance(r, dict) or r.get("enabled") is False:
                    continue
                name = str(r.get("name") or "").strip()
                if name and name in seen_names:
                    continue
                item = dict(r)
                item["source"] = source
                if name:
                    seen_names.add(name)
                base.append(item)
                n += 1
            return n

        added = 0
        if "rules-folders.json" not in disabled:
            doc = self._load("rules-folders.json")
            if doc:
                added += _add_pack("rules-folders.json", doc, "folders")
        # 已写在 rules-files.json 内的 folderRules（若有）
        native = self.files.get("folderRules")
        if isinstance(native, list):
            for r in native:
                if not isinstance(r, dict) or r.get("enabled") is False:
                    continue
                name = str(r.get("name") or "").strip()
                if name and name in seen_names:
                    continue
                item = dict(r)
                item.setdefault("source", "files")
                if name:
                    seen_names.add(name)
                base.append(item)
                added += 1
        # 其它自定义包
        core = {
            "rules-files.json", "rules-folders.json", "rules-simple.json",
            "rules-ioc.json", "rules-interesting-files.json", "rules-keywords.json",
            "rules-wininfosc.json", "rules-windows-system.json", "rules-browsers.json",
            "rules-file-types.json", "rules-encryption.json", "rules-email.json",
            "rules-timeline.json", "rules-yara-hash.json", "rules-central-repo.json",
            "rules-dftimewolf.json",
        }
        seen_files = set()
        for root in self._search_roots:
            if not root.is_dir():
                continue
            for p in sorted(root.glob("rules-*.json")):
                if p.name in core or p.name in disabled or p.name in seen_files:
                    continue
                seen_files.add(p.name)
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if isinstance(data, dict) and isinstance(data.get("folderRules"), list):
                    added += _add_pack(p.name, data, "custom:" + p.name)
        self.files = dict(self.files)
        self.files["folderRules"] = base
        if added:
            print(f"[RuleStore] merged {added} folder rules")

    def inventory(self) -> List[Dict[str, Any]]:
        """以磁盘为准列出规则文件，并同步索引到数据库。"""
        from .rule_index import scan_disk, sync_index
        disabled = getattr(self, "_disabled", set())
        rows = scan_disk()
        for row in rows:
            fname = row.get("file") or ""
            data = self.raw.get(fname) or {}
            loaded = fname not in disabled and isinstance(data, dict) and bool(data)
            row["loaded"] = loaded
            row["enabled"] = fname not in disabled
            if fname in disabled:
                row["status"] = "disabled"
            fam = classify_rule_os(fname, data if isinstance(data, dict) else None)
            row["os_family"] = fam
            row["os"] = fam
        try:
            sync_index(rows)
        except Exception as e:
            print(f"[RuleStore] sync index: {e}")
        return rows


# 规则文件适用平台：windows | linux | both
_RULE_OS_BY_FILE = {
    "rules-windows-system.json": "windows",
    "rules-windows-system-v3.json": "windows",
    "rules-windows-system-v3.2-edr-production.json": "windows",
    "rules-wininfosc.json": "windows",
    "rules-high-risk.json": "windows",
    "rules-windows-apt-persist.json": "windows",
    "rules-windows-process.json": "windows",
    "rules-linux-system.json": "linux",
    "rules-linux-sigma.json": "linux",
    "rules-linux-signatures.json": "linux",
    "rules-linux-process.json": "linux",
    "rules-linux-network.json": "linux",
    "rules-linux-kernel.json": "linux",
    "rules-linux-persistence.json": "linux",
    "rules-linux-0707.json": "linux",
    "rules-tools_rules.json": "linux",
    "rules-browsers.json": "windows",
    "rules-email.json": "windows",
    "rules-encryption.json": "both",
    "rules-file-types.json": "both",
    "rules-files.json": "both",
    "rules-files-v3.json": "both",
    "rules-folders.json": "both",
    "rules-folders-v3.json": "both",
    "rules-keywords.json": "both",
    "rules-keywords-v3.json": "both",
    "rules-ioc.json": "both",
    "rules-simple.json": "both",
    "rules-interesting-files.json": "windows",
    "rules-timeline.json": "both",
    "rules-yara-hash.json": "both",
    "rules-central-repo.json": "both",
    "rules-dftimewolf.json": "both",
}


def classify_rule_os(fname: str, doc: Optional[Dict[str, Any]] = None) -> str:
    """Infer which OS track a rules JSON applies to."""
    name = str(fname or "").strip().lower()
    data = doc if isinstance(doc, dict) else {}
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    for key in ("os_family", "osFamily", "platform", "os"):
        raw = str(meta.get(key) or data.get(key) or "").strip().lower()
        if raw in ("windows", "win", "win32"):
            return "windows"
        if raw in ("linux", "unix"):
            return "linux"
        if raw in ("both", "all", "shared", "common", "any"):
            return "both"
    if name in _RULE_OS_BY_FILE:
        return _RULE_OS_BY_FILE[name]
    if "linux" in name:
        return "linux"
    if "windows" in name or "wininfosc" in name or name.startswith("rules-win"):
        return "windows"
    # Sigma / eventlog packs under log_rules are Windows-oriented
    if "sysmon" in name or "eventlog" in name or "zircolite" in name:
        return "windows"
    return "both"

    def rmm_rules(self) -> List[Dict]:
        out = []
        for sc in self.interesting.get("categories", {}).get("rmmTools", {}).get("subCategories", []):
            out.extend(r for r in (sc.get("rules") or []) if isinstance(r, dict) and r.get("enabled") is not False)
        return out

    def rmm_index(self):
        """缓存的 FastRmmIndex，供 interesting / artifacts 复用。"""
        if self._rmm_index is None:
            from .matchers.rule_engine import FastRmmIndex
            dir_rules = [
                r for r in (self.interesting.get("categories", {}).get("rmmTools", {}).get("directoryRules") or [])
                if isinstance(r, dict) and r.get("enabled") is not False
            ]
            self._rmm_index = FastRmmIndex(self.rmm_rules(), dir_rules)
        return self._rmm_index


def get_store() -> RuleStore:
    """按规则代次自动热加载，避免删了文件进程里还在用旧规则。"""
    global _STORE, _STORE_GEN
    gen = 0
    try:
        from .rule_index import current_gen
        gen = current_gen()
    except Exception:
        gen = 0
    if _STORE is None or _STORE_GEN != gen:
        _STORE = RuleStore()
        _STORE_GEN = gen
        try:
            _STORE.inventory()
        except Exception:
            pass
    return _STORE


def reload_store() -> RuleStore:
    """重新从磁盘加载全部规则（含简单自定义规则合并）。"""
    global _STORE, _STORE_GEN
    try:
        from .rule_index import tombstone_file, current_gen
        for fname in RETIRED_RULE_FILES:
            tombstone_file(fname, "retired")
        _STORE_GEN = current_gen()
    except Exception:
        _STORE_GEN = None
    _STORE = RuleStore()
    try:
        _STORE.inventory()
    except Exception:
        pass
    return _STORE
