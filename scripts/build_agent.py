"""构建 Windows Agent 并生成 build-manifest.json。

用法:  python scripts/build_agent.py [--out agent/forensic-agent.exe] [--goarch amd64]

清单与 EXE 同目录，记录版本、构建时间、EXE SHA256、源码指纹、协议范围与能力。
后端据此判断下载的是否为“最新版”。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend import agent_release as rel  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "agent" / "forensic-agent.exe"))
    ap.add_argument("--goarch", default="amd64")
    args = ap.parse_args()

    go = rel._find_go()
    if not go:
        print("[build] 未找到 go，请先安装 Go", file=sys.stderr)
        return 2

    src = ROOT / "agent"
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    version = rel.source_version(src) or "0.0.0"
    source_rev = rel.compute_source_rev(src)
    build_time = time.strftime("%Y-%m-%dT%H:%M:%S%z") or time.strftime("%Y-%m-%dT%H:%M:%S")
    build_id = f"{version}+{source_rev[:8]}"

    # 若服务端已有升级公钥，则钉入 EXE（生产验签强制）
    upgrade_pub = ""
    try:
        from backend import agent_edr as _edr  # noqa: WPS433

        pk = _edr.get_upgrade_pubkey()
        if pk.get("ok") and pk.get("pubkey"):
            upgrade_pub = str(pk["pubkey"]).strip()
    except Exception as e:
        print("[build] upgrade pubkey skip:", e, flush=True)

    ldflags = (
        f"-H windowsgui -s -w "
        f"-X main.buildID={build_id} -X main.buildTime={build_time} -X main.sourceRev={source_rev}"
    )
    if upgrade_pub:
        # base64 含 /+，ldflags 用引号包一层
        ldflags += f" -X main.upgradePubKeyB64={upgrade_pub}"
        print(f"[build] pin upgrade Ed25519 pubkey ({len(upgrade_pub)} chars)", flush=True)
    env = os.environ.copy()
    env.setdefault("GOPROXY", "https://goproxy.cn,direct")
    env["GOOS"] = "windows"
    env["GOARCH"] = args.goarch
    env["CGO_ENABLED"] = "0"

    tmp_exe = out.with_suffix(".new.exe")
    print(f"[build] version={version} rev={source_rev} -> {out}", flush=True)
    cp = subprocess.run([go, "build", "-trimpath", f"-ldflags={ldflags}", "-o", str(tmp_exe), "."],
                        cwd=str(src), env=env)
    if cp.returncode != 0:
        tmp_exe.unlink(missing_ok=True)
        print("[build] go build 失败", file=sys.stderr)
        return cp.returncode or 1

    # 让新 EXE 自述构建信息（含 capabilities），windowsgui 无控制台故写文件
    info: dict = {}
    if os.name == "nt":
        fd, info_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            subprocess.run([str(tmp_exe), "build-info", info_path], timeout=30, check=True)
            info = json.loads(Path(info_path).read_text(encoding="utf-8"))
        except Exception as e:
            print("[build] 读取 build-info 失败:", e, file=sys.stderr)
        finally:
            Path(info_path).unlink(missing_ok=True)

    os.replace(tmp_exe, out)
    manifest = {
        "schema": rel.MANIFEST_SCHEMA,
        "version": version,
        "build_id": build_id,
        "build_time": build_time,
        "source_rev": source_rev,
        "exe_name": out.name,
        "exe_size": out.stat().st_size,
        "exe_sha256": rel.file_sha256(out),
        "protocol_min": info.get("protocol_min", 1),
        "protocol_max": info.get("protocol_max", 1),
        "capabilities": info.get("capabilities", []),
        "go_version": info.get("go_version", ""),
        "goos": "windows",
        "goarch": args.goarch,
    }
    mp = rel.manifest_path_for(out)
    tmp_m = mp.with_suffix(".tmp")
    tmp_m.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp_m, mp)
    print(f"[build] OK sha256={manifest['exe_sha256'][:16]}… manifest={mp}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
