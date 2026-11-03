"""Run the EDR services as one supervised process tree.

Ctrl+C first sends a graceful console break to every service, waits for
uvicorn shutdown hooks, then terminates only processes that did not exit.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--admin-port", type=int, default=8001)
    parser.add_argument("--edr-port", type=int, default=8100)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--skip-admin", action="store_true")
    parser.add_argument("--skip-edr", action="store_true")
    return parser.parse_args()


def start(cmd: list[str], root: Path, env: dict[str, str]) -> subprocess.Popen:
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    return subprocess.Popen(cmd, cwd=root, env=env, creationflags=flags)


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8,
            )
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, OSError, subprocess.SubprocessError):
        pass
    if proc.poll() is None:
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass


def graceful_stop(processes: list[subprocess.Popen]) -> None:
    alive = [p for p in processes if p.poll() is None]
    if not alive:
        return
    print("\n[stop] 正在通知各服务保存并退出…", flush=True)
    for proc in alive:
        try:
            if os.name == "nt":
                proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(proc.pid, signal.SIGINT)
        except (ProcessLookupError, OSError):
            pass

    deadline = time.monotonic() + 7
    while time.monotonic() < deadline and any(p.poll() is None for p in alive):
        time.sleep(0.15)

    # 超时仍未退出：连同 reload 子进程整棵树强杀，避免残留占端口
    stuck = [p for p in alive if p.poll() is None]
    for proc in stuck:
        print(f"[stop] PID={proc.pid} 未在时限内退出，强制结束进程树。", flush=True)
        _kill_tree(proc)
    if stuck:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and any(p.poll() is None for p in stuck):
            time.sleep(0.1)
    print("[stop] EDR 服务已全部结束。", flush=True)


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    env = os.environ.copy()
    env["EDR_PORT"] = str(args.edr_port)
    py = sys.executable
    processes: list[subprocess.Popen] = []

    def request_stop(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, request_stop)
    if os.name == "nt" and hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, request_stop)

    main_cmd = [
        py, "-m", "uvicorn", "server:app",
        "--host", args.host, "--port", str(args.port),
        "--app-dir", str(root),
        "--timeout-graceful-shutdown", "3",
    ]
    if args.reload:
        main_cmd += [
            "--reload", "--reload-dir", str(root / "backend"),
            "--reload-dir", str(root), "--reload-include=*.py",
            "--reload-exclude=frontend", "--reload-exclude=reports",
            "--reload-exclude=.git",
        ]
    else:
        main_cmd += ["--workers", "1"]

    try:
        if not args.skip_admin:
            processes.append(start([
                py, "-m", "uvicorn", "rules_admin.app:app",
                "--host", args.host, "--port", str(args.admin_port),
                "--timeout-graceful-shutdown", "3",
                *(["--reload"] if args.reload else []),
            ], root, env))
        if not args.skip_edr:
            processes.append(start([
                py, "edr_server.py", "--host", args.host,
                "--port", str(args.edr_port),
                *(["--reload"] if args.reload else []),
            ], root, env))
        processes.append(start(main_cmd, root, env))

        while True:
            for proc in processes:
                code = proc.poll()
                if code is not None:
                    print(f"\n[exit] 服务 PID={proc.pid} 已退出，code={code}；关闭其余服务。", flush=True)
                    return int(code or 0)
            time.sleep(0.3)
    except KeyboardInterrupt:
        return 0
    finally:
        graceful_stop(processes)


if __name__ == "__main__":
    raise SystemExit(main())
