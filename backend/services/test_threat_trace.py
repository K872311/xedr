"""威胁溯检服务测试。"""
from backend.services.threat_trace import (
    CONF_MEDIUM,
    CONF_STRONG,
    CONF_WEAK,
    _anchor_confidence,
    _eventlog_confidence,
    _eventlog_matches_process,
    _file_create_from_event,
    _finding_confidence,
    _finding_matches_process,
    _is_suspicious_drop_name,
    _parent_dir,
    _parse_loose_time,
    _proc_matches_file,
    _proc_matches_query,
    looks_like_filename,
    looks_like_path,
    search_processes,
)


def test_proc_matches_pid_and_name():
    procs = [
        {"pid": 1234, "name": "rundll32.exe", "path": r"C:\Windows\System32\rundll32.exe"},
        {"pid": 5678, "name": "notepad.exe", "path": r"C:\Windows\System32\notepad.exe"},
    ]
    assert search_processes(procs, pid=1234)[0]["pid"] == 1234
    got = search_processes(procs, q="rundll32")
    assert got and got[0]["name"] == "rundll32.exe"


def test_looks_like_filename_and_basename_file_match():
    assert looks_like_filename("ev2f79.exe")
    assert looks_like_filename("ev2f79")
    assert looks_like_filename("payload.dll")
    assert not looks_like_filename(r"C:\temp\ev2f79.exe")
    assert not looks_like_filename("8.8.8.8")
    assert not looks_like_path("ev2f79.exe")
    p = {
        "pid": 9,
        "name": "ev2f79.exe",
        "path": r"C:\Users\Public\ev2f79.exe",
        "command_line": r"C:\Users\Public\ev2f79.exe -s",
    }
    assert _proc_matches_file(p, "ev2f79.exe")
    assert search_processes([p], q="ev2f79.exe")
    assert search_processes([p], q="ev2f79")


def test_finding_matches_process_by_pid():
    p = {"pid": 99, "name": "evil.exe", "path": r"C:\temp\evil.exe"}
    f = {"title": "可疑进程", "extra": {"pid": 99}, "evidence": ["PID 99"]}
    assert _finding_matches_process(f, p)


def test_proc_matches_hash():
    p = {"pid": 1, "name": "a.exe", "md5": "abc" * 10 + "ef"}
    assert _proc_matches_query(p, "abc" * 10 + "ef")


def test_eventlog_matches_process_by_name_and_pid():
    p = {"pid": 4420, "name": "46ef329d.exe", "path": r"C:\Users\Public\46ef329d.exe"}
    ev = {
        "channel": "Security",
        "event_id": 4688,
        "message": "A new process has been created.",
        "fields": {"NewProcessName": r"C:\Users\Public\46ef329d.exe", "NewProcessId": "4420"},
    }
    assert _eventlog_matches_process(ev, p)
    ev2 = {"channel": "System", "event_id": 7045, "message": "Service installed", "fields": {}}
    assert not _eventlog_matches_process(ev2, p)


def test_finding_confidence_pid_strong():
    p = {"pid": 99, "name": "evil.exe", "path": r"C:\temp\evil.exe"}
    f = {"title": "可疑进程", "extra": {"pid": 99}, "evidence": ["PID 99"]}
    conf, reason = _finding_confidence(f, p)
    assert conf == CONF_STRONG
    assert "PID" in reason


def test_finding_confidence_name_weak():
    p = {"pid": 1, "name": "cmd.exe", "path": r"C:\Windows\System32\cmd.exe"}
    f = {"title": "命令执行", "reason": "检测到 cmd.exe 可疑调用", "evidence": []}
    conf, _ = _finding_confidence(f, p)
    assert conf == CONF_WEAK


def test_anchor_confidence_hash_and_path():
    item = {"path": r"C:\Users\Public\46ef329d.exe", "md5": "aabbccddeeff00112233445566778899"}
    conf, reason = _anchor_confidence(
        item,
        names={"46ef329d.exe"},
        paths={r"c:\users\public\46ef329d.exe"},
        hashes={"aabbccddeeff00112233445566778899"},
    )
    assert conf == CONF_STRONG
    assert "哈希" in reason

    conf2, reason2 = _anchor_confidence(
        {"command": r"C:\Users\Public\46ef329d.exe -s"},
        names={"46ef329d.exe"},
        paths={r"c:\users\public\46ef329d.exe"},
        hashes=set(),
    )
    assert conf2 == CONF_MEDIUM
    assert "路径" in reason2


def test_eventlog_confidence_pid_strong():
    p = {"pid": 4420, "name": "46ef329d.exe", "path": r"C:\Users\Public\46ef329d.exe"}
    ev = {
        "channel": "Security",
        "event_id": 4688,
        "message": "created",
        "fields": {"NewProcessId": "4420"},
    }
    conf, reason = _eventlog_confidence(ev, p)
    assert conf == CONF_STRONG
    assert "PID" in reason


def test_sysmon11_file_create_by_pid():
    by_pid = {
        4420: {"pid": 4420, "name": "dropper.exe", "path": r"C:\Users\Public\dropper.exe"},
    }
    ev = {
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 11,
        "time": "2026-08-18 23:10:00",
        "fields": {
            "ProcessId": "4420",
            "Image": r"C:\Users\Public\dropper.exe",
            "TargetFilename": r"C:\Users\Public\payload.dll",
        },
    }
    hit = _file_create_from_event(ev, by_pid)
    assert hit is not None
    assert hit["pid"] == 4420
    assert hit["path"].endswith("payload.dll")
    assert hit["confidence"] == CONF_STRONG
    assert "Sysmon" in hit["confidence_reason"]


def test_sysmon11_file_create_by_image():
    by_pid = {
        100: {"pid": 100, "name": "a.exe", "path": r"C:\Temp\a.exe"},
    }
    ev = {
        "event_id": 11,
        "fields": {
            "Image": r"C:\Temp\a.exe",
            "TargetFilename": r"C:\Temp\b.bat",
        },
    }
    hit = _file_create_from_event(ev, by_pid)
    assert hit is not None
    assert hit["pid"] == 100
    assert hit["confidence"] == CONF_STRONG


def test_sysmon11_skips_self_image():
    by_pid = {1: {"pid": 1, "name": "a.exe", "path": r"C:\Temp\a.exe"}}
    ev = {
        "event_id": 11,
        "fields": {"ProcessId": "1", "TargetFilename": r"C:\Temp\a.exe"},
    }
    assert _file_create_from_event(ev, by_pid) is None


def test_parent_dir_and_suspicious_ext():
    assert _parent_dir(r"C:\Users\Public\a.exe").lower() == r"c:\users\public"
    assert _is_suspicious_drop_name(r"C:\Temp\x.dll")
    assert not _is_suspicious_drop_name(r"C:\Temp\readme.txt")


def test_parse_loose_time():
    dt = _parse_loose_time("2026-08-18 23:09:09")
    assert dt is not None
    assert dt.year == 2026 and dt.month == 8 and dt.day == 18


def test_system_conclusion_from_trace():
    from backend.services.threat_trace import build_system_conclusion

    out = build_system_conclusion({
        "query": "evil.exe",
        "matches": [{"name": "evil.exe", "pid": 99, "path": r"C:\temp\evil.exe"}],
        "evidence": [
            {
                "module": "finding",
                "title": "高危告警",
                "severity": "high",
                "confidence": CONF_STRONG,
                "confidence_label": "强",
                "confidence_reason": "告警含相同 PID",
            },
        ],
        "stats": {
            "processes": 1,
            "network": 0,
            "findings": 1,
            "files": 0,
            "drops": 0,
            "related_files": 0,
            "persist": 0,
            "exec": 0,
            "eventlog": 0,
            "confidence": {"strong": 1, "medium": 0, "weak": 0},
        },
        "graph": {"nodes": []},
    })
    assert out["mode"] == "system"
    assert out["risk_level"] in ("高", "严重", "中")
    assert "evil.exe" in out["summary"]
    assert out["highlights"]


def test_looks_like_path():
    assert looks_like_path(r"C:\Users\Public\Videos")
    assert looks_like_path(r"C:\Users\Public\Videos\fontdrvhost.exe")
    assert looks_like_path("/tmp/evil")
    assert not looks_like_path("fontdrvhost")
    assert not looks_like_path("1128")


def test_proc_matches_file_exact_and_cmdline():
    p = {
        "pid": 1128,
        "name": "fontdrvhost.exe",
        "path": r"C:\Users\Public\Videos\fontdrvhost.exe",
        "command_line": r"C:\Users\Public\Videos\fontdrvhost.exe -k",
    }
    assert _proc_matches_file(p, r"C:\Users\Public\Videos\fontdrvhost.exe")
    assert not _proc_matches_file(p, r"C:\Windows\System32\cmd.exe")
    p2 = {
        "pid": 99,
        "name": "cmd.exe",
        "path": r"C:\Windows\System32\cmd.exe",
        "command_line": r'cmd /c C:\Users\Public\Videos\fontdrvhost.exe',
    }
    assert _proc_matches_file(p2, r"C:\Users\Public\Videos\fontdrvhost.exe")


def test_pid_focus_tree_excludes_parents():
    from backend.services.threat_trace import _collect_tree_pids

    procs = {
        5008: {"pid": 5008, "name": "Mw.exe", "path": r"C:\ProgramData\User\Mw.exe", "ppid": 1700},
        1700: {"pid": 1700, "name": "svchost.exe", "path": r"C:\Windows\System32\svchost.exe", "ppid": 448},
        8316: {"pid": 8316, "name": "Mw.exe", "path": r"C:\ProgramData\User\Mw.exe", "ppid": 1700},
        5010: {"pid": 5010, "name": "child.exe", "path": r"C:\temp\child.exe", "ppid": 5008},
    }
    got = search_processes(list(procs.values()), q="5008")
    assert len(got) == 1 and got[0]["pid"] == 5008
    tree = _collect_tree_pids({5008}, procs, up=0, down=1)
    assert tree == {5008, 5010}


def test_persist_subtype_run_and_folder():
    from backend.services.threat_trace import _persist_subtype

    sid, label = _persist_subtype("startup", {
        "location": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "command": r"C:\Temp\evil.exe",
    })
    assert sid == "run"
    assert "Run" in label

    sid2, label2 = _persist_subtype("startup", {
        "location": r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        "command": r"C:\Temp\evil.exe",
    })
    assert sid2 == "startup_folder"
    assert "启动" in label2

    sid3, label3 = _persist_subtype("service", {"name": "Svc"})
    assert sid3 == "service"
    assert "服务" in label3


def test_item_exe_path_from_command():
    from backend.services.threat_trace import _item_exe_path

    p = _item_exe_path({"command": r'"C:\Users\Public\evil.exe" -s'})
    assert p.lower().endswith("evil.exe")
    p2 = _item_exe_path({"resolved_path": r"C:\Temp\a.exe", "command": "ignored"})
    assert p2.lower().endswith("a.exe")


def test_launch_confidence_and_edges():
    from backend.services.threat_trace import _attach_launch_edges, _launch_confidence

    conf, reason = _launch_confidence(
        {"name": "evil.exe", "path": r"C:\Users\Public\evil.exe"},
        exe_path=r"C:\Users\Public\evil.exe",
        command=r"C:\Users\Public\evil.exe -s",
    )
    assert conf == CONF_MEDIUM
    assert "路径" in reason or "命令" in reason

    nodes = [
        {
            "id": "startup:1",
            "type": "startup",
            "path": r"C:\Users\Public\evil.exe",
            "command": r"C:\Users\Public\evil.exe -s",
            "payload": {},
        },
        {
            "id": "proc:99",
            "type": "process",
            "label": "evil.exe",
            "path": r"C:\Users\Public\evil.exe",
            "payload": {"name": "evil.exe", "path": r"C:\Users\Public\evil.exe"},
        },
    ]
    edges = []
    n = _attach_launch_edges(nodes, edges)
    assert n == 1
    assert edges[0]["kind"] == "launch"
    assert edges[0]["from"] == "startup:1"
    assert edges[0]["to"] == "proc:99"


def test_system_conclusion_mentions_persist_chain():
    from backend.services.threat_trace import build_system_conclusion

    out = build_system_conclusion({
        "query": "evil.exe",
        "matches": [{"name": "evil.exe", "pid": 99, "path": r"C:\temp\evil.exe"}],
        "evidence": [],
        "stats": {
            "processes": 1,
            "network": 0,
            "findings": 0,
            "files": 1,
            "drops": 1,
            "related_files": 0,
            "persist": 1,
            "persist_write": 1,
            "launches": 1,
            "exec": 0,
            "eventlog": 0,
            "confidence": {"strong": 0, "medium": 1, "weak": 0},
        },
        "graph": {"nodes": []},
    })
    assert "自启动串链" in out["summary"]
    assert any("拉起" in r for r in out["recommendations"])
