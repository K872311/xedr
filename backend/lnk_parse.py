"""Windows .lnk 快捷方式解析（MS-SHLLINK，供启动项链路补全）。"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Optional, Tuple


def parse_lnk_file(path: str) -> Tuple[str, str, bool]:
    """返回 (target_path, arguments, is_valid)。"""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return "", "", False
    if len(data) < 76:
        return "", "", False
    if data[0:4] != b"\x4c\x00\x00\x00":
        return "", "", False
    clsid = bytes([
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ])
    if data[4:20] != clsid:
        return "", "", False

    flags = struct.unpack_from("<I", data, 20)[0]
    is_unicode = bool(flags & 0x80)
    offset = 76

    if flags & 0x01:
        if offset + 2 > len(data):
            return "", "", True
        id_size = struct.unpack_from("<H", data, offset)[0]
        offset += 2 + id_size

    target = ""
    if flags & 0x02:
        if offset + 4 > len(data):
            return "", "", True
        link_size = struct.unpack_from("<I", data, offset)[0]
        if link_size >= 28 and offset + link_size <= len(data):
            target = _parse_link_info_local(data[offset : offset + link_size])
        offset += link_size

    arguments = ""
    if flags & 0x04:
        _, offset = _read_string_data(data, offset, is_unicode)
    if flags & 0x08:
        rel, offset = _read_string_data(data, offset, is_unicode)
        if not target:
            target = rel
    if flags & 0x10:
        _, offset = _read_string_data(data, offset, is_unicode)
    if flags & 0x20:
        arguments, offset = _read_string_data(data, offset, is_unicode)
    return target.strip(), arguments.strip(), True


def _parse_link_info_local(chunk: bytes) -> str:
    if len(chunk) < 28:
        return ""
    link_flags = struct.unpack_from("<I", chunk, 8)[0]
    if not (link_flags & 0x01):
        return ""
    base_off = struct.unpack_from("<I", chunk, 16)[0]
    if base_off == 0 or base_off >= len(chunk):
        return ""
    end = base_off
    while end < len(chunk) and chunk[end] != 0:
        end += 1
    return chunk[base_off:end].decode("utf-8", errors="replace")


def _read_string_data(data: bytes, offset: int, is_unicode: bool) -> Tuple[str, int]:
    if offset + 2 > len(data):
        return "", offset
    char_count = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if char_count == 0:
        return "", offset
    if is_unicode:
        byte_count = char_count * 2
        if offset + byte_count > len(data):
            return "", offset
        raw = data[offset : offset + byte_count]
        offset += byte_count
        chars = []
        for i in range(0, len(raw), 2):
            chars.append(struct.unpack_from("<H", raw, i)[0])
        return "".join(chr(c) for c in chars if c), offset
    if offset + char_count > len(data):
        return "", offset
    s = data[offset : offset + char_count].decode("latin-1", errors="replace")
    return s, offset + char_count


def resolve_lnk_target(path: str) -> Optional[str]:
    target, _, ok = parse_lnk_file(path)
    if ok and target:
        return target
    return None
