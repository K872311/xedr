# -*- coding: utf-8 -*-
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
uri = (ROOT / "static" / "logo_data_uri.txt").read_text(encoding="ascii").strip()


def patch(path: Path, patterns: list[tuple[str, str]]) -> None:
    html = path.read_text(encoding="utf-8")
    out = html
    for pat, repl in patterns:
        out = re.sub(pat, repl, out)
    if out == html:
        print("NO_CHANGE", path)
        return
    path.write_text(out, encoding="utf-8")
    print("UPDATED", path, "embeds", out.count("data:image/png;base64,"))


def main() -> None:
    repl = lambda m: m.group(0).split("=")[0] + '="' + uri + '"'  # noqa: E731 — unused
    # simpler: fixed replacements
    patch(
        ROOT / "index.html",
        [
            (r'href="/favicon\.png\?v=flower2"', f'href="{uri}"'),
            (r'href="/ZSYlogo\.png\?v=flower2"', f'href="{uri}"'),
            (r'src="/ZSYlogo\.png\?v=flower2"', f'src="{uri}"'),
        ],
    )
    patch(
        ROOT / "rules_admin" / "static" / "index.html",
        [
            (r'href="/static/favicon\.png\?v=flower2"', f'href="{uri}"'),
            (r'src="/static/ZSYlogo\.png\?v=flower2"', f'src="{uri}"'),
        ],
    )


if __name__ == "__main__":
    main()
