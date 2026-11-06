# -*- coding: utf-8 -*-
"""Parse exported HTML report findings and flag likely false positives."""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from html import unescape
from pathlib import Path

HTML = Path(r"D:\360极速浏览器X下载\t1_2026-08-13_03-52-30+08-00.html")
OUT = Path(r"D:\GeRen\AI\配套工具脚本\应急工具\rules\sigma_high_priority\fp_review_t1.json")


def main() -> None:
    html = HTML.read_text(encoding="utf-8", errors="replace")
    # cards: <article class="finding ..."> ... </article>
    arts = re.findall(
        r'<article class="finding[^"]*">(.*?)</article>',
        html,
        flags=re.I | re.S,
    )
    rows = []
    for a in arts:
        sev_m = re.search(r'<span class="sev">([^<]+)</span>', a)
        cat_m = re.search(r'<span class="cat">([^<]+)</span>', a)
        title_m = re.search(r'<strong>([^<]+)</strong>', a)
        evs = re.findall(r"<li>(.*?)</li>", a, flags=re.S)
        evs = [unescape(re.sub(r"<[^>]+>", "", x)).strip() for x in evs]
        rows.append(
            {
                "severity": (sev_m.group(1) if sev_m else "").strip().upper(),
                "category": unescape(cat_m.group(1) if cat_m else "").strip(),
                "title": unescape(title_m.group(1) if title_m else "").strip(),
                "evidence": evs[:8],
                "count": len(evs),
            }
        )

    by_title = defaultdict(list)
    for r in rows:
        by_title[r["title"]].append(r)

    # Heuristic FP tagging
    fp_reasons = []

    def mark(title_sub: str, reason: str, severity_hint: str = "high"):
        for t, items in by_title.items():
            if title_sub.lower() in t.lower():
                fp_reasons.append(
                    {
                        "title": t,
                        "hits": sum(x["count"] for x in items),
                        "severity": items[0]["severity"],
                        "category": items[0]["category"],
                        "reason": reason,
                        "sample": (items[0]["evidence"] or [])[:3],
                        "action": severity_hint,
                    }
                )

    # Known noisy registry / env / KnownDlls / LoadAppInit
    mark("Environment", "系统环境变量正常项（Path/OS/PATHEXT 等），非持久化恶意", "disable_or_whitelist")
    mark("KnownDlls", "KnownDlls 默认系统 DLL 列表被整表匹配，正常机器也会命中", "disable_rule")
    mark("LoadAppInit", "LoadAppInit_DLLs=0 是安全默认值，不应告警", "disable_rule")
    mark("Windows\\\\Load", "同上 Load/Run 类键值默认存在", "tighten")
    mark("AppInit_DLLs", "空或 0 的 AppInit 不是威胁", "disable_or_whitelist")

    # Sigma/keyword noise common patterns
    for t, items in by_title.items():
        blob = " ".join([" ".join(x["evidence"]) for x in items]).lower()
        title = t
        # LOLBin alone without suspicious args
        if any(x in title.lower() for x in ("rundll32", "regsvr32", "mshta", "wscript", "cscript")):
            if "temp" not in blob and "http" not in blob and "javascript:" not in blob:
                fp_reasons.append(
                    {
                        "title": title,
                        "hits": sum(x["count"] for x in items),
                        "severity": items[0]["severity"],
                        "category": items[0]["category"],
                        "reason": "常见系统/安装程序也会调用该 LOLBin，证据侧缺少可疑参数/路径",
                        "sample": (items[0]["evidence"] or [])[:3],
                        "action": "review",
                    }
                )
        # OneDrive / Microsoft signed paths
        if "onedrive" in blob or "\\microsoft\\" in blob and "temp" not in blob:
            if "可疑文件" in items[0]["category"] or "文件" in title:
                fp_reasons.append(
                    {
                        "title": title,
                        "hits": sum(x["count"] for x in items),
                        "severity": items[0]["severity"],
                        "category": items[0]["category"],
                        "reason": "Microsoft/OneDrive 等常规路径易误报",
                        "sample": (items[0]["evidence"] or [])[:3],
                        "action": "whitelist_path",
                    }
                )

    # Dedup by title
    seen = set()
    uniq = []
    for x in fp_reasons:
        if x["title"] in seen:
            continue
        seen.add(x["title"])
        uniq.append(x)

    # Summary all titles
    titles = []
    for t, items in sorted(by_title.items(), key=lambda kv: -sum(x["count"] for x in kv[1])):
        titles.append(
            {
                "title": t,
                "category": items[0]["category"],
                "severity": items[0]["severity"],
                "groups": len(items),
                "evidence_items": sum(x["count"] for x in items),
                "sample": (items[0]["evidence"] or [])[:2],
            }
        )

    sev_c = Counter(r["severity"] for r in rows)
    cat_c = Counter(r["category"] for r in rows)

    out = {
        "report": str(HTML),
        "finding_cards": len(rows),
        "unique_titles": len(by_title),
        "severity_counts": dict(sev_c),
        "category_counts": dict(cat_c),
        "likely_false_positives": uniq,
        "all_titles_top": titles[:80],
    }
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print("cards", len(rows), "titles", len(by_title))
    print("sev", dict(sev_c))
    print("cat", dict(cat_c))
    print("FP candidates", len(uniq))
    for x in uniq[:30]:
        print("-", x["severity"], x["title"][:60], "|", x["reason"][:40], "| hits", x["hits"])
    print("TOP titles:")
    for x in titles[:25]:
        print(f"  [{x['severity']}] {x['category']} :: {x['title'][:70]}  (n={x['evidence_items']})")


if __name__ == "__main__":
    main()
