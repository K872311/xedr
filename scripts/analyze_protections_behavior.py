# -*- coding: utf-8 -*-
import re
import collections
from pathlib import Path

root = Path(r"D:\GeRen\web\rules\rules\protections-artifacts-main\behavior\rules\windows")
first_token = collections.Counter()
needs = collections.Counter()
no_query = 0
files = list(root.glob("*.toml"))

for p in files:
    t = p.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"query = '''(.*?)'''", t, re.S)
    if not m:
        no_query += 1
        continue
    q = m.group(1).strip()
    if " where " in q:
        ft = q.split(" where ")[0].strip().split("\n")[-1].split()[0]
    else:
        ft = q.split()[0] if q else "EMPTY"
    first_token[ft] += 1
    for kw in (
        "sequence by",
        "correlation",
        "library where",
        "api where",
        "file where",
        "registry where",
        "network where",
        "dns where",
        "authentication where",
        "process where",
    ):
        if kw in q:
            needs[kw] += 1
    for field in (
        "process.parent.code_signature",
        "file.Ext",
        "dll.Ext",
        "process.Ext",
        "process.Ext.malware_classification",
        "user.id",
        "ImageLoaded",
        "registry.data",
    ):
        if field in q:
            needs["field:" + field] += 1

print("files", len(files), "no_query", no_query)
print("first_token", first_token.most_common(20))
print("needs", needs.most_common(30))

# conversion via same logic as backend.elastic_detection_import
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tomllib
from backend import elastic_detection_import as edi

stats = {"total": 0, "convertible": 0, "reference": 0, "unsupported": 0}
agent_n = evm_n = 0
convertible_samples = []
for p in files:
    with open(p, "rb") as f:
        doc = tomllib.load(f)
    rule = doc.get("rule")
    if not isinstance(rule, dict):
        continue
    if "rule_id" not in rule and rule.get("id"):
        rule = dict(rule)
        rule["rule_id"] = rule["id"]
    cr = edi.convert_elastic_rule(rule, rel_path="protections/" + p.name)
    stats["total"] += 1
    stats[cr.status] = stats.get(cr.status, 0) + 1
    if cr.agent_rule:
        agent_n += 1
    if cr.evm_rule:
        evm_n += 1
    if cr.status == "convertible" and len(convertible_samples) < 8:
        convertible_samples.append((p.name, rule.get("name"), cr.reason, bool(cr.agent_rule), bool(cr.evm_rule)))

print("convert_stats", stats, "with_agent", agent_n, "with_evm", evm_n)
for s in convertible_samples:
    print(" sample", s)

buckets = collections.Counter()
for p in files:
    with open(p, "rb") as f:
        doc = tomllib.load(f)
    q = str(doc.get("rule", {}).get("query") or "")
    if "api where" in q or "library where" in q:
        buckets["needs_api_or_dll"] += 1
    elif "sequence by" in q or "[process" in q:
        buckets["needs_sequence"] += 1
    elif re.search(r"^\s*process\s+where", q, re.M):
        buckets["process_where_only"] += 1
    elif re.search(r"^\s*registry\s+where", q, re.M):
        buckets["registry_where"] += 1
    elif re.search(r"^\s*file\s+where", q, re.M):
        buckets["file_where"] += 1
    else:
        buckets["other"] += 1
print("telemetry_buckets", dict(buckets))
