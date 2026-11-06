import re
import collections
from pathlib import Path

root = Path(r"D:\GeRen\web\rules\rules\protections-artifacts-main\behavior\rules\windows")
apis = collections.Counter()
n_api = 0
for p in root.glob("*.toml"):
    t = p.read_text(encoding="utf-8", errors="ignore")
    if "api where" not in t:
        continue
    n_api += 1
    for m in re.finditer(r'process\.Ext\.api\.name\s*==\s*"([^"]+)"', t):
        apis[m.group(1)] += 1
print("api_where_rules", n_api)
for name, c in apis.most_common(40):
    print(c, name)
