# Web / 中间件应用日志规则（Windows Server / Linux Server「应用日志」模块）
#
# 放置：本目录下 *.json（当前：rules-applogs-web-v1.json）
# 加载：backend/applog_rules.py
# 匹配：分析管线 matchers/applogs.py；上传后即时 rematch
#
# 规则字段（L1 原文）：
#   id, name, severity, enabled, appliesTo, textContainsAny/All,
#   textNotContainsAny, textRegex, fileNameContainsAny, reason, score
