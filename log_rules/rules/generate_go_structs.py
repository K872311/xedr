#!/usr/bin/env python3
"""
Generate Go-compatible structured data from parsed YAML rules
Focus on compromise detection capabilities
"""
import json
import re

with open('C:/Users/Administrator/Desktop/rules/parsed_rules.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Chinese translations for rule title patterns
title_translations = {
    "Possible Token Impersonation": "可能的令牌模拟攻击",
    "Explicit Logon Attempt": "显式登录尝试",
    "Hidden User Account Created": "隐藏用户账户创建",
    "User Added To Global Domain Admins Grp": "用户添加到全局域管理员组",
    "User Added To Local Admin Grp": "用户添加到本地管理员组",
    "User Added To Local Domain Admins Grp": "用户添加到本地域管理员组",
    "Suspicious Service Name": "可疑服务名称",
    "Suspicious Service Path": "可疑服务路径",
    "Possible LOLBIN": "可能的LOLBIN滥用",
    "Log Cleared": "日志被清除",
    "Important Log File Cleared": "重要日志文件被清除",
    "User Guessing": "用户名猜测攻击",
    "PW Guessing": "密码猜测攻击",
    "PW Spray": "密码喷射攻击",
    "Failed Logon": "登录失败",
    "Possible RDP Hijacking": "可能的RDP劫持",
    "Possible AS-REP Roasting": "可能的AS-REP Roasting攻击",
    "Possible Kerberoasting": "可能的Kerberoasting攻击",
    "BSOD": "系统蓝屏",
    "Process Exec": "进程执行",
    "Svc Installed": "服务安装",
    "Task Created": "计划任务创建",
    "Task Deleted": "计划任务删除",
    "PwdSh Pipeline Exec": "PowerShell管道执行",
    "PwdSh Scriptblock": "PowerShell脚本块",
    "Potentially Malicious PwSh": "潜在恶意PowerShell",
    "WMI Filter To Consumer Binding": "WMI过滤器到消费者绑定",
    "RDP Logon": "RDP登录",
    "RDP Logoff": "RDP注销",
    "RDP Disconnect": "RDP断开连接",
}

def translate_title(title):
    """Translate rule title to Chinese"""
    if not title:
        return ""
    for en, cn in title_translations.items():
        if en.lower() in title.lower():
            return cn
    return title  # Return original if no match

def translate_description(desc):
    """Add Chinese description based on patterns"""
    if not desc:
        return ""
    # Pattern-based translations
    patterns = {
        r"token impersonation|impersonation": "令牌模拟攻击 - 检测工具如Cobalt Strike使用的令牌模拟技术",
        r"logon|login": "登录事件检测",
        r"hidden|hide": "隐藏账户检测",
        r"admin|administrator": "管理员权限变更检测",
        r"service|svc": "服务创建/修改检测",
        r"powershell|pwsh": "PowerShell执行检测",
        r"rdp.*hijack|hijack.*rdp": "RDP会话劫持检测",
        r"password.*guess|guess.*password": "密码猜测攻击检测",
        r"password.*spray|spray.*password": "密码喷射攻击检测",
        r"kerberoast": "Kerberoasting攻击检测",
        r"as-rep": "AS-REP Roasting攻击检测",
        r"lolbin|living off the land": "生活在大地(Living Off The Land)二进制滥用检测",
        r"log.*clear|clear.*log": "日志清除行为检测",
        r"meterpreter|getsystem": "Meterpreter getsystem提权检测",
    }
    for pattern, cn_desc in patterns.items():
        if re.search(pattern, desc, re.IGNORECASE):
            return cn_desc
    return "安全事件检测"

def get_severity_cn(sev):
    mapping = {
        "critical": "严重",
        "high": "高",
        "medium": "中",
        "low": "低",
        "informational": "信息"
    }
    return mapping.get(sev, sev)

def extract_detection_criteria(detection):
    """Extract detailed detection criteria"""
    criteria = []
    if not detection or not isinstance(detection, dict):
        return criteria

    selections = detection.get('selections', {})
    for name, sel_data in selections.items():
        if not isinstance(sel_data, dict):
            continue
        for field, value in sel_data.items():
            if field in ['Channel', 'EventID']:
                continue
            criterion = {
                'field': field,
                'value': value
            }
            # Parse field modifiers
            if '|' in field:
                parts = field.split('|')
                criterion['field'] = parts[0]
                criterion['operator'] = parts[1] if len(parts) > 1 else 'eq'
            else:
                criterion['operator'] = 'eq'
            criteria.append(criterion)
    return criteria

def is_compromise_detection(rule):
    """Determine if rule is critical for compromise detection"""
    level = rule.get('level', '')
    eids = rule.get('event_ids', [])

    # High/Critical severity are compromise indicators
    if level in ['critical', 'high']:
        return True

    # Medium severity with specific event IDs
    critical_eids = ['4625', '4648', '4688', '4720', '4728', '4732', '4724',
                     '4697', '4698', '4699', '7045', '4103', '4104', '5145',
                     '6008', '1102', '5861']
    if level == 'medium' and any(e in critical_eids for e in eids):
        return True

    return False

# Build structured rules
structured_rules = []
for rule in data['rules']:
    title = rule.get('title', '')
    desc = rule.get('description', '')
    tags = rule.get('tags') or []
    level = rule.get('level', 'informational')
    eids = rule.get('event_ids', [])
    channels = rule.get('channels', [])

    # Extract MITRE info
    tactics = []
    techniques = []
    for tag in tags:
        if isinstance(tag, str):
            if tag.startswith('attack.t'):
                techniques.append(tag.replace('attack.', ''))
            elif tag.startswith('attack.'):
                tactics.append(tag.replace('attack.', ''))

    structured_rule = {
        'id': rule.get('id', ''),
        'filename': rule.get('filename', ''),
        'title_en': title,
        'title_cn': translate_title(title),
        'description_en': desc[:200] if desc else '',
        'description_cn': translate_description(desc),
        'event_ids': eids,
        'channel': channels[0] if channels else 'Security',
        'severity': level,
        'severity_cn': get_severity_cn(level),
        'is_compromise_detection': is_compromise_detection(rule),
        'mitre_tactics': tactics,
        'mitre_techniques': techniques,
        'detection_criteria': extract_detection_criteria(rule.get('detection', {})),
        'condition_expr': rule.get('condition', ''),
        'false_positives': rule.get('falsepositives') or [],
        'references': rule.get('references') or [],
        'status': rule.get('status', ''),
        'category': rule.get('category', 'other'),
        'author': rule.get('author', '')
    }
    structured_rules.append(structured_rule)

# Group by category for Go code generation
def group_by_event_id(rules):
    """Group rules by primary event ID"""
    by_eid = {}
    for rule in rules:
        for eid in rule['event_ids']:
            if eid not in by_eid:
                by_eid[eid] = []
            by_eid[eid].append(rule)
    return by_eid

# Generate summary statistics
stats = {
    'total_rules': len(structured_rules),
    'by_category': {},
    'by_severity': {},
    'by_event_id': {},
    'compromise_detection_count': sum(1 for r in structured_rules if r['is_compromise_detection'])
}

# Count by category
for r in structured_rules:
    cat = r['category']
    stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1
    sev = r['severity']
    stats['by_severity'][sev] = stats['by_severity'].get(sev, 0) + 1

# Count by event ID
by_eid = group_by_event_id(structured_rules)
for eid, rules in by_eid.items():
    high_sev = [r for r in rules if r['severity'] in ['critical', 'high']]
    stats['by_event_id'][eid] = {
        'total': len(rules),
        'high_severity': len(high_sev),
        'has_compromise': any(r['is_compromise_detection'] for r in rules)
    }

# Output JSON
output = {
    'metadata': {
        'title': 'Windows Event Detection Rules - Structured Data',
        'title_cn': 'Windows安全事件检测规则结构化数据',
        'description': 'Hayabusa Sigma rules parsed for compromise detection',
        'description_cn': '用于失陷检测的Hayabusa Sigma规则解析结果',
        'generated': '2025-04-11',
        'source_count': len(data['rules'])
    },
    'statistics': stats,
    'rules_by_event_id': by_eid,
    'all_rules': structured_rules
}

# Save full JSON
with open('C:/Users/Administrator/Desktop/rules/windows_detection_rules.json', 'w', encoding='utf-8') as f:
    json.dump(output, f, indent=2, ensure_ascii=False)

# Generate Go code snippet
go_code = '''// Windows Event Detection Rules
// Auto-generated from Hayabusa Sigma rules
// Focus: Compromise Detection (失陷检测)

package detection

// Severity levels
type Severity string
const (
    SeverityCritical Severity = "critical"    // 严重
    SeverityHigh     Severity = "high"        // 高
    SeverityMedium   Severity = "medium"      // 中
    SeverityLow      Severity = "low"         // 低
    SeverityInfo     Severity = "informational" // 信息
)

// DetectionOperator defines how to compare field values
type DetectionOperator string
const (
    OpEq        DetectionOperator = "eq"        // 等于
    OpContains  DetectionOperator = "contains"  // 包含
    OpStartsWith DetectionOperator = "startswith" // 以...开始
    OpEndsWith  DetectionOperator = "endswith"  // 以...结束
    OpRegex     DetectionOperator = "re"        // 正则匹配
    OpIn        DetectionOperator = "in"        // 在列表中
    OpGt        DetectionOperator = "gt"        // 大于
    OpFieldRef  DetectionOperator = "fieldref"  // 字段引用
)

// DetectionCriterion is a single detection condition
type DetectionCriterion struct {
    Field    string            // Field name to check
    Operator DetectionOperator // Comparison operator
    Value    interface{}       // Value to compare against
}

// DetectionRule defines a Windows event detection rule
type DetectionRule struct {
    ID                  string               // Rule UUID
    Filename            string               // Source YAML filename
    TitleEN             string               // English title
    TitleCN             string               // Chinese title (翻译)
    DescriptionEN       string               // English description
    DescriptionCN       string               // Chinese description (翻译)
    EventIDs            []string             // Windows Event IDs
    Channel             string               // Event log channel
    Severity            Severity             // Severity level
    SeverityCN          string               // Chinese severity (严重/高/中/低/信息)
    IsCompromiseDetection bool               // Critical for compromise detection
    MITRETactics        []string             // MITRE ATT&CK tactics
    MITRETechniques     []string             // MITRE ATT&CK techniques
    DetectionCriteria   []DetectionCriterion // Detection conditions
    ConditionExpr       string               // Boolean expression (e.g., "selection AND NOT filter")
    FalsePositives      []string             // Known false positives
    References          []string             // References
    Status              string               // Rule status (stable/test/experimental)
    Category            string               // Event category
    Author              string               // Rule author
}

// EventIDToRules maps Event IDs to their detection rules
var EventIDToRules = map[string][]DetectionRule{
'''

# Add EventID mappings
for eid in sorted(by_eid.keys(), key=lambda x: int(x) if x.isdigit() else 99999):
    rules = by_eid[eid]
    go_code += f'\t"{eid}": {{\n'
    for r in rules[:5]:  # Limit to 5 per EventID
        go_code += f'\t\t{{\n'
        go_code += f'\t\t\tID: "{r["id"]}",\n'
        go_code += f'\t\t\tTitleEN: "{r["title_en"].replace(chr(34), chr(92)+chr(34))}",\n'
        go_code += f'\t\t\tTitleCN: "{r["title_cn"].replace(chr(34), chr(92)+chr(34))}",\n'
        go_code += f'\t\t\tSeverity: "{r["severity"]}",\n'
        go_code += f'\t\t\tIsCompromiseDetection: {str(r["is_compromise_detection"]).lower()},\n'
        go_code += f'\t\t}},\n'
    go_code += f'\t}},\n'

go_code += '''}
'''

# Save Go code
with open('C:/Users/Administrator/Desktop/rules/detection_rules.go', 'w', encoding='utf-8') as f:
    f.write(go_code)

# Print summary
print("=" * 80)
print("STRUCTURED DATA GENERATION COMPLETE")
print("=" * 80)
print(f"\nTotal Rules Processed: {stats['total_rules']}")
print(f"Compromise Detection Rules: {stats['compromise_detection_count']}")
print(f"Unique Event IDs: {len(by_eid)}")

print("\nBy Category:")
for cat, count in sorted(stats['by_category'].items()):
    print(f"  - {cat}: {count} rules")

print("\nBy Severity:")
for sev, count in sorted(stats['by_severity'].items(),
                         key=lambda x: ['critical', 'high', 'medium', 'low', 'informational'].index(x[0]) if x[0] in ['critical', 'high', 'medium', 'low', 'informational'] else 99):
    print(f"  - {sev}: {count} rules")

print("\nTop Event IDs (by rule count):")
sorted_eids = sorted(stats['by_event_id'].items(),
                     key=lambda x: x[1]['total'], reverse=True)[:10]
for eid, info in sorted_eids:
    high = info['high_severity']
    comp = "[COMPROMISE]" if info['has_compromise'] else ""
    print(f"  - EventID {eid}: {info['total']} rules (High: {high}) {comp}")

print("\n" + "=" * 80)
print("OUTPUT FILES:")
print("=" * 80)
print("1. C:/Users/Administrator/Desktop/rules/windows_detection_rules.json")
print("   - Full structured data in JSON format")
print("\n2. C:/Users/Administrator/Desktop/rules/detection_rules.go")
print("   - Go struct definitions and EventID mappings")
