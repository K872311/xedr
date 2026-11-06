#!/usr/bin/env python3
import json
import re

with open('C:/Users/Administrator/Desktop/rules/parsed_rules.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

def translate_severity(level):
    trans = {
        'critical': '严重',
        'high': '高',
        'medium': '中',
        'low': '低',
        'informational': '信息'
    }
    return trans.get(level, level)

def categorize_by_event(rules):
    categories = {
        'authentication': [],
        'process_execution': [],
        'account_manipulation': [],
        'service_task': [],
        'powershell': [],
        'network_rdp': [],
        'system': [],
        'wmi': [],
        'defender': [],
        'other': []
    }

    for rule in rules:
        cat = rule.get('category', 'other')
        if cat in categories:
            categories[cat].append(rule)
        else:
            categories['other'].append(rule)
    return categories

def get_mitre_info(tags):
    tactics = []
    techniques = []
    if tags:
        for tag in tags:
            if isinstance(tag, str):
                if tag.startswith('attack.t'):
                    techniques.append(tag.replace('attack.', ''))
                elif tag.startswith('attack.'):
                    tactics.append(tag.replace('attack.', ''))
    return tactics, techniques

def extract_detection_fields(detection):
    fields = []
    if not detection or not isinstance(detection, dict):
        return fields

    selections = detection.get('selections', {})
    for sel_name, sel_data in selections.items():
        if isinstance(sel_data, dict):
            for field, value in sel_data.items():
                if field in ['Channel', 'EventID']:
                    continue
                if isinstance(value, list):
                    fields.append({'field': field, 'operator': 'in', 'values': value})
                elif isinstance(value, str) and '|' in field:
                    # Parse field|operator:value pattern
                    parts = field.split('|')
                    if len(parts) == 2:
                        fields.append({'field': parts[0], 'operator': parts[1], 'value': value})
                else:
                    fields.append({'field': field, 'operator': 'eq', 'value': value})
    return fields

# Category info with Chinese translations
category_info = {
    'authentication': {'name': 'Authentication Events', 'name_cn': '认证事件', 'desc': '账户登录、认证相关事件'},
    'process_execution': {'name': 'Process Execution Events', 'name_cn': '进程执行事件', 'desc': '进程创建、命令行执行相关事件'},
    'account_manipulation': {'name': 'Account Manipulation Events', 'name_cn': '账户操作事件', 'desc': '账户创建、密码更改、组成员变更等事件'},
    'service_task': {'name': 'Service/Task Events', 'name_cn': '服务/计划任务事件', 'desc': '服务安装、计划任务创建/执行等事件'},
    'powershell': {'name': 'PowerShell Events', 'name_cn': 'PowerShell事件', 'desc': 'PowerShell脚本执行相关事件'},
    'network_rdp': {'name': 'Network/RDP Events', 'name_cn': '网络/RDP事件', 'desc': '网络访问、RDP连接等事件'},
    'system': {'name': 'System Events', 'name_cn': '系统事件', 'desc': '系统启动、关闭、日志清除等事件'},
    'wmi': {'name': 'WMI Events', 'name_cn': 'WMI事件', 'desc': 'WMI活动、持久化相关事件'},
    'defender': {'name': 'Defender Events', 'name_cn': 'Defender安全事件', 'desc': 'Windows Defender检测事件'},
    'other': {'name': 'Other Events', 'name_cn': '其他事件', 'desc': '其他安全相关事件'}
}

severity_trans = {
    'critical': '严重',
    'high': '高',
    'medium': '中',
    'low': '低',
    'informational': '信息'
}

categories = categorize_by_event(data['rules'])

# Print comprehensive summary
output = []

output.append("=" * 100)
output.append("WINDOWS EVENT DETECTION RULES - COMPREHENSIVE SUMMARY")
output.append("Windows安全事件检测规则综合汇总")
output.append("=" * 100)
output.append(f"\nTotal Rules: {len(data['rules'])} rules parsed")
output.append("=" * 100)

# Critical event IDs for compromise detection
critical_eids = set(['4624', '4625', '4648', '4688', '4720', '4728', '4732', '4724',
                      '4697', '4698', '4699', '7045', '4103', '4104', '5140', '5145',
                      '6008', '1102', '4692', '4647', '4768', '4769', '4776'])

for cat_name, cat_rules in categories.items():
    if not cat_rules:
        continue

    info = category_info.get(cat_name, {'name': cat_name, 'name_cn': cat_name, 'desc': ''})

    output.append(f"\n{'='*100}")
    output.append(f"CATEGORY: {info['name']}")
    output.append(f"分类: {info['name_cn']}")
    output.append(f"Description: {info['desc']}")
    output.append(f"Total Rules: {len(cat_rules)}")
    output.append('='*100)

    # Group by severity
    by_severity = {'critical': [], 'high': [], 'medium': [], 'low': [], 'informational': []}
    for r in cat_rules:
        sev = r.get('level', 'informational')
        if sev not in by_severity:
            sev = 'informational'
        by_severity[sev].append(r)

    # Print high/critical first
    for sev in ['critical', 'high', 'medium', 'low', 'informational']:
        rules = by_severity.get(sev, [])
        if not rules:
            continue

        sev_cn = severity_trans.get(sev, sev)
        output.append(f"\n[{sev.upper()} / {sev_cn}] Severity Rules ({len(rules)}):")
        output.append("-" * 80)

        for r in rules[:15]:  # Limit to first 15 per severity
            eids = r.get('event_ids', [])
            eid_str = ','.join(eids) if eids else 'N/A'
            channel = ','.join(r.get('channels', ['Security'])) if r.get('channels') else 'Security'

            # Check if this is compromise-related
            is_compromise = any(e in critical_eids for e in eids) and sev in ['critical', 'high', 'medium']

            output.append(f"\n  Title (EN): {r.get('title', 'N/A')}")
            output.append(f"  标题 (CN): {r.get('title', 'N/A')}")
            output.append(f"  EventID: {eid_str}")
            output.append(f"  Channel: {channel}")
            output.append(f"  Severity: {sev} / {sev_cn}")
            if is_compromise:
                output.append(f"  [COMPROMISE DETECTION / 失陷检测] YES")

            # MITRE tags
            tags = r.get('tags', [])
            if tags:
                tactics, techniques = get_mitre_info(tags)
                if tactics or techniques:
                    output.append(f"  MITRE ATT&CK: Tactics={tactics}, Techniques={techniques}")

            # Detection logic
            detection = r.get('detection', {})
            cond_expr = r.get('condition', '')
            if cond_expr:
                output.append(f"  Condition: {cond_expr}")

            # Detection fields
            det_fields = extract_detection_fields(detection)
            if det_fields:
                output.append(f"  Detection Criteria:")
                for df in det_fields[:5]:
                    if 'values' in df:
                        output.append(f"    - {df['field']} {df['operator']} {df['values']}")
                    else:
                        output.append(f"    - {df['field']} {df['operator']} {df.get('value', '')}")

            # False positives
            fp = r.get('falsepositives', [])
            if fp and fp != [None]:
                output.append(f"  False Positives: {', '.join(fp)[:100]}")

output.append("\n" + "="*100)
output.append("END OF SUMMARY")
output.append("="*100)

# Print to console
print('\n'.join(output))

# Save to file
with open('C:/Users/Administrator/Desktop/rules/rules_summary.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(output))

print(f"\n\nSummary saved to: C:/Users/Administrator/Desktop/rules/rules_summary.txt")
