#!/usr/bin/env python3
import yaml
import os
import json
from pathlib import Path

rules_dir = Path("C:/Users/Administrator/Desktop/rules")

event_categories = {
    "authentication": [],
    "process_execution": [],
    "account_manipulation": [],
    "service_task": [],
    "powershell": [],
    "network_rdp": [],
    "system": [],
    "wmi": [],
    "defender": [],
    "other": []
}

auth_events = {'4624', '4625', '4634', '4647', '4648', '4672', '4768', '4769', '4776', '4778', '4779', '4825', '4611'}
process_events = {'4688'}
account_events = {'4720', '4723', '4724', '4728', '4732', '4741', '4726', '4738', '4743', '4756', '4757', '4765', '4766'}
service_events = {'4697', '4698', '4699', '7045', '7031', '7034', '7040', '4696', '5145', '4695'}
powershell_events = {'4103', '4104', '400'}
network_events = {'5140', '5145', '5156', '5157', '1024', '1102', '302', '303', '21', '22', '23', '24', '25', '1149', '261'}
system_events = {'6008', '104', '12', '6005', '6006', '6009', '6013', '1102', '1001', '20001', '7031', '7034', '7040'}
wmi_events = {'5857', '5860', '5861'}

def get_dict_value(obj, key, default=None):
    """Safely get value from dict or return default"""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return default

def extract_selections(detection):
    """Extract selection criteria from detection block"""
    selections = {}
    if not isinstance(detection, dict):
        return selections

    for key, value in detection.items():
        if key.startswith('selection'):
            selections[key] = value
        elif key == 'filter' or key.startswith('filter_'):
            selections[key] = {'type': 'filter', 'data': value}
    return selections

def parse_detection(detection):
    """Parse detection logic into structured format"""
    result = {
        'selections': {},
        'filters': {},
        'condition_str': '',
        'field_conditions': []
    }

    if not isinstance(detection, dict):
        return result

    # Extract condition
    result['condition_str'] = detection.get('condition', '')

    # Parse selections and filters
    for key, value in detection.items():
        if key == 'condition':
            continue
        elif key.startswith('selection'):
            result['selections'][key] = value
        elif key.startswith('filter'):
            result['filters'][key] = value

    # Extract field conditions
    def walk_conditions(obj, path=''):
        items = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (list, dict, str, int)):
                    items.append({'field': k, 'operator': 'eq', 'value': v})
        return items

    for sel_name, sel_data in result['selections'].items():
        conditions = walk_conditions(sel_data)
        if conditions:
            result['field_conditions'].extend(conditions)

    return result

all_rules = []
errors = []

for f in sorted(rules_dir.glob("*.yml")):
    if f.name == 'parse_rules.py':
        continue
    try:
        with open(f, 'r', encoding='utf-8') as file:
            content = file.read()
            try:
                docs = list(yaml.safe_load_all(content))
            except Exception as ye:
                errors.append(f"YAML Error in {f.name}: {ye}")
                continue

            for doc in docs:
                if not doc or not isinstance(doc, dict):
                    continue

                # Extract rule data
                logsource = doc.get('logsource', {}) or {}
                detection = doc.get('detection', {}) or {}

                rule = {
                    'filename': f.name,
                    'title': doc.get('title', ''),
                    'description': doc.get('description', doc.get('details', '')),
                    'id': doc.get('id', ''),
                    'level': doc.get('level', 'info'),
                    'status': doc.get('status', ''),
                    'product': logsource.get('product', ''),
                    'service': logsource.get('service', ''),
                    'category': logsource.get('category', ''),
                    'falsepositives': doc.get('falsepositives', []),
                    'tags': doc.get('tags', []),
                    'references': doc.get('references', []),
                    'author': doc.get('author', ''),
                    'date': doc.get('date', ''),
                    'modified': doc.get('modified', ''),
                    'ruletype': doc.get('ruletype', '')
                }

                # Parse detection
                parsed_detection = parse_detection(detection)
                rule['detection'] = parsed_detection
                rule['condition'] = parsed_detection['condition_str']

                # Extract EventID and Channel
                event_ids = set()
                channels = set()

                def extract_from_obj(obj):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if k == 'EventID':
                                if isinstance(v, list):
                                    for eid in v:
                                        if eid:
                                            event_ids.add(str(eid))
                                elif v:
                                    event_ids.add(str(v))
                            elif k == 'Channel':
                                if isinstance(v, list):
                                    for ch in v:
                                        if ch:
                                            channels.add(str(ch).lower())
                                elif v:
                                    channels.add(str(v).lower())
                            elif isinstance(v, (dict, list)):
                                extract_from_obj(v)
                    elif isinstance(obj, list):
                        for item in obj:
                            extract_from_obj(item)

                extract_from_obj(detection)
                extract_from_obj(logsource)

                rule['event_ids'] = sorted(list(event_ids))
                rule['channels'] = sorted(list(channels))

                # Determine category from EventIDs
                category = 'other'
                for eid in event_ids:
                    eid_str = str(eid)
                    if eid_str in auth_events:
                        category = 'authentication'
                        break
                    elif eid_str in process_events:
                        category = 'process_execution'
                        break
                    elif eid_str in account_events:
                        category = 'account_manipulation'
                        break
                    elif eid_str in service_events:
                        category = 'service_task'
                        break
                    elif eid_str in powershell_events:
                        category = 'powershell'
                        break
                    elif eid_str in network_events:
                        category = 'network_rdp'
                        break
                    elif eid_str in wmi_events:
                        category = 'wmi'
                        break
                    elif eid_str in system_events:
                        category = 'system'
                        break

                # Override based on filename
                fname = f.name.lower()
                if 'secc_46' in fname or 'sec_46' in fname:
                    if any(e in fname for e in ['4624', '4625', '4634', '4647', '4648', '4611']):
                        category = 'authentication'
                    elif '4688' in fname:
                        category = 'process_execution'
                elif 'sec_47' in fname or 'sec_48' in fname:
                    category = 'authentication'
                elif 'sys_' in fname:
                    if '7045' in fname:
                        category = 'service_task'
                    else:
                        category = 'system'
                elif 'pwsh_' in fname or 'pwshclassic' in fname:
                    category = 'powershell'
                elif 'wmi_' in fname:
                    category = 'wmi'
                elif 'local' in fname and 'sess' in fname:
                    category = 'network_rdp'
                elif 'remote' in fname and 'conn' in fname:
                    category = 'network_rdp'
                elif 'rdp' in fname.lower() or 'rds_' in fname.lower():
                    category = 'network_rdp'
                elif 'defender_' in fname:
                    category = 'defender'
                elif 'bitscli' in fname:
                    category = 'service_task'
                elif 'tasksch' in fname:
                    category = 'service_task'

                rule['category'] = category
                event_categories[category].append(rule)
                all_rules.append(rule)
    except Exception as e:
        errors.append(f"Error in {f.name}: {e}")

# Output results
print("=" * 80)
print("WINDOWS EVENT LOG RULES SUMMARY")
print("=" * 80)
print(f"\nTotal rules parsed: {len(all_rules)}")
if errors:
    print(f"Errors encountered: {len(errors)}")
    for e in errors[:10]:
        print(f"  - {e}")

for cat, rules in event_categories.items():
    if not rules:
        continue
    print(f"\n{'='*80}")
    print(f"CATEGORY: {cat.upper()} ({len(rules)} rules)")
    print('='*80)
    for r in rules[:5]:
        eids = ','.join(r['event_ids']) if r['event_ids'] else 'N/A'
        ch = ','.join(r['channels']) if r['channels'] else 'Security'
        print(f"\n  File: {r['filename']}")
        print(f"  Title: {r['title']}")
        print(f"  Level: {r['level']}")
        print(f"  EventID: {eids}")
        print(f"  Channel: {ch}")
        print(f"  Tags: {', '.join(r['tags']) if r['tags'] else 'N/A'}")
        detection = r['detection']
        if detection and detection.get('field_conditions'):
            print(f"  Detection Fields:")
            for fc in detection['field_conditions'][:3]:
                print(f"    - {fc['field']}: {fc['value']}")

print("\n" + "="*80)
print("CATEGORY COUNTS")
print("="*80)
for cat, rules in event_categories.items():
    if rules:
        print(f"  {cat}: {len(rules)}")

# Save to JSON for analysis
output = {
    'summary': {
        'total': len(all_rules),
        'categories': {k: len(v) for k, v in event_categories.items() if v}
    },
    'rules': all_rules
}

with open('C:/Users/Administrator/Desktop/rules/parsed_rules.json', 'w', encoding='utf-8') as f:
    json.dump(output, f, indent=2, ensure_ascii=False, default=str)

print("\nParsed rules saved to: C:/Users/Administrator/Desktop/rules/parsed_rules.json")
