#!/usr/bin/env python3
"""Run synthetic contract cases through real Wazuh logtest; never endpoint evidence."""
import copy
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def event(eid, fields, security=False):
    return {'win': {'system': {
        'providerName': 'Microsoft-Windows-Security-Auditing' if security else 'Microsoft-Windows-Sysmon',
        'channel': 'Security' if security else 'Microsoft-Windows-Sysmon/Operational',
        'eventID': str(eid), 'severityValue': 'AUDIT_SUCCESS' if security else 'INFORMATION',
        'computer': 'SYNTHETIC-CONTRACT-ONLY'}, 'eventdata': fields}}


def cases():
    ps = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    positive = [
        ('powershell-encoded', 100100, event(1, {'image': ps, 'commandLine': 'powershell.exe -EncodedCommand VwA='})),
        ('powershell-bypass', 100100, event(1, {'image': ps, 'commandLine': 'powershell.exe -ExecutionPolicy Bypass -Command whoami'})),
        ('run-key', 100110, event(13, {'targetObject': r'HKU\S-1-5-21-TEST\Software\Microsoft\Windows\CurrentVersion\Run\EDRLabHarmless'})),
        ('account-created', 100120, event(4720, {'targetUserName': 'edrlab_demo', 'subjectUserName': 'labadmin'}, True)),
        ('network-test-port', 100130, event(3, {'image': ps, 'destinationPort': '18080'})),
    ]
    result = [(name, rule, data, True) for name, rule, data in positive]
    for name, rule, data in positive:
        negative = copy.deepcopy(data)
        fields = negative['win']['eventdata']
        if rule == 100100:
            fields['commandLine'] = 'powershell.exe -NoProfile -Command Get-Date'
        elif rule == 100110:
            fields['targetObject'] = r'HKU\TEST\Software\Vendor\Preference'
        elif rule == 100120:
            negative['win']['system']['eventID'] = '4726'
        else:
            fields['destinationPort'] = '443'
        result.append((name + '-negative', rule, negative, False))
    # Missing fields must not silently turn into positive matches.
    for name, rule, data in positive:
        missing = copy.deepcopy(data)
        missing['win']['eventdata'] = {}
        if rule == 100120:
            del missing['win']['system']['eventID']
        result.append((name + '-missing', rule, missing, False))
    return result


def run_cases():
    destination = ROOT / 'evidence' / 'validation' / 'rule-tests'
    destination.mkdir(parents=True, exist_ok=True)
    results = []
    for name, expected, data, should_match in cases():
        raw = json.dumps(data)
        proc = subprocess.run(['docker', 'compose', '-f', 'compose.test.yaml', 'exec', '-T', 'rulecheck',
                               '/var/ossec/bin/wazuh-logtest'], input=raw + '\n',
                              text=True, capture_output=True, cwd=ROOT, timeout=30)
        output = proc.stdout + proc.stderr
        (destination / (name + '.txt')).write_text(output)
        found = f"id: '{expected}'" in output
        passed = proc.returncode == 0 and found == should_match and "name: 'json'" in output
        results.append({'case': name, 'expected_rule': expected, 'should_match': should_match,
                        'passed': passed, 'provenance': 'synthetic JSON; real Wazuh engine with test-only rule 60000 JSON bridge'})
    (destination / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))
    if not all(r['passed'] for r in results):
        raise SystemExit(1)


if __name__ == '__main__':
    compose = ['docker', 'compose', '-f', 'compose.test.yaml']
    try:
        subprocess.run(compose + ['up', '-d', '--wait', '--wait-timeout', '90'], cwd=ROOT, check=True)
        run_cases()
    finally:
        subprocess.run(compose + ['down'], cwd=ROOT, check=True)
