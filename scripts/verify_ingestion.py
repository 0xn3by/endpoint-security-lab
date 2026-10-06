#!/usr/bin/env python3
"""Compare one real helper run against exported Wazuh alerts, never fixture inputs."""
import argparse
import json
from pathlib import Path


def verify(events, alerts):
    if not events:
        raise ValueError('No events')
    run_ids = {e['lab']['run_id'] for e in events}
    if len(run_ids) != 1:
        raise ValueError('Supply a single-run evidence file')
    expected = {(str(e['process']['pid']), str(e['source']['port'])) for e in events}
    observed = set()
    matched = []
    for alert in alerts:
        data = alert.get('data', {})
        if str(alert.get('rule', {}).get('id')) != '100140' or data.get('lab', {}).get('run_id') not in run_ids:
            continue
        observed.add((str(data['process']['pid']), str(data['source']['port'])))
        matched.append(alert)
    if expected != observed:
        raise ValueError(f'Missing/extra evidence: expected {expected}, observed {observed}')
    return {'run_id': next(iter(run_ids)), 'unique_connections': len(expected), 'matching_alerts': len(matched),
            'rule': '100140', 'status': 'PASS', 'scope': 'helper JSON -> manager localfile -> Wazuh alert; no Windows agent'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('events', type=Path)
    p.add_argument('alerts', type=Path)
    a = p.parse_args()
    print(json.dumps(verify([json.loads(s) for s in a.events.read_text().splitlines() if s.strip()],
                            [json.loads(s) for s in a.alerts.read_text().splitlines() if s.strip()]), indent=2))
