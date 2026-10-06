#!/usr/bin/env python3
"""Compare one real helper run against exported Wazuh alerts, never fixture inputs."""
import argparse
import json
from pathlib import Path


def connection_key(event):
    """Compare source-event identity and rule fields, normalizing decoder numbers."""
    try:
        if (event['lab']['source'] != 'edr-lab-network-observer'
                or event['event']['action'] != 'connection_accepted'
                or event['destination']['ip'] != '127.0.0.1'
                or str(event['destination']['port']) != '18080'):
            raise ValueError('Evidence does not satisfy rule 100140 fields')
        return tuple(str(value) for value in (
            event['lab']['run_id'], event['timestamp'], event['process']['pid'],
            event['source']['ip'], event['source']['port'],
            event['destination']['ip'], event['destination']['port']))
    except (KeyError, TypeError) as error:
        raise ValueError('Missing required connection evidence fields') from error


def verify(events, alerts):
    if not events:
        raise ValueError('No events')
    run_ids = {e['lab']['run_id'] for e in events}
    if len(run_ids) != 1:
        raise ValueError('Supply a single-run evidence file')
    expected = {connection_key(e) for e in events}
    if len(expected) != len(events):
        raise ValueError('Duplicate source events; supply unique connection evidence')
    observed = set()
    matched = []
    for alert in alerts:
        data = alert.get('data', {})
        if str(alert.get('rule', {}).get('id')) != '100140' or data.get('lab', {}).get('run_id') not in run_ids:
            continue
        observed.add(connection_key(data))
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
