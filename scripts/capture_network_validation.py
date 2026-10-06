#!/usr/bin/env python3
"""Export and verify latest live helper run; publish explicitly redacted evidence."""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import time
from verify_ingestion import verify

ROOT = Path(__file__).resolve().parents[1]


def alert_extract(alert):
    """Keep actual comparison fields so public evidence can be checked offline."""
    data = alert['data']
    return {'timestamp': alert['timestamp'], 'id': alert.get('id'), 'rule': alert['rule'],
            'agent': {'id': alert['agent']['id'], 'name': 'MANAGER-REDACTED'},
            'location': alert['location'], 'lab_run_id': data['lab']['run_id'],
            'source_port': data['source']['port'],
            'data': {**{key: copy.deepcopy(data[key]) for key in
                       ('lab', 'timestamp', 'event', 'source', 'destination')},
                     'process': {'pid': data['process']['pid']}}}


def main():
    candidates = list((ROOT / 'evidence/private').glob('*/network.jsonl'))
    if not candidates:
        raise SystemExit('Run scripts/simulate_network_activity.py first')
    path = max(candidates, key=lambda p: p.stat().st_mtime_ns)
    events = [json.loads(s) for s in path.read_text().splitlines()]
    run_id = events[0]['lab']['run_id']
    last_error = None
    for _ in range(15):
        result = subprocess.run(['docker', 'compose', 'exec', '-T', 'manager', 'cat',
                                 '/var/ossec/logs/alerts/alerts.json'], capture_output=True, text=True, cwd=ROOT)
        if result.returncode:
            raise SystemExit(result.stderr)
        alerts = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        alerts = [a for a in alerts if a.get('data', {}).get('lab', {}).get('run_id') == run_id]
        try:
            summary = verify(events, alerts)
            break
        except ValueError as error:
            last_error = error
            time.sleep(2)
    else:
        raise SystemExit(f'Ingestion NOT VERIFIED: {last_error}')
    (path.parent / 'alerts.jsonl').write_text(''.join(json.dumps(a) + '\n' for a in alerts))
    summary.update({'verified_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                    'first_event': events[0]['timestamp'], 'last_event': events[-1]['timestamp'],
                    'raw_event_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                    'duration_seconds': (dt.datetime.fromisoformat(events[-1]['timestamp']) -
                                         dt.datetime.fromisoformat(events[0]['timestamp'])).total_seconds(),
                    'redactions': 'host/user labels and repository path replaced; timestamps, PIDs, ports, executable hash retained'})
    public = ROOT / 'evidence/validation/live-network'
    public.mkdir(parents=True, exist_ok=True)
    sanitized = copy.deepcopy(events)
    for event in sanitized:
        event['host']['name'] = 'LAB-HOST-REDACTED'
        event['user']['name'] = 'LAB-USER-REDACTED'
        event['process']['command_line'] = event['process']['command_line'].replace(str(ROOT), '<REPOSITORY>')
    # Publish the relevant real alert fields, explicitly as an extract rather than raw alerts.
    extracts = [alert_extract(a) for a in alerts]
    (public / 'events.redacted.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in sanitized))
    (public / 'alerts.extract.jsonl').write_text(''.join(json.dumps(a) + '\n' for a in extracts))
    (public / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
