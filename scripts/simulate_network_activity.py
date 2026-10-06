#!/usr/bin/env python3
"""Linux fallback: real loopback sockets, helper-observed JSON (not kernel EDR)."""
import argparse
import datetime as dt
import getpass
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def client():
    for _ in range(6):
        with socket.create_connection(('127.0.0.1', 18080), timeout=5) as connection:
            connection.sendall(b'EDR-LAB\n')
        time.sleep(0.5)


def run(output):
    run_id = str(uuid.uuid4())
    output.parent.mkdir(parents=True, exist_ok=True)
    records = []
    command = [sys.executable, str(Path(__file__).resolve()), '--client']
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 18080))
        listener.listen(8)
        listener.settimeout(10)
        child = subprocess.Popen(command)
        try:
            for _ in range(6):
                connection, peer = listener.accept()
                with connection:
                    connection.settimeout(5)
                    payload = connection.recv(1024)
                record = {
                    'lab': {'source': 'edr-lab-network-observer', 'run_id': run_id,
                            'provenance': 'live-loopback-helper-observation'},
                    'timestamp': utc(), 'event': {'action': 'connection_accepted'},
                    'host': {'name': socket.gethostname()}, 'user': {'name': getpass.getuser()},
                    'process': {'pid': child.pid, 'parent_pid': os.getpid(),
                                'executable': sys.executable, 'command_line': ' '.join(command),
                                'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()},
                    'source': {'ip': peer[0], 'port': peer[1]},
                    'destination': {'ip': '127.0.0.1', 'port': 18080},
                    'network': {'protocol': 'tcp', 'received_bytes': len(payload)},
                    'attribution': 'client PID from subprocess launch; not kernel socket attribution',
                }
                records.append(record)
                with output.open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps(record) + '\n')
            if child.wait(timeout=10) != 0:
                raise RuntimeError('Client failed')
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
    destination = ROOT / 'evidence' / 'private' / run_id
    destination.mkdir(parents=True)
    raw = ''.join(json.dumps(record) + '\n' for record in records)
    (destination / 'network.jsonl').write_text(raw, encoding='utf-8')
    manifest = {'run_id': run_id, 'records': len(records), 'sha256': hashlib.sha256(raw.encode()).hexdigest(),
                'provenance': 'live loopback observer, not Sysmon; Wazuh ingestion separately verified'}
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))
    return records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--output', type=Path, default=ROOT / '.runtime/telemetry/network.jsonl')
    args = parser.parse_args()
    client() if args.client else run(args.output)
