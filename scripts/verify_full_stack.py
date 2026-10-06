#!/usr/bin/env python3
"""Check local indexer authentication and dashboard service without printing credentials."""
import base64
import datetime as dt
import json
from pathlib import Path
import ssl
import subprocess
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    credentials = json.loads((ROOT / '.runtime/full-stack-credentials.json').read_text())
    compose = ['docker', 'compose', '-f', str(ROOT / '.runtime/wazuh-docker/single-node/docker-compose.yml')]
    # Certificate generation assigns container ownership. Read only the public CA
    # through the running dashboard; never relax permissions on private keys.
    ca = subprocess.run(compose + ['exec', '-T', 'wazuh.dashboard', 'cat',
                                   '/usr/share/wazuh-dashboard/certs/root-ca.pem'],
                        text=True, capture_output=True, check=True).stdout
    context = ssl.create_default_context(cadata=ca)
    # Upstream lab CA lacks the keyUsage extension required by Python 3.13+
    # strict mode. Retain CA-chain verification with OpenSSL's compatibility mode.
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    # Local transport is deliberately loopback; validate the generated CA chain.
    # The upstream certificates name services rather than this loopback URL.
    context.check_hostname = False
    token = base64.b64encode(('admin:' + credentials['admin']).encode()).decode()
    def get(url):
        req = urllib.request.Request(url, headers={'Authorization': 'Basic ' + token})
        with urllib.request.urlopen(req, context=context, timeout=15) as response:
            return response.status, json.load(response)
    try:
        code, health = get('https://127.0.0.1:9200/_cluster/health')
        dashboard_code, dashboard = get('https://127.0.0.1:8443/api/status')
    except (OSError, urllib.error.URLError, ValueError) as error:
        raise SystemExit(f'Full stack NOT VERIFIED: {type(error).__name__}: {error}. Check Compose logs and retry.')
    overall = dashboard.get('status', {}).get('overall', {})
    state = overall.get('state', overall.get('level', 'unknown'))
    api = subprocess.run(compose + ['exec', '-T', 'wazuh.manager', '/bin/sh', '-c',
                          'curl --silent --insecure --user "$API_USERNAME:$API_PASSWORD" --output /dev/null --write-out "%{http_code}" https://127.0.0.1:55000/security/user/authenticate'],
                         text=True, capture_output=True, check=True).stdout.strip()
    if code != 200 or health.get('status') not in ('green', 'yellow') or dashboard_code != 200 or state not in ('green', 'available') or api != '200':
        raise SystemExit(f'Full stack NOT VERIFIED: indexer={health.get("status")}, dashboard={state}')
    summary = {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'status': 'PASS',
               'indexer_http': code, 'indexer_health': health['status'],
               'dashboard_http': dashboard_code, 'dashboard_state': state,
               'manager_api_auth_http': int(api),
               'scope': 'authenticated localhost indexer and dashboard status APIs; no Windows telemetry or screenshots',
               'tls': 'generated CA chain validated in compatibility mode (CA lacks keyUsage); service-name/loopback hostname difference explicitly allowed; internal manager API probe uses its loopback self-signed certificate'}
    destination = ROOT / 'evidence/validation/full-stack.json'
    destination.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
