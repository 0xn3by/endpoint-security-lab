#!/usr/bin/env python3
"""Prepare pinned official stack in ignored runtime directory; does not start services."""
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[1]
VERSION = '4.14.8'


def replace_once(text, old, new):
    if old not in text:
        raise RuntimeError(f'Upstream configuration changed; missing expected token {old!r}')
    return text.replace(old, new)


def main():
    os.umask(0o077)
    runtime = ROOT / '.runtime'
    repo = runtime / 'wazuh-docker'
    if repo.exists():
        raise SystemExit('Refusing to overwrite existing .runtime/wazuh-docker. Use its existing configuration.')
    runtime.mkdir(exist_ok=True)
    subprocess.run(['git', 'clone', '--depth', '1', '--branch', 'v' + VERSION,
                    'https://github.com/wazuh/wazuh-docker.git', str(repo)], check=True)
    directory = repo / 'single-node'
    passwords = {name: 'Aa1!' + secrets.token_hex(24) for name in ('admin', 'kibanaserver', 'wazuh-wui')}
    credentials = runtime / 'full-stack-credentials.json'
    credentials.write_text(json.dumps(passwords, indent=2) + '\n')
    compose = directory / 'docker-compose.yml'
    text = compose.read_text()
    text = replace_once(text, 'SecretPassword', passwords['admin'])
    text = replace_once(text, 'MyS3cr37P450r.*-', passwords['wazuh-wui'])
    text = replace_once(text, 'DASHBOARD_PASSWORD=kibanaserver', 'DASHBOARD_PASSWORD=' + passwords['kibanaserver'])
    text = replace_once(text, '"1514:1514"', '"${WAZUH_BIND_IP:-127.0.0.1}:1514:1514"')
    text = replace_once(text, '"1515:1515"', '"${WAZUH_BIND_IP:-127.0.0.1}:1515:1515"')
    for old, new in [('"514:514/udp"','"127.0.0.1:5514:514/udp"'),
                     ('"55000:55000"','"127.0.0.1:55000:55000"'),
                     ('"9200:9200"','"127.0.0.1:9200:9200"'), ('443:5601','127.0.0.1:8443:5601')]:
        text = replace_once(text, old, new)
    text = re.sub(r'^(\s+- \./[^\n]+)$', r'\1:z', text, flags=re.MULTILINE)
    rule_source = directory / 'config/edr_lab_rules.xml'
    rule_source.write_text((ROOT / 'detections/local_rules.xml').read_text())
    marker = '      - ./config/wazuh_cluster/wazuh_manager.conf:'
    position = text.index(marker)
    text = text[:position] + '      - ./config/edr_lab_rules.xml:/wazuh-config-mount/etc/rules/edr_lab_rules.xml:ro,Z\n' + text[position:]
    compose.write_text(text)
    generator = directory / 'generate-indexer-certs.yml'
    generator.write_text(re.sub(r'^(\s+- \./[^\n]+)$', r'\1:z', generator.read_text(), flags=re.MULTILINE))
    users = directory / 'config/wazuh_indexer/internal_users.yml'
    contents = users.read_text()
    for name in ('admin', 'kibanaserver'):
        result = subprocess.run(['docker', 'run', '--rm', '--network', 'none',
                                 '-e', 'JAVA_HOME=/usr/share/wazuh-indexer/jdk', '--entrypoint', '/bin/bash',
                                 'wazuh/wazuh-indexer:' + VERSION,
                                 '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh',
                                 '-p', passwords[name]], text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError('Indexer hash utility failed; inspect image compatibility. Credentials remain private.')
        hashes = re.findall(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}', result.stdout)
        if len(hashes) != 1:
            raise RuntimeError('Could not parse indexer password hash')
        contents, count = re.subn(r'(^' + re.escape(name) + r':\s*\n\s+hash:\s*)"[^"\n]+"',
                                  lambda m: m.group(1) + '"' + hashes[0] + '"', contents, flags=re.MULTILINE)
        if count != 1:
            raise RuntimeError('Unexpected internal_users.yml structure')
    users.write_text(contents)
    conf = directory / 'config/wazuh_cluster/wazuh_manager.conf'
    contents = conf.read_text().replace('<logall_json>no</logall_json>', '<logall_json>yes</logall_json>')
    conf.write_text(contents)
    if (ROOT / '.env').exists():
        (directory / '.env').write_text((ROOT / '.env').read_text())
    subprocess.run(['docker', 'compose', 'config', '--quiet'], cwd=directory, check=True)
    print(f'Prepared {directory}. Credentials saved privately in {credentials}.')
    print('Certificate generation and live dashboard startup still require validation.')


if __name__ == '__main__':
    main()
