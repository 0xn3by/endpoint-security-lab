#!/usr/bin/env python3
"""Check repository paths, Python syntax, XML, rule IDs and local Markdown links."""
import ast
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def main():
    tracked = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard'],
                             cwd=ROOT, text=True, capture_output=True, check=True).stdout.splitlines()
    files = [ROOT / name for name in tracked if (ROOT / name).is_file()]
    failures = []
    counts = {'python': 0, 'xml': 0, 'markdown_links': 0}
    for path in files:
        try:
            if path.suffix == '.py':
                ast.parse(path.read_text(), filename=str(path))
                counts['python'] += 1
            elif path.suffix == '.xml' or path.name == 'manager.conf':
                ET.parse(path)
                counts['xml'] += 1
            elif path.suffix == '.md':
                content = path.read_text()
                if content.count('```') % 2:
                    failures.append(f'Unbalanced code fences: {path.relative_to(ROOT)}')
                for link in re.findall(r'\]\(([^)]+)\)', content):
                    target = link.split('#', 1)[0]
                    if not target or '://' in target or target.startswith('mailto:'):
                        continue
                    counts['markdown_links'] += 1
                    if not (path.parent / target).exists():
                        failures.append(f'Broken local link {path.relative_to(ROOT)} -> {target}')
        except (SyntaxError, ET.ParseError) as error:
            failures.append(f'{path.relative_to(ROOT)}: {error}')
    rules = ET.parse(ROOT / 'detections/local_rules.xml').getroot().findall('rule')
    ids = [int(rule.attrib['id']) for rule in rules]
    if len(ids) != len(set(ids)) or not all(100000 <= rid <= 120000 for rid in ids):
        failures.append('Invalid/duplicate custom rule IDs')
    for item in ('README.md', 'architecture/architecture.md', 'reports/validation-matrix.md',
                 'reports/final-endpoint-report.md', 'docs/resume-bullets.md'):
        if not (ROOT / item).is_file():
            failures.append('Missing required file: ' + item)
    for failure in failures:
        print('FAIL:', failure)
    print('Repository checks:', counts, 'failures:', len(failures))
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
