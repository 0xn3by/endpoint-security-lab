# Validation Status

Audit: 2026-10-06. Overall: **READY WITH MANUAL VALIDATION** for the explicitly bounded portfolio presentation. Native Windows investigations are unfinished.

| Scenario | Simulation Tested | Telemetry Verified | Detection Verified | Investigation Evidence Verified | Status |
|---|---|---|---|---|---|
| Windows suspicious PowerShell | NOT VERIFIED | NOT VERIFIED | PARTIALLY VERIFIED | NOT VERIFIED | PARTIALLY VERIFIED |
| Windows Run-key persistence indicator | NOT VERIFIED | NOT VERIFIED | PARTIALLY VERIFIED | NOT VERIFIED | PARTIALLY VERIFIED |
| Windows local account creation | NOT VERIFIED | NOT VERIFIED | PARTIALLY VERIFIED | NOT VERIFIED | PARTIALLY VERIFIED |
| Windows network variant | NOT VERIFIED | NOT VERIFIED | PARTIALLY VERIFIED | NOT VERIFIED | PARTIALLY VERIFIED |
| Linux helper connections, retained run | VERIFIED | VERIFIED | VERIFIED | VERIFIED | VERIFIED |

Windows detection cells are partial solely because retained synthetic logtest output supports candidate predicates under a test-only JSON bridge. No native Windows alert is claimed. Linux verification applies to retained run `937ce4fd-4cbf-42be-80e4-bd256764ec3a`, not fresh execution.

## What was actually checked

[Current command output](../evidence/validation/audit-local.json) records local execution.
The [publication checks](../evidence/validation/audit-review.json) found no broken
local Markdown targets/anchors or high-confidence secret-pattern candidates in
inspected publishable files. Private originals and generated credentials remain
ignored; pattern checks are not an exhaustive secret guarantee.
Ten evidence-verifier regression tests passed with Python optimization enabled. Repository Python/XML/link checks, shell syntax and root Compose configuration passed.

The original retained network file was available locally; its SHA-256 matches `0243bc23bb18f09a74f83e9a52ca223c890fff935c0660ef46aabee8a8a0e33a`. The stricter verifier passed on original events/alerts and the public redacted equivalents: six connections, six rule 100140 alerts. The event interval is 2.504257 seconds. Report 004's PID, parent, source ports, times, destination and LOW/no-escalation disposition agree with the retained evidence.

The public alert extracts now retain additional comparison fields copied from those same original alert IDs. Existing alert values/timestamps were preserved. These remain redacted extracts, not newly generated alerts. Repeat the check without private files:

```bash
python3 scripts/verify_ingestion.py evidence/validation/live-network/events.redacted.jsonl evidence/validation/live-network/alerts.extract.jsonl
```

The verifier now compares source-event timestamp, PID, source address/port and destination, checks the rule's source/action predicates, and rejects duplicate source evidence. It does not authenticate a log's origin or prove kernel socket ownership.

All 15 retained [rule-test transcripts](../evidence/validation/rule-tests/results.json) were checked against their expected target-rule presence/absence and JSON decoder output. These are historical engine outputs, not a fresh engine run. [Full-stack JSON](../evidence/validation/full-stack.json) records historical authenticated health only; it does not prove current health or Windows alert indexing. Earlier PowerShell syntax and Filebeat execution claims are historical notes; this audit did not rerun them.

## Current execution limits

`docker ps` failed with permission denied on the Docker socket.
An attempted `python3 scripts/simulate_network_activity.py --output /tmp/edr-audit-network.jsonl` failed at socket creation with PermissionError before any connection was generated. No PowerShell executable is available in this session.

**NOT VERIFIED — requires local Wazuh/endpoint execution:** fresh simulations/engine tests, service health, Windows agent enrollment, native fields, alerts, cleanup and screenshots. Existing historical evidence was not replaced with an invented successful run.

## Exact manual completion steps

Start with [manager setup](../setup/wazuh-setup.md), [agent enrollment](../setup/endpoint-agent-setup.md) and [Sysmon/auditing](../setup/sysmon-setup.md). Use a disposable Windows VM, host-only networking and Windows PowerShell 5.1. Confirm a baseline whoami Event 1 locally and in manager archives before simulations.

On the manager host, from the root:

```bash
docker compose up -d --wait --wait-timeout 90
docker compose exec -T manager /var/ossec/bin/wazuh-analysisd -t
docker compose exec -T manager /var/ossec/bin/agent_control -l
python3 scripts/test_rules.py
```

Require an Active Windows agent; local agent 000 is not endpoint enrollment.
In elevated Windows PowerShell at C:\EDR, run each separately, recording UTC start/end and inspecting evidence before continuing:

```powershell
.\scripts\simulate_powershell_activity.ps1 -LabConfirmed
# Require Sysmon 1 for PowerShell and whoami child; rule 100100.
.\scripts\simulate_persistence.ps1 -LabConfirmed
# Require Sysmon 13 targetObject/details; rule 100110. Creation is not logon execution.
.\scripts\simulate_account_change.ps1 -LabConfirmed
# Require Security 4720 actor/target; disabled standard account; rule 100120.
.\scripts\simulate_network_activity.ps1 -LabConfirmed
# Require Sysmon 3 processGuid/destination; rule 100130.
.\scripts\export_windows_evidence.ps1 -Minutes 15
```

Compare each local event with decoded manager fields and the actual alert. Manager inspection commands:

```bash
docker compose exec -T manager tail -n 100 /var/ossec/logs/archives/archives.json
docker compose exec -T manager tail -n 100 /var/ossec/logs/alerts/alerts.json
```

Keep exports private; use the exact run window/host/record IDs, not arbitrary recent alerts.
Follow each [scenario](../README.md#scenarios) for evidence joins and final worksheet completion. If Sysmon does not expose loopback traffic, leave the Windows network row NOT VERIFIED; Linux fallback does not validate it.

After capture:

```powershell
.\scripts\simulate_persistence.ps1 -LabConfirmed -Cleanup
.\scripts\simulate_account_change.ps1 -LabConfirmed -Cleanup
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name EDRLabHarmless -ErrorAction SilentlyContinue
Get-LocalUser -Name edrlab_demo -ErrorAction SilentlyContinue
Get-NetTCPConnection -LocalPort 18080 -State Listen -ErrorAction SilentlyContinue
```

Require absent lab artifacts/listener, verify command errors rather than interpreting all silence as success, and restore auditing/policy per setup. Administrator-group modification is not implemented and must not be claimed.

For a fresh Linux replay, preserve earlier public evidence, then run the two network simulation/capture commands from [setup](../setup/wazuh-setup.md). Confirm exact run IDs, listener/child exit and update the report if publishing new evidence.

## Scope and source review

No screenshots exist; use the [capture checklist](../screenshots/README.md). Decorations are not screenshots. Historical health does not demonstrate dashboard investigation.

[Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) supports the distinct Event 1/3/13 roles. [Wazuh rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html) supports decoded-field matching; actual native casing remains a runtime gate. ATT&CK mappings are conditional mechanisms: [PowerShell](https://attack.mitre.org/techniques/T1059/001/), [Run keys](https://attack.mitre.org/techniques/T1547/001/) and [local account creation](https://attack.mitre.org/techniques/T1136/001/). No C2, exfiltration or demonstrated privilege escalation is inferred.
