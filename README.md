# Endpoint Detection & Investigation Lab

A personal **Wazuh endpoint investigation lab** with safe simulation scripts, custom rules, evidence checks and documented triage. Retained Linux loopback telemetry supports one completed investigation; Windows cases remain prepared workflows.

> Personal cybersecurity lab. Retained activity comes from a controlled environment. This project does not represent production SOC or enterprise experience.

**Current evidence:** six retained helper-observed connections and six matching Wazuh alerts, rechecked offline. **Native Windows execution and agent telemetry: NOT VERIFIED.** [Validation details](docs/VALIDATION.md).

## What This Project Demonstrates

- Wazuh manager configuration and custom detection rules.
- Correlation of endpoint-helper telemetry with retained Wazuh alerts.
- Process launch, user, destination and timestamp investigation.
- Candidate Windows rules for PowerShell, persistence and account creation.
- Sysmon process GUID and parent-process investigation methodology.
- False-positive assessment, severity, escalation and evidence documentation.

## Architecture

```text
Retained executed path:
Linux loopback sockets → helper JSON → manager localfile → rule 100140 → investigation

Windows path — NOT VERIFIED:
PowerShell simulation → Sysmon / Security logs → Wazuh agent → manager rules
                                                                  ↓
                                                  Process/user/network investigation
```

Root Compose runs the manager **without a dashboard**. A separate optional stack adds an indexer and dashboard. Helper process attribution comes from a launched child, not kernel telemetry. [Architecture](architecture/architecture.md).

## Technology

| Technology | Role |
| --- | --- |
| Wazuh 4.14.8 / Docker Compose | Manager, rules, optional full stack |
| Python / Linux | Loopback helper and evidence verification |
| Windows PowerShell 5.1 | Supplied VM simulations; execution pending |
| Sysmon / Windows Event Logs | Planned Event 1/3/13, Security 4720 and optional 4104 collection |

## Scenarios

Pending-case severity is a triage guide, not an observed disposition.

| Scenario | Detection Objective | Evidence | Severity | Status |
| --- | --- | --- | --- | --- |
| [PowerShell](scenarios/01-suspicious-powershell/README.md) | Encoded/bypass arguments, rule 100100 | [Synthetic rule output](evidence/validation/rule-tests/powershell-encoded.txt), [worksheet](investigations/incident-001.md) | MEDIUM pending context | PARTIALLY VERIFIED |
| [Persistence indicator](scenarios/02-persistence/README.md) | Run value set, rule 100110 | [Synthetic rule output](evidence/validation/rule-tests/run-key.txt), [worksheet](investigations/incident-002.md) | MEDIUM pending context | PARTIALLY VERIFIED |
| [Account creation](scenarios/03-privileged-account-change/README.md) | Security 4720, rule 100120 | [Synthetic rule output](evidence/validation/rule-tests/account-created.txt), [worksheet](investigations/incident-003.md) | MEDIUM pending context | PARTIALLY VERIFIED |
| [Windows network](scenarios/04-suspicious-outbound-connection/README.md) | PowerShell to test port, rule 100130 | [Synthetic rule output](evidence/validation/rule-tests/network-test-port.txt) | Pending investigation | PARTIALLY VERIFIED |
| [Linux helper connections](scenarios/04-suspicious-outbound-connection/README.md) | Accepted loopback connection, rule 100140 | [Events](evidence/validation/live-network/events.redacted.jsonl), [alerts](evidence/validation/live-network/alerts.extract.jsonl), [case 004](investigations/incident-004.md) | LOW, authorized test | VERIFIED |

**VERIFIED applies only to the retained Linux run.** Synthetic contracts do not establish native detection. The account script creates a disabled standard account; administrator-group modification is not implemented. Run-key creation does not prove logon execution.

## Investigation Workflow

Endpoint Activity → Telemetry → Wazuh → Alert → Process/User/Network Investigation → Severity → Escalation → Remediation recommendation.

[Playbook](docs/endpoint-triage-playbook.md) · [Report](reports/final-endpoint-report.md) · [Interview notes](docs/interview-notes.md).

## Example Investigation

[Case 004](investigations/incident-004.md) correlates six retained connections to `127.0.0.1:18080` over **2.504257 seconds** with six rule 100140 alerts. Evidence includes run ID, source ports, process launch context and separate source/alert times.

Repeated interpreter traffic merits review, but development tools and health checks are legitimate alternatives. The known helper and controlled listener support **LOW**, benign authorized activity, with no escalation. Neither C2 nor exfiltration is established.

## Evidence / Screenshots

[Evidence provenance](evidence/README.md) separates actual observations from synthetic rule tests. [Current output](evidence/validation/audit-local.json) records local checks. **No screenshots are included.** Follow the [capture guide](screenshots/README.md) for agent status, events, process context, alerts and timeline.

## Detection Engineering

Windows candidates use `win.eventdata.image`, `commandLine`, `targetObject`, `destinationPort` and `win.system.eventID`. Rule fields omit the alert wrapper's `data.` prefix. Confirm native fields in the VM before claiming coverage.

Rule 100140 checks helper source, accepted-connection action and loopback destination/port. Network rules match individual events; repetition is investigated separately. Tune using approved process/actor context and actual baselines. Rule level is separate from incident severity. [Methodology](docs/detection-methodology.md).

## Reproduce the Lab

Offline checks from the repository root:

```bash
python3 scripts/check_repository.py
python3 -O -m unittest discover -s tests -v
python3 scripts/verify_ingestion.py evidence/validation/live-network/events.redacted.jsonl evidence/validation/live-network/alerts.extract.jsonl
```

Follow [manager setup](setup/wazuh-setup.md), preserve retained public evidence, then:

```bash
docker compose up -d --wait --wait-timeout 90
python3 scripts/simulate_network_activity.py
python3 scripts/capture_network_validation.py
```

The helper contacts only loopback. Capture replaces public latest-run files; update the investigation when publishing a new run. [Windows setup](setup/README.md) requires a disposable VM; preserve evidence before cleanup.

## Validation Status

[docs/VALIDATION.md](docs/VALIDATION.md) separates retained evidence from fresh execution. Ten verifier tests pass locally. Docker access and loopback creation are blocked in this audit session. **NOT VERIFIED — requires local Wazuh/endpoint execution:** fresh health, Windows enrollment, native events/alerts and cleanup.

## Limitations

Helper telemetry is not kernel EDR attribution. No commercial EDR backend, automated isolation, memory acquisition, enterprise baseline, production data or measured detection accuracy. Windows cases are worksheets, not completed investigations. No project license has been selected.

## What I Learned

- Match event identity and rule fields before accepting ingestion evidence.
- Process GUID joins need host context; Security 4720 does not supply process ancestry.
- Persistence artifacts and account creation do not prove execution or privilege escalation.
- An expected rule match can be benign; severity requires context.

## Ethical Scope

Controlled personal lab only. No malware or external attacks. Run Windows simulations in a disposable VM with documented cleanup.
