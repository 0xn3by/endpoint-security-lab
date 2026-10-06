# Final endpoint lab report

## Scope and delivered implementation

Personal lab and portfolio work only. The repository contains four harmless Windows simulation scripts, a real Linux network fallback, Wazuh manager Compose deployment, optional full-stack preparation, Sysmon/agent configuration, five custom rules, isolated rule tests, evidence helpers, investigation records, triage playbook, interview notes, resume wording and manual screenshot instructions.

## Evidence-backed result

The retained Linux run `937ce4fd-4cbf-42be-80e4-bd256764ec3a` generated six actual loopback TCP connections. Wazuh ingested the helper JSON through its manager localfile collector and produced six matching rule 100140 alerts. The verifier compared the exact run ID and each process/source-port pair. [Incident 004](../investigations/incident-004.md) documents the timestamps, process context, hash, frequency, limitations and LOW/no-escalation disposition.

The Windows detection contract suite passed 15 positive/negative/missing-field cases in real Wazuh 4.14.8 using an isolated test-only rule 60000 JSON bridge. The live manager keeps the native Windows decoder requirement. Six PowerShell files parsed successfully in PowerShell 7.4 on Linux; this is syntax validation only.

## Environment limitations and unfinished live work

The Fedora host had Docker and Python, roughly 6 GB available RAM and 31 GB free disk at inspection. No registered Windows VM was available. Native scenario execution, Sysmon/Security collection, Windows agent enrollment, live Windows field validation and cleanup are **NOT VERIFIED**. Incidents 001–003 are prepared worksheets, with no invented host IDs, times or findings. No screenshots were generated.

Full-stack preparation and startup were executed successfully: pinned upstream checkout, generated credentials, indexer bcrypt hashes, Compose validation and local TLS certificates. [The recorded check](../evidence/validation/full-stack.json) at 2026-10-06T04:44:41.997032Z returned HTTP 200 for the indexer and dashboard, both green, and HTTP 200 for manager API authentication. Filebeat's output test confirmed a TLS connection to the indexer. Native Windows scenario alert presentation and screenshots remain **NOT VERIFIED**.

The initial password utility invocation required an explicit Java home; the helper now sets it and keeps regenerated credentials private. The generated lab CA requires compatibility-mode verification in newer Python; the health helper still validates its CA chain. These environment findings are documented in setup. Lab services are stopped after validation to free host memory; their configurations and evidence volumes remain available.

## Engineering findings

- The official manager image needs its initialization stage before the Wazuh control script can start. The lab entrypoint handles fresh creation and later restarts.
- CLI logtest treats supplied JSON differently from native Windows EventChannel collection. A disposable test container contains the compatibility adjustment, with its scope explicitly recorded.
- Repository syntax/path checks passed, and five evidence-verifier regression cases passed, including execution with Python optimization enabled. Missing or unrelated alerts cannot satisfy the verifier.
- Detection priorities are separate from incident severity. The known loopback test is benign even though its expected rule fires.
- Local account creation is distinct from privilege elevation; the safe simulation creates a disabled standard account. No administrator addition is claimed.
- Persistence artifact creation is distinct from successful persistence execution. The lab Run value only points to a harmless marker command.

## Recommended next actions

1. Provision/snapshot the Windows lab VM and complete baseline agent/Sysmon collection.
2. Run each native scenario separately, preserve originals, inspect decoded fields and validate the live rules.
3. Complete incidents 001–003 and add Windows context to incident 004 only if actual evidence supports it.
4. Verify cleanup, capture the documented screenshots, update the [validation matrix](validation-matrix.md), and revise portfolio claims to match the new evidence.

The strongest current portfolio claim is a reproducible personal endpoint investigation lab with verified Wazuh ingestion for actual local network telemetry and clearly documented native Windows validation gaps. This report does not claim enterprise EDR operations or a real security incident.
