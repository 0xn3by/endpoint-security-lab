# Final validation matrix

Snapshot: 2026-10-06. **COMPLETE applies only to the explicitly named executed path.** NOT VERIFIED means the required runtime/evidence was unavailable, not that the activity was malicious or the rule necessarily failed.

| Scenario | Simulation tested | Telemetry verified | Detection validated | Investigation verified | Status |
| --- | --- | --- | --- | --- | --- |
| 01 Suspicious PowerShell — Windows | NOT VERIFIED; syntax parsed | NOT VERIFIED | Synthetic contract PASS; live fields NOT VERIFIED | NOT VERIFIED; prepared worksheet | NOT VERIFIED |
| 02 Run-key persistence — Windows | NOT VERIFIED; syntax parsed | NOT VERIFIED | Synthetic contract PASS; live fields NOT VERIFIED | NOT VERIFIED; prepared worksheet | NOT VERIFIED |
| 03 Local account creation — Windows | NOT VERIFIED; syntax parsed | NOT VERIFIED | Synthetic contract PASS; live fields NOT VERIFIED | NOT VERIFIED; prepared worksheet | NOT VERIFIED |
| 04 Connections — Windows variant | NOT VERIFIED; syntax parsed | NOT VERIFIED | Synthetic contract PASS; live fields NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| 04 Connections — Linux helper fallback | PASS; six actual connections | PASS; helper JSON and manager ingestion | PASS; real rule 100140, six matching alerts | PASS; incident 004 references retained run | COMPLETE for helper path |

The four native Windows scenarios are not represented as complete. The Linux fallback uses a manager file collector and helper launch context; it does not validate Windows enrollment, Sysmon or independent process/socket attribution.

## Supporting checks

- Docker manager startup/health and actual JSON ingestion: verified.
- Windows rule predicate/hierarchy suite: **15/15 PASS** using synthetic inputs in real Wazuh 4.14.8 with the isolated JSON bridge. See [results](../evidence/validation/rule-tests/results.json).
- PowerShell parser: six `.ps1` files parsed successfully using Microsoft's PowerShell 7.4 container. Windows PowerShell 5.1 runtime behavior remains NOT VERIFIED.
- Network evidence: [actual run summary](../evidence/validation/live-network/summary.json), [redacted observations](../evidence/validation/live-network/events.redacted.jsonl), [real alert extracts](../evidence/validation/live-network/alerts.extract.jsonl).
- Windows agent enrollment, live Sysmon/Security field inspection, native cleanup, native scenario alert indexing and screenshots: **NOT VERIFIED**.
- Full-stack preparation, certificate generation, authenticated indexer/dashboard health, manager API authentication and Filebeat output connection: **PASS**. [Retained infrastructure check](../evidence/validation/full-stack.json). Native scenario presentation is still NOT VERIFIED.
- Evidence-verifier regression checks: **5/5 PASS**, including missing connections, incorrect rule IDs and unrelated run IDs, also with Python optimization enabled.
- Local repository check: Python syntax, XML parsing and local Markdown link targets PASS; shell syntax and Compose configuration PASS.

See the [local command validation record](../evidence/validation/local-checks.md) for runtime versions, scope and actual checks.

## Completion gate for a Windows row

Retain script result and UTC window; capture actual local event XML/EVTX; find the corresponding decoded manager event; inspect every detection field; confirm live alert; fill the investigation from those evidence IDs; justify classification/severity/escalation; perform cleanup; verify resulting state. Then update this matrix and the resume/interview wording. Never promote a row based only on files, screenshots of fixtures, or a syntax check.
