# Incident 001 — Suspicious PowerShell

**Prepared investigation worksheet — NOT VERIFIED. No Windows alert or incident is claimed.** Complete the evidence-dependent fields after executing the scenario. A synthetic rule test is not incident evidence.

1. **Incident ID:** LAB-INC-001.
2. **Incident title:** Suspicious PowerShell.
3. **Alert source:** planned Wazuh rule 100100, Sysmon Event 1; optional PowerShell 4104; live alert NOT VERIFIED.
4. **Detection timestamp:** NOT VERIFIED; retain alert timestamp separately from endpoint UTC event time.
5. **Affected host:** NOT VERIFIED; copy actual computer name and Wazuh agent ID.
6. **Affected user:** NOT VERIFIED; capture actor/user SID and distinguish target account where applicable.
7. **Process:** NOT VERIFIED; preserve image path, PID, process GUID, integrity and hashes when available.
8. **Parent process:** NOT VERIFIED; join the actual parent process GUID to Event 1. Do not infer it from the script's intended execution alone.
9. **Command line:** Record the actual child command line from Event 1. The script uses -NoProfile -ExecutionPolicy Bypass -EncodedCommand; the exact encoded string is in captured telemetry, once collected.
10. **Network indicators:** None deliberately requested. Check actual Event 3 records before concluding there were no connections.
11. **Summary / what happened:** Planned activity: A child Windows PowerShell process decodes a fixed harmless UTF-16LE payload, writes a lab marker, and launches whoami.exe. The simulator performs no download. Actual execution has not been observed in this build environment.
12. **Evidence / why alert:** Expected predicate: Match a full image path ending in powershell.exe or pwsh.exe, plus a command line containing -enc/-EncodedCommand or -ExecutionPolicy Bypass. Matching is case-insensitive. This intentionally does not cover every PowerShell abbreviation, host, or obfuscation. Required evidence: Capture Event 1 for the child PowerShell and whoami.exe. Join the whoami parentProcessGuid to the child PowerShell processGuid. Preserve the encoded command and decoded text; verify the binary path/signature/hash and actual user/integrity. If 4104 is enabled, preserve the payload script block. Search Event 3 and Event 13 for that process GUID; record gaps explicitly. Evidence file paths, SHA256 and record IDs: NOT VERIFIED.
13. **Timeline:** NOT VERIFIED. Add separate UTC entries for baseline, launch, source event, manager receipt/alert, analyst checks and cleanup; include a source reference for each. Do not fill times from illustrative fixtures.
14. **Investigation process:** Preserve raw events; inspect exact fields; reconstruct process/user/host context; correlate preceding/following events; verify authorization; scope activity; classify; assess severity; decide escalation; document cleanup.
15. **Analyst observations:** PowerShell can execute commands with the caller's privileges. The fixed lab payload is harmless; unknown payloads require investigation. This is an expected-impact statement, not an observed finding. Additional evidence to seek: Inspect the launch parent's Event 1, PowerShell 4104, user logon, file provenance, approved change records and surrounding DNS/proxy/network logs.
16. **False-positive possibilities:** Software deployment, remote administration and maintenance scripts can use encoding and bypass. Verify the change window, exact decoded payload, actor, expected parent and approved script provenance.
17. **Severity:** Provisional MEDIUM for unexplained behavior; final severity NOT VERIFIED.
18. **Severity justification:** MEDIUM at initial unexplained execution; LOW only after verifying the authorized marker/whoami payload, bounded scope and expected actor. Reassess privilege, execution success, persistence, host criticality, scope and business impact using actual evidence.
19. **Escalation required:** NOT VERIFIED pending evidence. Expected authorized-lab decision: no, if all checks support the planned activity.
20. **Escalation justification:** No for a verified authorized simulation. Yes if the actor/payload is unexplained, privilege is high, the parent is anomalous, or correlated persistence/network/file activity raises concern.
21. **Recommended remediation:** Preserve evidence, run the scenario's documented cleanup and verify resulting state. For real unauthorized activity, escalate with evidence before containment and remove only confirmed unauthorized artifacts under response authority.
22. **Lessons learned:** Proposed review points: Prefer a narrow approved-tool, signer/hash, parent, host-role and time-window exception with review expiry. Do not allowlist all administrators or powershell.exe. Record actual observations and collection gaps after the run.
23. **MITRE ATT&CK mapping:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/). Encoding alone does not justify a command-and-control mapping.

[Reproduction and cleanup](../scenarios/01-suspicious-powershell/README.md) · [Detection](../detections/suspicious-powershell.md) · [Triage playbook](../docs/endpoint-triage-playbook.md)

