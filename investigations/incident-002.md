# Incident 002 — Run-key persistence indicator

**Prepared investigation worksheet — NOT VERIFIED. No Windows alert or incident is claimed.** Complete the evidence-dependent fields after executing the scenario. A synthetic rule test is not incident evidence.

1. **Incident ID:** LAB-INC-002.
2. **Incident title:** Run-key persistence indicator.
3. **Alert source:** planned Wazuh rule 100110, Sysmon Event 13 (registry value set), correlated with Event 1; live alert NOT VERIFIED.
4. **Detection timestamp:** NOT VERIFIED; retain alert timestamp separately from endpoint UTC event time.
5. **Affected host:** NOT VERIFIED; copy actual computer name and Wazuh agent ID.
6. **Affected user:** NOT VERIFIED; capture actor/user SID and distinguish target account where applicable.
7. **Process:** NOT VERIFIED; preserve image path, PID, process GUID, integrity and hashes when available.
8. **Parent process:** NOT VERIFIED; join the actual parent process GUID to Event 1. Do not infer it from the script's intended execution alone.
9. **Command line:** Capture Event 13 details for the stored command and Event 1 commandLine for the writer. These are different commands.
10. **Network indicators:** No network activity is requested. Correlate the registry writer and any later launched target with Event 3.
11. **Summary / what happened:** Planned activity: Create the current user's EDRLabHarmless Run value pointing to cmd.exe /d /c echo with a harmless marker. The value is not executed during setup. No elevated permission is needed. Actual execution has not been observed in this build environment.
12. **Evidence / why alert:** Expected predicate: Match a value immediately below Software\Microsoft\Windows\CurrentVersion\Run using an anchored, case-insensitive regular expression. This covers the lab HKCU path, represented as HKU plus the user's SID in Sysmon. It does not cover RunOnce, WOW6432Node, tasks or services. Required evidence: Capture Event 13 with the exact targetObject and details, then read the registry value directly. Join its processGuid to Event 1 to find the writer and parent. Record whether the configured executable exists and whether a later process event proves execution. Do not equate creation with successful persistence execution. Evidence file paths, SHA256 and record IDs: NOT VERIFIED.
13. **Timeline:** NOT VERIFIED. Add separate UTC entries for baseline, launch, source event, manager receipt/alert, analyst checks and cleanup; include a source reference for each. Do not fill times from illustrative fixtures.
14. **Investigation process:** Preserve raw events; inspect exact fields; reconstruct process/user/host context; correlate preceding/following events; verify authorization; scope activity; classify; assess severity; decide escalation; document cleanup.
15. **Analyst observations:** An unauthorized Run value may execute at the next logon in that user's context. This lab's command only prints a marker; no logon execution has been demonstrated. This is an expected-impact statement, not an observed finding. Additional evidence to seek: Seek the exact registry value before/after, payload signature/hash, installer history, user logon, and execution at the next logon if authorized.
16. **False-positive possibilities:** Updaters, collaboration tools, device utilities and approved installers commonly use Run keys. Check software installation records, signer, target location, owner and change time.
17. **Severity:** Provisional MEDIUM for unexplained behavior; final severity NOT VERIFIED.
18. **Severity justification:** MEDIUM for an unexplained value set; HIGH if unapproved and linked to suspicious payload or privileged scope; LOW after confirming the harmless authorized test. Reassess privilege, execution success, persistence, host criticality, scope and business impact using actual evidence.
19. **Escalation required:** NOT VERIFIED pending evidence. Expected authorized-lab decision: no, if all checks support the planned activity.
20. **Escalation justification:** No for the verified authorized marker and successful cleanup. Yes for unexplained persistence, untrusted target, persistence reappearance or correlated execution/network activity.
21. **Recommended remediation:** Preserve evidence, run the scenario's documented cleanup and verify resulting state. For real unauthorized activity, escalate with evidence before containment and remove only confirmed unauthorized artifacts under response authority.
22. **Lessons learned:** Proposed review points: Limit exemptions to approved exact value/path, trusted signer and documented installer behavior. Keep alerts for user-writable or changed destinations. Expand to RunOnce/tasks later. Record actual observations and collection gaps after the run.
23. **MITRE ATT&CK mapping:** [T1547.001 — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/). The mechanism is mapped; actual execution must be independently verified.

[Reproduction and cleanup](../scenarios/02-persistence/README.md) · [Detection](../detections/persistence.md) · [Triage playbook](../docs/endpoint-triage-playbook.md)

