# Incident 003 — Unexpected local account creation

**Prepared investigation worksheet — NOT VERIFIED. No Windows alert or incident is claimed.** Complete the evidence-dependent fields after executing the scenario. A synthetic rule test is not incident evidence.

1. **Incident ID:** LAB-INC-003.
2. **Incident title:** Unexpected local account creation.
3. **Alert source:** planned Wazuh rule 100120, Windows Security Event 4720 (Audit User Account Management success); live alert NOT VERIFIED.
4. **Detection timestamp:** NOT VERIFIED; retain alert timestamp separately from endpoint UTC event time.
5. **Affected host:** NOT VERIFIED; copy actual computer name and Wazuh agent ID.
6. **Affected user:** NOT VERIFIED; capture actor/user SID and distinguish target account where applicable.
7. **Process:** NOT VERIFIED; preserve image path, PID, process GUID, integrity and hashes when available.
8. **Parent process:** NOT VERIFIED; join the actual parent process GUID to Event 1. Do not infer it from the script's intended execution alone.
9. **Command line:** Event 4720 has no direct originating command-line field. Capture the initiating PowerShell Event 1 and label any time/user-based attribution as inferred.
10. **Network indicators:** Not applicable to the creation event. Investigate subsequent account logons separately.
11. **Summary / what happened:** Planned activity: An elevated PowerShell session creates edrlab_demo with a random password, marked as lab-owned and disabled from creation. It does not add the account to Administrators. Password is not printed or stored. Actual execution has not been observed in this build environment.
12. **Evidence / why alert:** Expected predicate: Match Security event 4720. This is account creation, not administrator-group addition. The rule is intentionally broad: do not deploy it unchanged to domain controllers and assume every event is local account creation. Required evidence: Capture 4720 showing actor and target SID/name. Verify Get-LocalUser reports Enabled=False and inspect local Administrators membership. Correlate subjectLogonId with 4624 and privilege context, and a narrow Sysmon Event 1 window for likely process origin. Event 4720 does not directly supply process ancestry; document that attribution limit. Evidence file paths, SHA256 and record IDs: NOT VERIFIED.
13. **Timeline:** NOT VERIFIED. Add separate UTC entries for baseline, launch, source event, manager receipt/alert, analyst checks and cleanup; include a source reference for each. Do not fill times from illustrative fixtures.
14. **Investigation process:** Preserve raw events; inspect exact fields; reconstruct process/user/host context; correlate preceding/following events; verify authorization; scope activity; classify; assess severity; decide escalation; document cleanup.
15. **Analyst observations:** An enabled or privileged unauthorized account could provide durable access. The simulated account is disabled and standard, so the demonstrated action alone confers no administrator access. This is an expected-impact statement, not an observed finding. Additional evidence to seek: Seek change authorization, account enabled state, SID/group membership, 4722/4732/4733 if available, 4624/4625 logons, 4672 privilege assignment and owner confirmation.
16. **False-positive possibilities:** Authorized provisioning, installers, recovery accounts and documented administrator maintenance. Validate the request and owner independently of the actor's own claim.
17. **Severity:** Provisional MEDIUM for unexplained behavior; final severity NOT VERIFIED.
18. **Severity justification:** MEDIUM pending authorization; HIGH for an unauthorized enabled administrator or suspicious subsequent logon; LOW for the verified disabled lab account. Reassess privilege, execution success, persistence, host criticality, scope and business impact using actual evidence.
19. **Escalation required:** NOT VERIFIED pending evidence. Expected authorized-lab decision: no, if all checks support the planned activity.
20. **Escalation justification:** No for the verified authorized disabled account and cleanup. Yes for unapproved creation, later enablement/admin membership, unexpected logons or unclear actor authority.
21. **Recommended remediation:** Preserve evidence, run the scenario's documented cleanup and verify resulting state. For real unauthorized activity, escalate with evidence before containment and remove only confirmed unauthorized artifacts under response authority.
22. **Lessons learned:** Proposed review points: Use host role and approved provisioning actors/windows; retain deviations in account naming, enablement and group membership. A lab-name exclusion would hide the test and teach little. Record actual observations and collection gaps after the run.
23. **MITRE ATT&CK mapping:** [T1136.001 — Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) describes the simulated mechanism. Disabled account creation alone does not prove an adversary established access.

[Reproduction and cleanup](../scenarios/03-privileged-account-change/README.md) · [Detection](../detections/privileged-account-change.md) · [Triage playbook](../docs/endpoint-triage-playbook.md)

