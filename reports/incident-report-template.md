# Endpoint incident report template

**Personal lab only. Status: NOT VERIFIED until populated from an actual run.**

1. Incident ID and run ID:
2. Incident title:
3. Alert source, rule ID/version and source event ID:
4. Detection timestamp and endpoint event timestamp (UTC, separately):
5. Affected host, agent ID, role and criticality:
6. Affected user, actor/target SIDs, logon ID and privilege context:
7. Process path, GUID/PID, start time, hash and signature:
8. Parent process path, GUID/PID and evidence for relationship:
9. Exact command line and safely decoded content if applicable:
10. Network indicators: source/destination, port/protocol, frequency and attribution:
11. Summary: what happened, execution success, scope and likely impact:
12. Evidence: original file paths, SHA256, event record IDs, alert IDs and redactions:
13. UTC timeline: observation, source reference, inference and confidence for each entry:
14. Investigation process: queries, correlations, checks and evidence gaps:
15. Analyst observations: observed facts versus assumptions; additional evidence needed:
16. Legitimate explanations and how each was evaluated:
17. Severity: LOW / MEDIUM / HIGH / CRITICAL:
18. Severity justification: confidence, privilege, persistence, success, scope, criticality and impact:
19. Escalation required: yes / no / NOT VERIFIED:
20. Escalation justification and requested next action:
21. Recommended remediation, approvals, actual actions and recovery checks:
22. Lessons learned and detection/collection improvements:
23. Accurate MITRE ATT&CK mapping, or reason no mapping is justified:

Closure requires evidence-backed classification, documented disposition, cleanup/recovery confirmation and review of remaining gaps. Preserve originals before changing the endpoint.
