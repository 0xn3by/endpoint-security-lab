# Endpoint triage playbook

Start with the alert ID, UTC window, exact rule/version, and raw event. Save the evidence before changing the endpoint. Use these questions during an investigation or interview.

1. **Which host?** Record agent ID, computer name, IP, OS, owner and business role. Confirm the agent is reporting and the clock is synchronized.
2. **Which user?** Record SID, domain/local status, logon ID and session type. Separate the actor from any target account.
3. **Which process?** Record full path, PID, Sysmon process GUID, hash, signature and start time. A familiar filename can be copied elsewhere.
4. **What is the parent?** Join parentProcessGuid to Event 1 on the same host. Capture parent path/command line and its parent if available.
5. **What command line?** Preserve it exactly; decode base64 as UTF-16LE text when applicable. Look for flags, destinations, paths, quoting, scripts and chained commands.
6. **Was it expected?** Check software deployment, change window, user role and a verified owner explanation. An assertion alone is insufficient.
7. **What privilege?** Inspect integrity level, token/logon context and group membership. Administrator membership does not prove this process had an elevated token.
8. **Children?** Find Event 1 records whose parentProcessGuid equals the suspicious process GUID. Inspect whoami, cmd, script interpreters and unexpected tools.
9. **Network?** Join Event 3 by process GUID; capture destination, port, protocol, timing and initiation. Seek DNS/proxy/firewall evidence if needed. Do not upload private data to public lookup services.
10. **Persistence?** Inspect Event 13, Run/RunOnce keys, scheduled tasks, startup folders and services as appropriate. A write proves an artifact exists; it does not prove later execution.
11. **Accounts changed?** Inspect 4720, 4726 and, where enabled, 4732/4733. Compare target SID with Administrators SID `S-1-5-32-544`; do not rely on localized group names.
12. **Before?** Search 5–15 minutes earlier for logon, browser/download, document opening, software deployment and parent processes.
13. **After?** Search for children, connections, file changes, persistence, account use and cleanup. Broaden time/scope only when evidence warrants it.
14. **Could it be legitimate?** Compare exact payload, approved tool hash, actor, schedule, source and destination with the change record. Document competing explanations.
15. **What is missing?** Note absent command lines, script blocks, dropped events, unavailable memory, retention gaps and unsupported process attribution. Request specific data.
16. **What severity?** Apply the four-level model in [detection methodology](detection-methodology.md). Explain confidence and likely impact separately.
17. **Escalate?** Say yes/no and why. Escalate unauthorized privileged activity, unexplained persistence, credible malware/exfiltration, wider scope, or material uncertainty on a critical host. Preserve evidence and state what the next responder should do.
18. **Remediation?** Recommend containment proportional to evidence: stop a confirmed malicious process, remove confirmed unauthorized persistence, disable a compromised account, rotate exposed credentials and patch the entry point. Obtain operational authorization in a real SOC. Validate recovery and monitor for recurrence.

## Practical queries

Dashboard KQL examples, after confirming fields in your own alert:

```text
agent.name:"EDR-WIN01" AND rule.id:"100100"
data.win.system.eventID:"13"
data.win.eventdata.processGuid:"{COPY-ACTUAL-GUID}"
data.win.eventdata.parentProcessGuid:"{COPY-ACTUAL-GUID}"
data.win.system.eventID:"4720"
```

Non-alerted process events may exist only in archives or local EVTX. Do not expect every Event 1 in `wazuh-alerts-*`. Build a small UTC timeline containing evidence ID, observation, inference, and confidence. Separate what the source says from your interpretation.

Escalation handoff: **host + user + behavior + strongest evidence + scope + severity reason + actions already taken + missing evidence + requested next action**. This is a lab workflow, not a claim of production response authority.
