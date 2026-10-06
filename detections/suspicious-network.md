# Suspicious network activity

## Objective and sources

Investigate repeated connections from an unexpected process to a controlled test port. Windows uses Sysmon Event 3 and Event 1 for ancestry. The executed Linux fallback uses actual loopback socket observations from a Python helper and a manager local-file collector. These are different telemetry sources.

## Available fields and detection logic

Windows candidate rule **100130** uses `win.eventdata.image` and `win.eventdata.destinationPort`, under `sysmon_event3`. It matches powershell.exe connecting to TCP test port 18080. Obtain `processGuid`, `processId`, `user`, `sourceIp`, `sourcePort`, `destinationIp`, `destinationPort`, `protocol`, `initiated` and `utcTime` from your actual Event 3 before finalizing it. Join Event 1 to get parent/command line/hash; these are not promised in Event 3. Native collection is NOT VERIFIED.

Linux rule **100140** uses the actually observed decoded fields `lab.source`, `event.action`, `destination.ip`, and `destination.port`. It requires the helper source, `connection_accepted`, 127.0.0.1 and port 18080. The real alert wraps them under `data`. Actual samples: [events](../evidence/validation/live-network/events.redacted.jsonl), [alert extracts](../evidence/validation/live-network/alerts.extract.jsonl).

Both rules alert on individual connections. **Neither is a frequency-correlation rule.** Frequency is established during investigation by grouping the same host/process/run/destination in the actual UTC window. The verified run contains six unique source ports over 2.504257 seconds. A production frequency threshold would require baseline data, stable process identity and separate testing; no such detection is claimed.

## Expected alert and evidence

Windows: expected rule 100130 per matching event; live result NOT VERIFIED. Linux: rule 100140 fired for all six captured connections in the retained run. The capture verifier compares source ports and process IDs for the exact run ID. The helper's process attribution comes from its launched child, not independent kernel observation. Any local writer able to alter the JSON could forge helper records; treat this as controlled lab instrumentation.

## False positives, tuning and evasion

Local development servers, agents, health checks and management scripts can produce repeated traffic. Verify exact process origin, listener ownership, destination, payload and authorization. Port 18080 is a lab indicator, not a universal malicious port. Tune by approved process provenance, host role, exact destination and time window; do not suppress all interpreter traffic.

Different ports/interpreters, missing Event 3, process injection, low-rate traffic and suppressed/forged logs can evade this narrow rule. Loopback events may not appear on every Sysmon build. A missing Windows event leaves that path NOT VERIFIED; the fallback does not fill that gap.

## Triage, severity and escalation

Capture source host/user/process/parent, destination/protocol/port, UTC frequency and execution context. Validate DNS/proxy/firewall context when applicable, inspect child processes and persistence, and check whether any actual data left the host. Seek independent OS socket/process telemetry in a real SOC.

Initial unexplained network activity may be MEDIUM. The observed bounded loopback test is LOW with no escalation: it was authorized, locally contained and matched the known helper activity. Unexpected external destination, sensitive-data access, privilege or correlated persistence can raise severity to HIGH and warrant escalation. No ATT&CK command-and-control or exfiltration mapping is assigned: those behaviors are not demonstrated.
