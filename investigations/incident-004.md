# Incident 004 — Repeated loopback connections

**Executed personal-lab investigation: Linux helper path verified. Windows Sysmon variant NOT VERIFIED.** The observed activity was an authorized simulation, not a real compromise.

1. **Incident ID:** LAB-INC-004; run `937ce4fd-4cbf-42be-80e4-bd256764ec3a`.
2. **Incident title:** Repeated controlled loopback TCP connections.
3. **Alert source:** Wazuh 4.14.8 rule 100140, manager localfile `/lab/network.jsonl`, agent ID `000`.
4. **Detection timestamp:** first retained alert `2026-10-06T03:59:19.856+0000`; first observed connection `2026-10-06T03:59:19.425002+00:00`. These are different source and detection times.
5. **Affected host:** Fedora lab host, publicly labeled `LAB-HOST-REDACTED`. Original host identity remains in private evidence. Wazuh sees manager-local collection, not a separately enrolled endpoint.
6. **Affected user:** local invoking user, publicly labeled `LAB-USER-REDACTED`; no account mutation is requested by this helper. Token/privilege context was not independently captured.
7. **Process:** `/usr/bin/python3`, child PID `100954`; executable SHA256 `0d64bd6d66d68dac91cdadafc46e22d4f09f22bdc997aaae870f42865b024a3e`.
8. **Parent process:** helper Python process PID `100947`, known from the script's subprocess launch. A kernel-derived process tree was not captured; parent-of-parent is unknown.
9. **Command line:** `/usr/bin/python3 <REPOSITORY>/scripts/simulate_network_activity.py --client`. Repository path is redacted; original is retained privately.
10. **Network indicators:** source 127.0.0.1, destination 127.0.0.1, TCP port 18080. Six unique connections across 2.504257 seconds; first source port 53034. Each observed connection carried eight received bytes. Source ports for every connection are retained in the event file.
11. **Summary / what happened:** The helper opened a local listener and launched a child that made six bounded loopback connections. The observer wrote actual connection records, and Wazuh generated six matching rule 100140 alerts. This was expected test behavior.
12. **Evidence / why alert:** [Redacted events](../evidence/validation/live-network/events.redacted.jsonl) show source, destination and process launch context. [Real alert extracts](../evidence/validation/live-network/alerts.extract.jsonl) identify rule, alert IDs/timestamps and matching source ports. [Verification summary](../evidence/validation/live-network/summary.json) reports six unique connections and six matching alerts. Raw event-file SHA256: `0243bc23bb18f09a74f83e9a52ca223c890fff935c0660ef46aabee8a8a0e33a`. The rule requires the helper source label, accepted-connection action, loopback destination and port 18080.
13. **Timeline:** `03:59:19.425002Z` first accept; `03:59:19.856Z` first Wazuh alert; `03:59:21.929259Z` last accept; `04:10:45.705944Z` ingestion verification completed. Date for all entries: 2026-10-06 UTC. Per-connection times are in retained events. The verification time is an analyst validation time, not an alert delay metric.
14. **Investigation process:** Inspected actual generated JSON fields, confirmed manager collection and rule output, restricted comparison to the exact run ID, matched each PID/source-port pair, reviewed process launch and bounded loopback destination, and compared results with the known authorized simulation.
15. **Analyst observations:** This rule is a single-connection lab indicator; repetition is established by correlation. Helper process identity is self-observed and lacks independent kernel attribution. There is no evidence in this capture of communication beyond loopback. This limited capture cannot establish that the entire host had no other network activity.
16. **False-positive possibilities:** Local development services, application health checks and administrator scripts can produce the same pattern. Exact known command, controlled listener and authorized run explain these events. Classify as benign authorized activity detected as designed.
17. **Severity:** LOW.
18. **Severity justification:** High confidence in the bounded test, loopback-only destination, short duration and limited demonstrated impact. Privilege and broader host activity were not independently assessed. No observed persistence, data egress or business impact is established by this capture.
19. **Escalation required:** No for this documented simulation.
20. **Escalation justification:** The event pattern matches the approved helper activity and expected local destination. In a real SOC, an unexplained interpreter, external destination, sensitive-data access or correlated persistence would require broader investigation and potentially escalation.
21. **Recommended remediation:** No security containment is justified for the known simulation. Preserve originals, ensure the child/listener exit, and stop the lab manager after use. Do not block localhost or isolate the host merely because this rule fired.
22. **Lessons learned:** End-to-end matching revealed the difference between transport, decoding and analyst conclusions. Seek OS-derived process/socket telemetry, reliable privilege context, broader process ancestry and a baseline before generalizing this detection. Do not use helper fields as evidence of Sysmon collection.
23. **MITRE ATT&CK mapping:** None assigned. Repeated local TCP connections do not establish command and control or exfiltration.

To rerun, follow [Scenario 4](../scenarios/04-suspicious-outbound-connection/README.md). Re-running the capture helper replaces the public latest-run extracts; preserve this report's referenced run before doing so and update report IDs/times for a new run.
