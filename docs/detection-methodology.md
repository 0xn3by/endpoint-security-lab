# Detection methodology and evidence standards

## End-to-end workflow

Endpoint activity → telemetry → Wazuh agent/collector → manager → detection/alert → triage → process/user/host context → related-event correlation → legitimate explanations → classification → severity → escalation decision → remediation recommendation → incident report.

Every arrow needs evidence. A script exit code does not prove an event was collected. A fixture match does not prove endpoint telemetry exists. An alert file does not prove dashboard indexing. A missing event is a visibility gap, not evidence of absence.

## Inspect before tuning

1. Save the original Windows EVTX plus event XML, or the actual Linux helper JSON. Hash the saved files.
2. Find the corresponding manager archive by host, UTC time, event ID and process GUID. Save its raw `full_log` and decoded `data` separately.
3. Inventory available keys and compare them with each `<field name>` in [local_rules.xml](../detections/local_rules.xml). Preserve exact capitalization.
4. Native Windows Event XML has names such as `CommandLine`; Wazuh decoded rules use `win.eventdata.commandLine`. The dashboard alert wrapper exposes `data.win.eventdata.commandLine`. Do not put `data.` into the rule field name.
5. Use positive, nearby legitimate, and missing-field cases. Then reproduce the activity through the real agent. Archive the rule version, configuration, input, and engine result.
6. If a field is absent, revise the detection or declare the coverage gap. Do not invent values or quietly map unrelated fields.

Windows rule fields here are candidate contracts based on Microsoft's event schema and Wazuh 4.14.8's shipped rules. Actual Windows collection is **NOT VERIFIED**. They are not finalized as live detections until the VM run supplies decoded samples. The helper's JSON fields have been inspected in actual locally generated records and Wazuh alerts.

## Rule-test scope

`python3 scripts/test_rules.py` creates a separate network-disabled Wazuh container. Wazuh CLI logtest decodes JSON fixtures as `json`; the test-only rule 60000 bridge admits that data into the Windows rule hierarchy. It does not change the live manager. The fixtures are explicitly synthetic and are never incident evidence. Passing tests validate field predicates and rule hierarchy under that bridge; they do not validate Windows EventChannel transport or live decoder behavior.

Never apply `tests/logtest-entrypoint.sh` to a live manager. It changes the decoder requirement in the disposable container's copy of rule 60000. For actual Windows raw-event replay, use this isolated contract harness with a reviewed copy; final proof always comes from live agent ingestion. The API exposes an EventChannel format, but its equivalence to live decoding has not been verified here.

## Correlation

Prefer `(host, processGuid)` for Sysmon Event 1 ↔ Event 3/13. Link `parentProcessGuid` to the parent's Event 1. PIDs are reused; PID-only joins across long windows are unsafe. Windows Security account events have subject and target SIDs/logon IDs but no reliable process command line; correlate 4624/4672 and Sysmon by host, user/logon context and a narrow time window, and label the process attribution as inferred unless independently supported.

Record endpoint event time, manager detection time, and analyst time separately in UTC. Check clock skew before ordering activity. Preserve event record IDs and full command lines. Decode encoded PowerShell as text only; never execute a decoded unknown payload.

## Classification and severity

Classification and severity are separate. An alert can accurately detect a behavior and still be an authorized benign activity. A false positive for malicious intent is not necessarily a broken rule.

- **LOW:** expected, authorized, limited scope, low privilege or inert artifact; no evidence of harmful impact. Close with evidence and cleanup verification.
- **MEDIUM:** suspicious execution or unexplained account/persistence change on an ordinary host; intent/authorization uncertain. Gather context promptly; escalate if authorization cannot be established or evidence gaps affect confidence.
- **HIGH:** credible unauthorized execution plus persistence, administrative privileges, suspicious external communication, credential exposure, or sensitive-host access. Escalate promptly and recommend containment with the authorized responder.
- **CRITICAL:** confirmed active destructive activity, material exfiltration, broad spread, or high-impact compromise of critical systems. Immediate incident-response escalation and coordinated containment.

Consider confidence, privilege, execution success, persistence, host criticality, network scope, data access and business impact. Wazuh levels 0–15 are rule priorities; they do not automatically equal these four analyst severities. Reassess as evidence changes. Do not isolate a host just because `-EncodedCommand` appears.

## Evidence and publication

Keep originals in ignored `evidence/private/`. Store SHA256 manifests and preserve originals before cleanup. Public extracts must state redactions and retain enough timestamps/IDs to explain conclusions. Never publish credentials, enrollment keys, tokens, unrelated personal telemetry or invented screenshots. A pending record must say NOT VERIFIED and identify exactly what evidence is needed.

References: [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [Wazuh Windows collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html), [Wazuh logtest Windows limitation](https://github.com/wazuh/wazuh/discussions/25405).
