# Run-key persistence indicator detection

**Status:** candidate Windows detection; native endpoint telemetry and live ingestion NOT VERIFIED. Contract-test output is in [rule tests](../evidence/validation/rule-tests/results.json).

## Objective and data source

Identify a new or changed executable command under a Windows Run key. Source: Sysmon Event 13 (registry value set), correlated with Event 1.

## Telemetry fields and logic

`win.eventdata.targetObject`; parent group `sysmon_event_13`. Context: Event 13 `image`, `processGuid`, `processId`, `user`, `details`, `utcTime`; Event 1 supplies ancestry, command line, integrity and hashes.

Match a value immediately below Software\Microsoft\Windows\CurrentVersion\Run using an anchored, case-insensitive regular expression. This covers the lab HKCU path, represented as HKU plus the user's SID in Sysmon. It does not cover RunOnce, WOW6432Node, tasks or services.

Rule 100110 in [local_rules.xml](local_rules.xml). Expected result is an alert for the described behavior; this is an expectation until the real VM event is retained. Wazuh level is a rule priority, not the analyst's final severity.

## Triage and correlation

Capture Event 13 with the exact targetObject and details, then read the registry value directly. Join its processGuid to Event 1 to find the writer and parent. Record whether the configured executable exists and whether a later process event proves execution. Do not equate creation with successful persistence execution.

**Could it be legitimate?** Updaters, collaboration tools, device utilities and approved installers commonly use Run keys. Check software installation records, signer, target location, owner and change time.

**Additional real-SOC evidence:** Seek the exact registry value before/after, payload signature/hash, installer history, user logon, and execution at the next logon if authorized.

**Likely impact:** An unauthorized Run value may execute at the next logon in that user's context. This lab's command only prints a marker; no logon execution has been demonstrated.

## Tuning and evasion

Limit exemptions to approved exact value/path, trusted signer and documented installer behavior. Keep alerts for user-writable or changed destinations. Expand to RunOnce/tasks later.

Other persistence locations, renamed values, alternate registry views or telemetry suppression can bypass this narrow mechanism.

## Severity and escalation

MEDIUM for an unexplained value set; HIGH if unapproved and linked to suspicious payload or privileged scope; LOW after confirming the harmless authorized test.

No for the verified authorized marker and successful cleanup. Yes for unexplained persistence, untrusted target, persistence reappearance or correlated execution/network activity.

## ATT&CK

[T1547.001 — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/). The mechanism is mapped; actual execution must be independently verified.

Read [field validation methodology](../docs/detection-methodology.md) before editing this rule.

