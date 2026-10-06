# Suspicious PowerShell detection

**Status:** candidate Windows detection; native endpoint telemetry and live ingestion NOT VERIFIED. Contract-test output is in [rule tests](../evidence/validation/rule-tests/results.json).

## Objective and data source

Identify PowerShell launched with an encoded command or an explicit execution-policy bypass. Source: Sysmon Event 1; optional PowerShell 4104.

## Telemetry fields and logic

`win.eventdata.image`, `win.eventdata.commandLine`; parent group `sysmon_event1`. Context to collect: `processGuid`, `processId`, `parentProcessGuid`, `parentProcessId`, `parentImage`, `parentCommandLine`, `user`, `integrityLevel`, `hashes`, `utcTime`, and `win.system.computer`.

Match a full image path ending in powershell.exe or pwsh.exe, plus a command line containing -enc/-EncodedCommand or -ExecutionPolicy Bypass. Matching is case-insensitive. This intentionally does not cover every PowerShell abbreviation, host, or obfuscation.

Rule 100100 in [local_rules.xml](local_rules.xml). Expected result is an alert for the described behavior; this is an expectation until the real VM event is retained. Wazuh level is a rule priority, not the analyst's final severity.

## Triage and correlation

Capture Event 1 for the child PowerShell and whoami.exe. Join the whoami parentProcessGuid to the child PowerShell processGuid. Preserve the encoded command and decoded text; verify the binary path/signature/hash and actual user/integrity. If 4104 is enabled, preserve the payload script block. Search Event 3 and Event 13 for that process GUID; record gaps explicitly.

**Could it be legitimate?** Software deployment, remote administration and maintenance scripts can use encoding and bypass. Verify the change window, exact decoded payload, actor, expected parent and approved script provenance.

**Additional real-SOC evidence:** Inspect the launch parent's Event 1, PowerShell 4104, user logon, file provenance, approved change records and surrounding DNS/proxy/network logs.

**Likely impact:** PowerShell can execute commands with the caller's privileges. The fixed lab payload is harmless; unknown payloads require investigation.

## Tuning and evasion

Prefer a narrow approved-tool, signer/hash, parent, host-role and time-window exception with review expiry. Do not allowlist all administrators or powershell.exe.

Shortened/alternative flags, in-process PowerShell hosts, renamed executables, missing command lines and log tampering can evade this rule.

## Severity and escalation

MEDIUM at initial unexplained execution; LOW only after verifying the authorized marker/whoami payload, bounded scope and expected actor.

No for a verified authorized simulation. Yes if the actor/payload is unexplained, privilege is high, the parent is anomalous, or correlated persistence/network/file activity raises concern.

## ATT&CK

[T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/). Encoding alone does not justify a command-and-control mapping.

Read [field validation methodology](../docs/detection-methodology.md) before editing this rule.

