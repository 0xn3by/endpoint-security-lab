# 01 — Suspicious PowerShell

**Live Windows status: NOT VERIFIED.** This is a controlled simulation, not a real compromise.

## Preconditions

Finish the [agent](../../setup/endpoint-agent-setup.md) and [Sysmon](../../setup/sysmon-setup.md) setup. Prove a baseline event reaches manager archives. Use a snapshot and Windows PowerShell 5.1 in `C:\EDR`. Record UTC start and end times and the exact commit/configuration used.

## Activity and run command

A child Windows PowerShell process decodes a fixed harmless UTF-16LE payload, writes a lab marker, and launches whoami.exe. The simulator performs no download.

```powershell
(Get-Date).ToUniversalTime().ToString('o')
.\scripts\simulate_powershell_activity.ps1 -LabConfirmed
(Get-Date).ToUniversalTime().ToString('o')
```

## Prove the full workflow

1. Find Sysmon Event 1; optional PowerShell 4104 locally with Get-WinEvent/Event Viewer; save event XML/EVTX.
2. Find the same event in manager archives by computer, event ID, record ID/time, and process GUID where present.
3. Confirm rule 100100 in manager alerts. In the full dashboard search `rule.id:100100` with the actual run time. If absent, inspect actual fields before changing a rule.
4. Capture Event 1 for the child PowerShell and whoami.exe. Join the whoami parentProcessGuid to the child PowerShell processGuid. Preserve the encoded command and decoded text; verify the binary path/signature/hash and actual user/integrity. If 4104 is enabled, preserve the payload script block. Search Event 3 and Event 13 for that process GUID; record gaps explicitly.
5. Compare legitimate explanations, classify, justify severity and escalation, recommend remediation, and update [incident 001](../../investigations/incident-001.md).
6. Run `.\scripts\export_windows_evidence.ps1 -Minutes 15` elevated. Keep originals private, hash them, and publish only reviewed redacted extracts.

## Decision guide

Software deployment, remote administration and maintenance scripts can use encoding and bypass. Verify the change window, exact decoded payload, actor, expected parent and approved script provenance.

MEDIUM at initial unexplained execution; LOW only after verifying the authorized marker/whoami payload, bounded scope and expected actor. No for a verified authorized simulation. Yes if the actor/payload is unexplained, privilege is high, the parent is anomalous, or correlated persistence/network/file activity raises concern.

## Cleanup and verify

No persistent artifact is created. Preserve evidence; the child processes exit automatically.

Mark complete only after successful execution, local telemetry, central receipt, actual-field detection validation, evidence-backed investigation and cleanup verification. [Detection details](../../detections/suspicious-powershell.md).

