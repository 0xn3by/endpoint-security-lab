# 02 — Run-key persistence indicator

**Live Windows status: NOT VERIFIED.** This is a controlled simulation, not a real compromise.

## Preconditions

Finish the [agent](../../setup/endpoint-agent-setup.md) and [Sysmon](../../setup/sysmon-setup.md) setup. Prove a baseline event reaches manager archives. Use a snapshot and Windows PowerShell 5.1 in `C:\EDR`. Record UTC start and end times and the exact commit/configuration used.

## Activity and run command

Create the current user's EDRLabHarmless Run value pointing to cmd.exe /d /c echo with a harmless marker. The value is not executed during setup. No elevated permission is needed.

```powershell
(Get-Date).ToUniversalTime().ToString('o')
.\scripts\simulate_persistence.ps1 -LabConfirmed
(Get-Date).ToUniversalTime().ToString('o')
```

## Prove the full workflow

1. Find Sysmon Event 13 (registry value set), correlated with Event 1 locally with Get-WinEvent/Event Viewer; save event XML/EVTX.
2. Find the same event in manager archives by computer, event ID, record ID/time, and process GUID where present.
3. Confirm rule 100110 in manager alerts. In the full dashboard search `rule.id:100110` with the actual run time. If absent, inspect actual fields before changing a rule.
4. Capture Event 13 with the exact targetObject and details, then read the registry value directly. Join its processGuid to Event 1 to find the writer and parent. Record whether the configured executable exists and whether a later process event proves execution. Do not equate creation with successful persistence execution.
5. Compare legitimate explanations, classify, justify severity and escalation, recommend remediation, and update [incident 002](../../investigations/incident-002.md).
6. Run `.\scripts\export_windows_evidence.ps1 -Minutes 15` elevated. Keep originals private, hash them, and publish only reviewed redacted extracts.

## Decision guide

Updaters, collaboration tools, device utilities and approved installers commonly use Run keys. Check software installation records, signer, target location, owner and change time.

MEDIUM for an unexplained value set; HIGH if unapproved and linked to suspicious payload or privileged scope; LOW after confirming the harmless authorized test. No for the verified authorized marker and successful cleanup. Yes for unexplained persistence, untrusted target, persistence reappearance or correlated execution/network activity.

## Cleanup and verify

```powershell
.\scripts\simulate_persistence.ps1 -LabConfirmed -Cleanup
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name EDRLabHarmless -ErrorAction SilentlyContinue
# No returned lab value is expected. Other values must remain.
```

Mark complete only after successful execution, local telemetry, central receipt, actual-field detection validation, evidence-backed investigation and cleanup verification. [Detection details](../../detections/persistence.md).

