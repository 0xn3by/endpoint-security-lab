# 03 — Unexpected local account creation

**Live Windows status: NOT VERIFIED.** This is a controlled simulation, not a real compromise.

## Preconditions

Finish the [agent](../../setup/endpoint-agent-setup.md) and [Sysmon](../../setup/sysmon-setup.md) setup. Prove a baseline event reaches manager archives. Use a snapshot and Windows PowerShell 5.1 in `C:\EDR` as Administrator. Record UTC start and end times and the exact commit/configuration used.

## Activity and run command

An elevated PowerShell session creates edrlab_demo with a random password, marked as lab-owned and disabled from creation. It does not add the account to Administrators. Password is not printed or stored.

```powershell
(Get-Date).ToUniversalTime().ToString('o')
.\scripts\simulate_account_change.ps1 -LabConfirmed
(Get-Date).ToUniversalTime().ToString('o')
```

## Prove the full workflow

1. Find Windows Security Event 4720 (Audit User Account Management success) locally with Get-WinEvent/Event Viewer; save event XML/EVTX.
2. Find the same event in manager archives by computer, event ID, record ID/time, and process GUID where present.
3. Confirm rule 100120 in manager alerts. In the full dashboard search `rule.id:100120` with the actual run time. If absent, inspect actual fields before changing a rule.
4. Capture 4720 showing actor and target SID/name. Verify Get-LocalUser reports Enabled=False and inspect local Administrators membership. Correlate subjectLogonId with 4624 and privilege context, and a narrow Sysmon Event 1 window for likely process origin. Event 4720 does not directly supply process ancestry; document that attribution limit.
5. Compare legitimate explanations, classify, justify severity and escalation, recommend remediation, and update [incident 003](../../investigations/incident-003.md).
6. Run `.\scripts\export_windows_evidence.ps1 -Minutes 15` elevated. Keep originals private, hash them, and publish only reviewed redacted extracts.

## Decision guide

Authorized provisioning, installers, recovery accounts and documented administrator maintenance. Validate the request and owner independently of the actor's own claim.

MEDIUM pending authorization; HIGH for an unauthorized enabled administrator or suspicious subsequent logon; LOW for the verified disabled lab account. No for the verified authorized disabled account and cleanup. Yes for unapproved creation, later enablement/admin membership, unexpected logons or unclear actor authority.

## Cleanup and verify

```powershell
.\scripts\simulate_account_change.ps1 -LabConfirmed -Cleanup
Get-LocalUser -Name edrlab_demo -ErrorAction SilentlyContinue
# No returned account is expected. Preserve deletion Event 4726 if emitted.
```

Mark complete only after successful execution, local telemetry, central receipt, actual-field detection validation, evidence-backed investigation and cleanup verification. [Detection details](../../detections/privileged-account-change.md).

