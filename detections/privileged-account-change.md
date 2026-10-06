# Unexpected local account creation detection

**Status:** candidate Windows detection; native endpoint telemetry and live ingestion NOT VERIFIED. Contract-test output is in [rule tests](../evidence/validation/rule-tests/results.json).

## Objective and data source

Detect account creation and investigate authorization and potential privilege impact. Source: Windows Security Event 4720 (Audit User Account Management success).

## Telemetry fields and logic

`win.system.eventID`; parent group `windows_security`. Context to verify in actual decoded data: `win.eventdata.targetUserName`, `targetSid`, `targetDomainName`, `subjectUserName`, `subjectUserSid`, `subjectLogonId`, and `win.system.computer`/`systemTime`.

Match Security event 4720. This is account creation, not administrator-group addition. The rule is intentionally broad: do not deploy it unchanged to domain controllers and assume every event is local account creation.

Rule 100120 in [local_rules.xml](local_rules.xml). Expected result is an alert for the described behavior; this is an expectation until the real VM event is retained. Wazuh level is a rule priority, not the analyst's final severity.

## Triage and correlation

Capture 4720 showing actor and target SID/name. Verify Get-LocalUser reports Enabled=False and inspect local Administrators membership. Correlate subjectLogonId with 4624 and privilege context, and a narrow Sysmon Event 1 window for likely process origin. Event 4720 does not directly supply process ancestry; document that attribution limit.

**Could it be legitimate?** Authorized provisioning, installers, recovery accounts and documented administrator maintenance. Validate the request and owner independently of the actor's own claim.

**Additional real-SOC evidence:** Seek change authorization, account enabled state, SID/group membership, 4722/4732/4733 if available, 4624/4625 logons, 4672 privilege assignment and owner confirmation.

**Likely impact:** An enabled or privileged unauthorized account could provide durable access. The simulated account is disabled and standard, so the demonstrated action alone confers no administrator access.

## Tuning and evasion

Use host role and approved provisioning actors/windows; retain deviations in account naming, enablement and group membership. A lab-name exclusion would hide the test and teach little.

Reusing an existing account, later enabling it, changing another group, domain account creation, or missing audit policy can bypass the scenario's scope.

## Severity and escalation

MEDIUM pending authorization; HIGH for an unauthorized enabled administrator or suspicious subsequent logon; LOW for the verified disabled lab account.

No for the verified authorized disabled account and cleanup. Yes for unapproved creation, later enablement/admin membership, unexpected logons or unclear actor authority.

## ATT&CK

[T1136.001 — Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) describes the simulated mechanism. Disabled account creation alone does not prove an adversary established access.

Read [field validation methodology](../docs/detection-methodology.md) before editing this rule.

