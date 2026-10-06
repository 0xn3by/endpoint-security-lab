# Interview notes

**What is EDR?** Endpoint Detection and Response combines endpoint behavior collection, detection, investigation and response capabilities.

**How is EDR different from antivirus?** Antivirus emphasizes prevention and malware detection. EDR adds historical behavior, process relationships, hunting and response context; modern products overlap.

**How is EDR different from SIEM?** EDR concentrates on endpoint activity and response. SIEM correlates logs from endpoints, identity, networks and applications across the environment.

**Explain your endpoint lab.** I built a personal Wazuh endpoint investigation lab with four harmless Windows scenarios and a Linux loopback fallback. I verified real helper-generated network records reaching Wazuh and producing alerts. Windows execution and Sysmon transport remain pending until I run the VM steps. The repository keeps those limits visible.

**What telemetry did you collect?** In the executed Linux path, a controlled socket observer recorded actual loopback connections with time, process launch context, user, host and executable hash. The Windows plan collects Sysmon 1/3/13, Security 4720 and optional PowerShell 4104; I only claim those as collected after retaining real VM evidence.

**What is a process tree?** It is a chain of parent and child processes. I correlate Sysmon process GUIDs on the same host and verify start times.

**Why are parent-child relationships important?** They explain the origin of execution and help distinguish expected automation from unusual chains. They are one signal and can be incomplete or spoofed.

**How do you investigate suspicious PowerShell?** Preserve the command, inspect path/signature/hash, decode encoded text safely, identify user and token, reconstruct ancestry/children, then correlate script blocks, network and persistence with an approved change.

**What makes PowerShell suspicious but not automatically malicious?** Encoded commands and bypass flags hide useful context or relax a setting, but administrators and deployment tools also use them. Payload, origin, privilege and subsequent behavior determine risk.

**How do you detect persistence?** Monitor configuration changes such as Run-key value sets, identify the actor and executable, and verify whether it is approved and whether it actually ran. In this lab I implemented a harmless Run-key scenario.

**How do you investigate an unexpected administrator account?** Distinguish account creation from group addition; inspect actor/target SIDs, 4720/4732, authorization, logons and subsequent activity. A disabled standard account is lower risk than an enabled new administrator. My simulation uses the former.

**What would make you isolate a host?** Credible ongoing harm such as active malware, destructive activity, lateral movement or exfiltration, evaluated with host criticality and operational authority. A single ambiguous flag alone is insufficient.

**When would you escalate?** When evidence suggests unauthorized execution/persistence, privileged compromise, wider scope or material uncertainty on a sensitive host. I hand off evidence, severity rationale, actions and gaps.

**What are false positives?** Benign activity flagged as suspicious. I investigate the exact behavior and authorization before tuning, and avoid blanket exclusions for all PowerShell or all administrators.

**What limitations does this lab have?** Limited hosts/time, no malicious payloads, no enterprise baseline, a helper-observed Linux fallback, and pending Windows/full-dashboard verification. Contract tests do not establish production detection quality.

**What would enterprise EDR add?** Depending on the product: kernel telemetry, tamper protection, memory inspection, behavioral analytics, remote collection, host isolation, fleet-wide hunting, retention and response orchestration. This lab does not demonstrate those capabilities.
