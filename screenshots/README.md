# Manual screenshot checklist

No screenshots have been generated. Capture only actual UI/terminal evidence from your run. Use PNG, readable text, a narrow UTC window and consistent host pseudonyms. Redact credentials, public IPs, personal usernames, unrelated logs and enrollment keys. Keep original evidence private; screenshots supplement raw events rather than replacing them.

1. **01-agent-connected.png:** Wazuh agent list showing EDR-WIN01 Active, agent ID and last keepalive. Manager-only alternative: `agent_control -l` output. Do not substitute manager agent 000 for a Windows enrollment.
2. **02-endpoint-event.png:** actual Sysmon Event 1 locally and matching manager archive/alert fields: computer, record ID, time, process GUID and command line.
3. **03-powershell-alert.png:** rule 100100 with host/user, event UTC time and full encoded/bypass command line. Capture only after native execution succeeds.
4. **04-process-context.png:** PowerShell's process GUID, parent GUID/image/command and whoami child's matching parent GUID. A manually drawn tree must label the underlying event IDs and any inferred edges.
5. **05-persistence-alert.png:** rule 100110 plus actual Run targetObject/details, actor and registry verification. Add a cleanup screenshot showing the lab value absent.
6. **06-account-alert.png:** rule 100120, 4720 actor/target SID, and Get-LocalUser showing the test account disabled. Do not caption this as an administrator addition.
7. **07-network-alert.png:** Windows rule 100130 if verified, or Linux rule 100140 explicitly captioned as helper telemetry. Show process, destination, port, time and alert ID.
8. **08-investigation-timeline.png:** actual source/alert timestamps for one run plus evidence references, classification, severity rationale and escalation decision. Do not insert proposed timestamps for unexecuted cases.
9. **09-dashboard-overview.png (optional):** useful filters for lab host, time and rules. Decorative dashboard totals do not demonstrate investigation quality.

Suggested caption format: **Personal lab — source/tool — actual UTC window — behavior observed — redactions — verification limitation.** Add selected images to the README only after they exist and their captions accurately describe the evidence.
