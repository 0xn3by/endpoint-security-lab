# Resume evidence — personal project

## Three bullet options

- Built a personal Wazuh lab with five custom rules and safe simulation scripts for PowerShell, Run-key changes, account creation and loopback network activity; documented native Windows validation gaps.
- Correlated six retained helper-observed TCP connections with six Wazuh rule 100140 alerts using run IDs, timestamps, process IDs and network fields; documented a benign LOW-severity investigation.
- Developed endpoint triage playbooks and evidence-verification tooling with ten passing regression tests, separating process attribution, false-positive assessment and escalation decisions from unsupported conclusions.

## Concise project description

Personal Wazuh endpoint investigation lab with a retained Linux telemetry-to-alert case, candidate Windows rules and explicit manual gates for Sysmon/agent execution.

## Technology list

Wazuh 4.14.8, Docker Compose, Python, Linux, JSON/XML; Windows PowerShell 5.1, Sysmon and Windows Event Logs in the supplied but runtime-unverified VM workflow.

## Strongest measured facts

- Six source connection records and six matching retained alerts; exact run in [case 004](../investigations/incident-004.md).
- 2.504257 seconds between the first and last retained connection observations; not a response-time or detection-latency metric.
- Ten verifier tests passed in [current local checks](../evidence/validation/audit-local.json).
- Fifteen retained synthetic Wazuh contract transcripts support five predicates; these were inspected, not rerun in this audit.

See [validation](VALIDATION.md). Do not claim native Windows collection, completed Windows investigations, administrator-group modification, commercial EDR response, enterprise experience, detection accuracy or improved response times. Explain what you personally ran versus what you inspected in retained evidence.
