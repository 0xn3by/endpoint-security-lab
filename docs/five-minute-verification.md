# Five-minute verification

Use this after installation and a completed simulation; it is not a promise that initial downloads or VM provisioning take five minutes.

1. **Minute 1 — health:** `docker compose ps` should show healthy. Run `docker compose exec -T manager /var/ossec/bin/wazuh-analysisd -t`; investigate any errors.
2. **Minute 2 — real telemetry:** run `python3 scripts/simulate_network_activity.py`, then `python3 scripts/capture_network_validation.py`. Require PASS for the exact new run ID. Preserve earlier report evidence before overwriting public latest-run extracts.
3. **Minute 3 — inspect one alert:** open the actual event and alert extract; compare process PID, source port, destination, rule and UTC time. Agent 000 is manager-local collection, not Windows enrollment.
4. **Minute 4 — Windows gate:** if the VM is available, require an Active agent and a matching local Sysmon event/manager archive. Otherwise leave Windows scenarios NOT VERIFIED. Never substitute synthetic test output.
5. **Minute 5 — disposition:** confirm the listener/child exited, update the relevant investigation with evidence IDs, explain severity/escalation, and identify the next missing screenshot or telemetry item. Run `python3 scripts/check_repository.py` before publishing.

Stop services when finished with `docker compose stop`. Capture source evidence before cleaning the Windows Run value/account or reverting the VM.
