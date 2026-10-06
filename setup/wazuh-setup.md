# Wazuh deployment

## Verified lightweight manager path

Run from the repository root:

```bash
cp -n .env.example .env
mkdir -p .runtime/telemetry
touch .runtime/telemetry/network.jsonl
docker compose up -d --wait --wait-timeout 90
docker compose exec -T manager /var/ossec/bin/wazuh-analysisd -t
python3 scripts/test_rules.py
python3 scripts/simulate_network_activity.py
```

This pins Wazuh 4.14.8 and starts the manager services. It has no indexer or dashboard. The manager API runs inside the container but has no published host port. The image's initialization prepares its internal configuration before Wazuh starts. The entrypoint handles subsequent restarts and graceful shutdown. Logs, queue, configuration, and enrollment keys use named volumes.

For a Windows VM, set `WAZUH_BIND_IP` in `.env` to your Fedora host-only adapter IPv4 address, then run `docker compose up -d --wait`. Never use `127.0.0.1` as the manager address inside Windows: that points to Windows itself. Allow TCP 1514 (agent telemetry) and 1515 (enrollment) only from the lab VM's host-only IP in your host firewall. Enrollment has no shared password in this isolated lab; do not expose 1515 to untrusted networks. Stop enrollment after adding your VM if the lab network is shared.

Check addresses with `ip -br address` on Fedora and `Get-NetIPAddress -AddressFamily IPv4` on Windows. Keep the VM off bridged/public networks. Example firewall rule, replacing both values before execution:

```bash
sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="WINDOWS_VM_IP/32" port port="1514-1515" protocol="tcp" accept'
```

Runtime firewall changes disappear on reboot. Use the same rule with `--remove-rich-rule` after the lab. Do not disable the firewall or SELinux.

## Verification and evidence export

```bash
docker compose exec -T manager /var/ossec/bin/agent_control -l
docker compose exec -T manager tail -n 20 /var/ossec/logs/alerts/alerts.json
docker compose exec -T manager tail -n 20 /var/ossec/logs/archives/archives.json
python3 scripts/capture_network_validation.py
```

The capture helper exports only the latest locally generated run's matching alert records and checks every observed connection. It creates private evidence and a public redacted summary. It fails if ingestion is missing. Manager local-file events have agent ID `000`; that is not proof of a Windows agent connection.

`logall_json=yes` preserves events that do not produce alerts in this short lab. Archives are not automatically indexed in a dashboard. Keep the capture window small; command lines and account names may contain private information. Stop the manager after use to bound disk growth:

```bash
docker compose stop
docker compose start --wait
```

To apply edits to rule/config source files, use `docker compose restart manager` and check health before testing. `docker compose down` keeps named evidence volumes; do not add `-v` unless you intentionally want to erase them.

## Optional full dashboard path — infrastructure verified

Use the official single-node stack, which includes manager, indexer, dashboard, certificates, and Filebeat. The preparation helper fetches the pinned upstream configuration, replaces its published sample credentials with generated values, restricts published ports, and installs this lab's rules. It keeps all generated credentials and upstream files inside ignored `.runtime/`.

On this workspace the stack is already prepared and was tested successfully. Skip preparation and certificate generation when restarting it; run `docker compose -f .runtime/wazuh-docker/single-node/docker-compose.yml up -d` from the repository root, with the lightweight manager stopped. The commands below are for a fresh checkout. The preparation helper refuses to overwrite an existing stack.

```bash
docker compose stop
python3 scripts/prepare_full_stack.py
cd .runtime/wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
docker compose ps
```

The indexer requires `vm.max_map_count` of at least 262144:

```bash
sysctl vm.max_map_count
# Only if lower; this affects the host and resets after reboot:
sudo sysctl -w vm.max_map_count=262144
```

Open `https://127.0.0.1:8443` on Fedora. Use the generated admin credential in `.runtime/full-stack-credentials.json`. Accept the locally generated certificate only after confirming this is your local service. Allow several minutes for first initialization. Select the Wazuh threat-hunting/events view and the `wazuh-alerts-*` data view; search `rule.id:100100` etc. Set the time picker to the actual UTC run window.

From the repository root, verify infrastructure with `python3 scripts/verify_full_stack.py`. The retained [result](../evidence/validation/full-stack.json) confirms authenticated indexer/dashboard status and manager API access. The build notes report a successful Filebeat output test, but no transcript is retained; this result is NOT VERIFIED by the current audit. This does not establish Windows scenario alert visibility. The helper validates the generated CA chain in compatibility mode because the upstream lab CA lacks the keyUsage extension required by newer Python strict mode; it permits the service-name/localhost hostname difference. It does not weaken service configuration.

The upstream certificate generator printed a missing `find` warning during cleanup, but generated certificates were present and used successfully by the services and Filebeat. Keep private-key permissions intact. Stop the full stack with `docker compose -f .runtime/wazuh-docker/single-node/docker-compose.yml stop` from the repository root before returning to the lightweight deployment.

The two stacks have independent enrollment keys: re-enroll Windows when switching. Full-stack equivalents use service `wazuh.manager`, e.g. `docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -l`. The root helper telemetry mount is not configured in the full stack; use Windows agent ingestion there.

## Troubleshooting

- **Manager exits:** `docker compose logs --tail=80`; inspect errors before re-running. Validate XML with `python3 scripts/check_repository.py` and manager rules with `wazuh-analysisd -t`.
- **Permission denied on Docker socket:** use `sudo docker`; do not make the socket world-writable.
- **Mount access denied on Fedora:** keep the supplied `:Z`/`:z` labels and inspect `sudo ausearch -m AVC -ts recent`. Shared inputs require `:z`. Do not turn off SELinux.
- **Agent disconnected:** test Windows `Test-NetConnection MANAGER_IP -Port 1514` and `-Port 1515`, check manager binding, firewall, agent service, agent log, and duplicate enrollment names.
- **Event present locally but absent centrally:** check channel spelling, duplicate collection blocks, agent connectivity, manager archives, and UTC clock alignment. Restart the agent after configuration edits.
- **Archives contain event but alert missing:** inspect its exact `data.win` fields, rule parents and field casing. Native EventChannel replay is not equivalent to ordinary JSON CLI logtest; use the isolated harness described in [methodology](../docs/detection-methodology.md) for predicate checks, then confirm through the real agent. Do not feed the alert wrapper as a raw event or change the live decoder to make a test pass.
- **Alert in file but absent in dashboard:** check Filebeat, indexer health, dashboard time range and `wazuh-alerts-*`. This is an indexing issue, not necessarily a detection issue.
- **No loopback Sysmon Event 3:** confirm NetworkConnect collection. If the Sysmon build does not emit loopback events, use the verified Linux fallback or a separately controlled lab listener. Do not claim Windows network coverage without a captured event.

Sources: [official Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html), [pinned upstream Compose](https://github.com/wazuh/wazuh-docker/blob/v4.14.8/single-node/docker-compose.yml), [Wazuh rule testing](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html).
