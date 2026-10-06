# Local validation record — 2026-10-06

These are checks executed while building this repository, not projected results.

- `python3 scripts/check_repository.py`: PASS; eight Python files parsed, four XML/config files parsed, 90 local Markdown link targets checked, zero failures at the recorded final check.
- `python3 -O -m unittest discover -s tests -v`: PASS, five evidence-verifier cases. Explicit exceptions preserve rejection checks when assertions are disabled.
- `bash -n scripts/manager-entrypoint.sh tests/logtest-entrypoint.sh`: PASS.
- `docker compose config --quiet`: PASS for the lightweight stack; preparation also ran Compose validation for the generated full stack.
- `/var/ossec/bin/wazuh-analysisd -t` inside the final lightweight manager: exit 0 with no reported configuration error.
- Fresh lightweight-manager startup, health and restart: verified. `agent_control -l` showed only local agent 000; no Windows enrollment is claimed.
- PowerShell parser container: all six `.ps1` files passed after the evidence-export update. Image: `mcr.microsoft.com/powershell:7.4-ubuntu-22.04`; downloaded digest `sha256:62300a213a9293916333df2b014cd3a8f22fb0b0b65f2bb446aaf436bcf8c868`. This checks syntax, not Windows execution or PowerShell 5.1 runtime behavior.
- Linux simulation: actual six-connection run, confirmed by [retained summary](live-network/summary.json). A later host check found no listener on port 18080 and no process at the recorded child PID.
- Wazuh detection contracts: [15 passing cases](rule-tests/results.json), using the explicitly documented isolated JSON bridge.
- Full-stack authenticated health: [PASS](full-stack.json). Filebeat `test output` reported URL parsing, DNS, TCP, certificate-chain/TLS handshake and server communication OK.
- Git ignore checks confirmed generated credentials and private alert originals are excluded from the repository.

Docker, Windows installer downloads, VM provisioning and native Windows telemetry were not all installed/executed from a clean operating system. Refer to the [validation matrix](../../reports/validation-matrix.md) before making portfolio claims.
