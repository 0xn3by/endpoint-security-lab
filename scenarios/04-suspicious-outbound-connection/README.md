# 04 — Repeated controlled connections

## Linux fallback — live ingestion verified

From the repository root with the manager healthy:

```bash
python3 scripts/simulate_network_activity.py
python3 scripts/capture_network_validation.py
```

The helper listens only on 127.0.0.1:18080, starts a child Python process and accepts six connections spaced about half a second apart. It records actual accept times, peer ports and received byte lengths, plus known child launch context. It exits and closes the listener/child automatically; it creates no persistence. If the port is occupied it fails rather than changing another process.

Workflow: socket activity → helper JSON → mounted file → Wazuh localfile collector → rule 100140 → retained alert → correlation by run/PID/source port → benign authorized classification → LOW → no escalation → verify socket/child exit → [incident 004](../../investigations/incident-004.md).

This validates a real monitoring pipeline with helper instrumentation. It does not prove Windows agent or kernel-level endpoint attribution. Raw evidence stays under `evidence/private/<run-id>/`. Public redacted records and extracts are under `evidence/validation/live-network/`.

## Windows variant — NOT VERIFIED

Complete [Sysmon/agent setup](../../setup/README.md), then in Windows PowerShell 5.1 at `C:\EDR`:

```powershell
.\scripts\simulate_network_activity.ps1 -LabConfirmed
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -MaxEvents 20 | Format-List TimeCreated,Message
.\scripts\export_windows_evidence.ps1 -Minutes 15
```

Find Event 3 for powershell.exe and destination 127.0.0.1:18080, then join its process GUID to Event 1 for user, parent and command line. Confirm central archives and rule 100130. If your Sysmon version does not emit loopback events, document the gap and retain the verified Linux fallback. No external destination is used.

## Investigation and cleanup

Determine listener owner, originating process, privilege, destination and timing. Check before/after context and whether other destinations exist; do not infer malicious intent from repetition alone. The scripts close their own sockets automatically. Verify no listener remains using `ss -ltn 'sport = :18080'` on Linux or `Get-NetTCPConnection -LocalPort 18080 -State Listen -ErrorAction SilentlyContinue` on Windows. TIME_WAIT entries can remain briefly and are not a persistent listener.

Capture [network evidence and timeline screenshots](../../screenshots/README.md). [Detection details](../../detections/suspicious-network.md).
