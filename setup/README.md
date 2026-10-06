# Setup and one-day schedule

This is a personal endpoint-security lab. Use a disposable Windows 10/11 VM with a snapshot, a local lab administrator, and a host-only network. Do not join it to a work domain. No Kali VM is needed.

1. **First 45 minutes:** install prerequisites and start [Wazuh](wazuh-setup.md). The root Compose file runs the manager engine; the optional official stack adds the indexer and dashboard.
2. **Next 45 minutes:** prepare the [Windows agent](endpoint-agent-setup.md), enable [Sysmon and auditing](sysmon-setup.md), and prove a normal process event arrives.
3. **Next 90 minutes:** run each [scenario](../README.md#scenarios) individually, record UTC start/end times, capture evidence, then clean up.
4. **Next hour:** complete the [investigation records](../investigations/incident-001.md), justify severity and escalation, and take the [screenshots](../screenshots/README.md).
5. **Final 30 minutes:** check reproduction, evidence hashes, redaction, and the [validation matrix](../reports/validation-matrix.md).

Budget is a planning estimate, not a measured completion time. A Windows VM download/install may require extra time. Native Windows verification is a manual prerequisite on the current host.

## Prerequisites

Fedora host: x86-64, Python 3, Git, curl, Docker Engine and Compose plugin. A dedicated machine with at least 16 GB RAM and 80 GB free disk is a practical target for the full stack plus Windows. The initial host had about 6 GB available RAM and 31 GB free disk; use the manager-only path here until resources are freed. Reserve roughly 4 GB RAM for the Windows VM. Do not run both manager deployments on the same ports.

Install ordinary tools:

```bash
sudo dnf install -y git curl python3
```

On a clean host, install Docker using the [official Fedora procedure](https://docs.docker.com/engine/install/fedora/):

```bash
sudo dnf config-manager addrepo --from-repofile https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker version
sudo docker compose version
```

If Docker already works, keep that installation. Review the official package-conflict guidance before replacing an existing engine. The repository build used the host's existing Docker 29.7.2 and Compose 5.5.1; it did not reinstall them.

Commands throughout use `docker`; prefix with `sudo` if your account cannot reach its socket. Python helpers that invoke Docker also need socket access. Use `sudo python3 scripts/test_rules.py` / `sudo python3 scripts/capture_network_validation.py` when needed, and note that resulting evidence may be root-owned. Docker access gives extensive host privileges. Keep SELinux enabled; mounts use private `:Z` or shared `:z` labels as appropriate.

For a Windows VM, use Fedora Virtual Machine Manager (`sudo dnf install virt-manager`) or an existing hypervisor. Obtain Windows installation media from Microsoft and follow its licensing terms. Create a host-only adapter, snapshot the clean VM, and copy this repository into `C:\EDR`. Installing Windows itself has not been automated or verified here.

No Python third-party packages are required for the local helpers.
