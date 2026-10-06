# Windows agent enrollment

Use Windows PowerShell 5.1 **as Administrator** inside your disposable VM. Set the actual Fedora host-only address when prompted. Manager must already be reachable on TCP 1514/1515.

```powershell
$Manager = Read-Host 'Fedora host-only manager IPv4 address'
Test-NetConnection $Manager -Port 1515
Invoke-WebRequest -Uri 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.8-1.msi' -OutFile "$env:TEMP\wazuh-agent.msi"
Get-AuthenticodeSignature "$env:TEMP\wazuh-agent.msi" | Format-List Status,SignerCertificate
# Continue only after confirming a valid signature and expected Wazuh publisher.
$install = Start-Process msiexec.exe -ArgumentList @('/i',"`"$env:TEMP\wazuh-agent.msi`"",'/qn',"WAZUH_MANAGER=$Manager",'WAZUH_AGENT_NAME=EDR-WIN01') -Wait -PassThru
if ($install.ExitCode -notin @(0,3010)) { throw "Install failed: $($install.ExitCode)" }
Start-Service WazuhSvc
Get-Service WazuhSvc
Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 30
```

Download and installation commands are supplied for reproduction; no Windows runtime was available during the repository build. A reboot may be required when MSI returns 3010.

Back up `C:\Program Files (x86)\ossec-agent\ossec.conf` before editing. Merge the three `localfile` blocks from [windows-agent-snippet.xml](../config/windows-agent-snippet.xml) inside its existing `ossec_config`. Keep its existing client/manager settings. Security is usually already collected; keep exactly one Security block. Do not paste a nested `ossec_config` element.

```powershell
Copy-Item 'C:\Program Files (x86)\ossec-agent\ossec.conf' 'C:\Program Files (x86)\ossec-agent\ossec.conf.pre-lab'
notepad 'C:\Program Files (x86)\ossec-agent\ossec.conf'
Restart-Service WazuhSvc
```

On Fedora, confirm `EDR-WIN01` is Active using `agent_control -l`. Inside Windows, run `whoami.exe`; after Sysmon setup, find its Event 1 locally and in manager archives. Match computer name, command line, process GUID, event record ID, and event timestamp. Record agent ID separately from computer name. This is the baseline before Scenario 1.

For re-enrollment, use a unique agent name or remove only the obsolete lab registration through `manage_agents` after checking its ID. Do not remove unrelated agents. Never publish `client.keys` or your entire agent configuration.

Reference: [Wazuh Windows agent deployment](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html).
