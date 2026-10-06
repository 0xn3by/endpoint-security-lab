# Sysmon and Windows auditing

Run elevated Windows PowerShell 5.1 in `C:\EDR`. Snapshot the VM first. Use the official Microsoft download:

```powershell
Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" 'C:\EDR\tools\Sysmon'
Get-AuthenticodeSignature 'C:\EDR\tools\Sysmon\Sysmon64.exe' | Format-List Status,SignerCertificate
# Verify a valid Microsoft signature before installation.
& 'C:\EDR\tools\Sysmon\Sysmon64.exe' -accepteula -i 'C:\EDR\config\sysmon.xml'
& 'C:\EDR\tools\Sysmon\Sysmon64.exe' -c
Get-Service Sysmon64
```

The config collects all process creates (Event 1, including SHA256), all network connects (Event 3), and Run-key registry changes (including Event 13). This is intentionally broad for a short disposable lab. Sysmon network events have process GUID/PID but usually no parent command line: join to Event 1 by process GUID plus host. A hash identifies file contents; it does not prove a file is benign.

If Sysmon already exists, save its existing configuration and use `-c C:\EDR\config\sysmon.xml` rather than reinstalling. Inspect `Sysmon64.exe -s` if your downloaded build rejects schema 4.90; do not silently omit failed collection settings.

Enable account-management auditing by language-independent subcategory GUID:

```powershell
auditpol /backup /file:C:\EDR\audit-policy-before.csv
auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
auditpol /get /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}"
```

That subcategory generates 4720 for account creation and 4726 for deletion. Administrator membership would require Security Group Management and 4732; this lab deliberately creates only a disabled standard account. Do not describe it as demonstrated privilege escalation.

For script-content context, enable PowerShell script block logging in the VM's Local Group Policy: Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging. Set Enabled. This produces 4104 for investigation; it is not required by rule 100100. Save the prior setting and restore it afterward. Script logging can capture sensitive command content.

```powershell
whoami.exe
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 3 | Format-List TimeCreated,Id,Message
```

Verify this event in manager archives before running scenarios. Record `systemTime`/Sysmon `utcTime` in UTC and distinguish them from Wazuh ingestion time.

Cleanup after preserving evidence: remove the Run value and lab account using their scripts, restore auditing with `auditpol /restore /file:C:\EDR\audit-policy-before.csv`, restore script-block policy, and revert the VM snapshot if desired. Uninstall Sysmon only if you installed it for this lab: `C:\EDR\tools\Sysmon\Sysmon64.exe -u`.

Sources: [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [Microsoft event 4720 schema](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720).
