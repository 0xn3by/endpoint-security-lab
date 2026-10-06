#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()] param([switch]$LabConfirmed, [switch]$Cleanup)
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Use only in your disposable lab VM; pass -LabConfirmed.' }
$name = 'edrlab_demo'
$description = 'EDR-LAB disposable disabled account'
$existing = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
if ($Cleanup) {
    if ($existing -and $existing.Description -ne $description) { throw 'Account is not marked as lab-owned; refusing deletion.' }
    if ($existing) { Remove-LocalUser -Name $name }
    Write-Output 'Lab account absent.'
    return
}
if ($existing) { throw 'Account already exists; refusing to modify it.' }
$password = ConvertTo-SecureString ('Aa1!' + [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')) -AsPlainText -Force
New-LocalUser -Name $name -Password $password -Disabled -Description $description | Select-Object Name,Enabled,SID
Write-Output 'Disabled standard account created. No administrator membership added. Capture 4720 then use -Cleanup.'
