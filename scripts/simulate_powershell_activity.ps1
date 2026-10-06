#requires -Version 5.1
[CmdletBinding()] param([switch]$LabConfirmed)
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Use only in your disposable lab VM; pass -LabConfirmed.' }
$payload = 'Write-Output "EDR-LAB harmless encoded command"; & "$env:WINDIR\System32\whoami.exe"'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
& "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded
if ($LASTEXITCODE -ne 0) { throw "Child PowerShell failed: $LASTEXITCODE" }
Write-Output 'Inspect Sysmon Event 1 for PowerShell and its whoami.exe child. No download performed.'
