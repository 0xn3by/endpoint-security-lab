#requires -Version 5.1
[CmdletBinding()] param([switch]$LabConfirmed, [switch]$Cleanup)
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Use only in your disposable lab VM; pass -LabConfirmed.' }
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$name = 'EDRLabHarmless'
$value = '"' + $env:WINDIR + '\System32\cmd.exe" /d /c echo EDR-LAB harmless logon marker'
$existing = Get-ItemPropertyValue -Path $key -Name $name -ErrorAction SilentlyContinue
if ($Cleanup) {
    if ($null -ne $existing -and $existing -ne $value) { throw 'Value differs from lab payload; refusing deletion.' }
    if ($null -ne $existing) { Remove-ItemProperty -Path $key -Name $name }
    Write-Output 'Lab Run value absent. Other values preserved.'
    return
}
if ($null -ne $existing) { throw 'Lab value already exists. Inspect or clean it first.' }
if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
New-ItemProperty -Path $key -Name $name -Value $value -PropertyType String | Out-Null
Get-ItemProperty -Path $key -Name $name
Write-Output 'Run value created, NOT executed. Capture Event 13, then use -Cleanup.'
