#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()] param([int]$Minutes = 15)
$ErrorActionPreference = 'Stop'
if ($Minutes -lt 1 -or $Minutes -gt 120) { throw 'Minutes must be 1..120.' }
$root = Join-Path $PSScriptRoot '..\evidence\private'
$out = Join-Path $root ((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
New-Item -ItemType Directory -Path $out -ErrorAction Stop | Out-Null
$start = (Get-Date).AddMinutes(-$Minutes)
foreach ($channel in @('Microsoft-Windows-Sysmon/Operational','Security','Microsoft-Windows-PowerShell/Operational')) {
    $stem = $channel -replace '[/\\]','_'
    Get-WinEvent -ListLog $channel -ErrorAction Stop | Out-Null
    $readErrors = @()
    $events = @(Get-WinEvent -FilterHashtable @{ LogName=$channel; StartTime=$start } -ErrorAction SilentlyContinue -ErrorVariable readErrors)
    foreach ($readError in $readErrors) {
        if ($readError.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw $readError }
    }
    if ($events.Count -eq 0) { Write-Warning "No events in the selected window for $channel; this is a visibility/collection check, not a verified scenario." }
    $xml = @($events | ForEach-Object { $_.ToXml() })
    Set-Content -Encoding UTF8 -Path (Join-Path $out "$stem.xml.txt") -Value $xml
    $query = '*[System[TimeCreated[timediff(@SystemTime) <= ' + ($Minutes * 60000) + ']]]'
    & wevtutil epl $channel (Join-Path $out "$stem.evtx") "/q:$query"
    if ($LASTEXITCODE -ne 0) { throw "wevtutil failed for $channel" }
}
Get-ChildItem $out -File | Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $out 'manifest.json')
Write-Output "Evidence exported to $out. Review/redact before publishing."
