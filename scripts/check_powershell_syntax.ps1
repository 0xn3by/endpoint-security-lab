$ErrorActionPreference = 'Stop'
$failed = $false
Get-ChildItem (Join-Path $PSScriptRoot '*.ps1') | ForEach-Object {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count -gt 0) {
        $failed = $true
        $parseErrors | ForEach-Object { Write-Output $_.Message }
    } else { Write-Output ("PARSE PASS: " + $_.Name) }
}
if ($failed) { exit 1 }
Write-Output 'Syntax only. Windows execution, APIs and telemetry remain NOT VERIFIED.'
