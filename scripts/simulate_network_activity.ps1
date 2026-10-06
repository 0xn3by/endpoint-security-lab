#requires -Version 5.1
[CmdletBinding()] param([switch]$LabConfirmed)
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Use only in your disposable lab VM; pass -LabConfirmed.' }
# A raw TCP listener avoids HTTP.sys URL reservations; traffic never leaves loopback.
$listener = New-Object Net.Sockets.TcpListener ([Net.IPAddress]::Loopback),18080
try {
    $listener.Start()
    for ($i = 0; $i -lt 6; $i++) {
        $client = New-Object Net.Sockets.TcpClient
        $server = $null
        try {
            $client.Connect('127.0.0.1',18080)
            $server = $listener.AcceptTcpClient()
            $bytes = [Text.Encoding]::UTF8.GetBytes('EDR-LAB')
            $client.GetStream().Write($bytes,0,$bytes.Length)
            Write-Output ((Get-Date).ToUniversalTime().ToString('o') + ' loopback TCP connection to port 18080')
        } finally { if ($server) { $server.Dispose() }; $client.Dispose() }
        Start-Sleep -Milliseconds 500
    }
} finally { $listener.Stop() }
Write-Output 'Inspect Sysmon Event 3. Loopback visibility must be verified on your Sysmon build.'
