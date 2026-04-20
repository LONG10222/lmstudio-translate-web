$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
$url = "http://127.0.0.1:7870/"

if (-not (Test-Path $venvPython)) {
    throw "Virtual environment not found at $venvPython"
}

Set-Location $projectRoot

$existing = Get-NetTCPConnection -LocalPort 7870 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existing) {
    Start-Process $url
    return
}

$server = Start-Process -FilePath $venvPython -ArgumentList "app.py" -WorkingDirectory $projectRoot -PassThru

for ($i = 0; $i -lt 50; $i++) {
    Start-Sleep -Milliseconds 200
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
        if ($response.StatusCode -eq 200) {
            break
        }
    } catch {
    }
}

Write-Host ""
Write-Host "Local URL: $url"

$lanIps = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.IPAddress -notlike "127.*" -and
        ($_.IPAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)')
    } |
    Select-Object -ExpandProperty IPAddress -Unique

foreach ($ip in $lanIps) {
    Write-Host "LAN URL: http://$ip:7870/"
}

$securityPath = Join-Path $projectRoot "security.json"
if (Test-Path $securityPath) {
    try {
        $security = Get-Content -Encoding UTF8 $securityPath | ConvertFrom-Json
        if ($security.lan_access_token) {
            Write-Host "LAN Access Token: $($security.lan_access_token)"
        }
    } catch {
    }
}

Start-Process $url
Wait-Process -Id $server.Id
