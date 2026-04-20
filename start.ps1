$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
$venvPythonw = Join-Path $projectRoot ".venv\Scripts\pythonw.exe"
$url = "https://127.0.0.1:7870/"

if (-not (Test-Path $venvPython) -or -not (Test-Path $venvPythonw)) {
    throw "Virtual environment not found under $projectRoot\\.venv\\Scripts"
}

Set-Location $projectRoot

$prepareJson = & $venvPython -c "import json, app; print(json.dumps(app.prepare_runtime(), ensure_ascii=False))"
if (-not $prepareJson) {
    throw "Failed to prepare runtime security assets."
}

$runtime = $prepareJson | ConvertFrom-Json
$certPath = [string]$runtime.ca_cert_path
$thumbprint = ([string]$runtime.ca_thumbprint).ToUpperInvariant()
$httpsReadyScript = @"
import sys
import requests
import urllib3

url = sys.argv[1]
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
response = requests.get(url, verify=False, timeout=3)
response.raise_for_status()
"@

$existingRoot = Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $thumbprint } |
    Select-Object -First 1

if (-not $existingRoot -and (Test-Path $certPath)) {
    try {
        Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
    } catch {
    }
}

foreach ($port in 7870, 7871) {
    $existing = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existing) {
        Stop-Process -Id $existing.OwningProcess -Force
        Start-Sleep -Seconds 1
    }
}

Start-Process -FilePath $venvPythonw -ArgumentList "app.py" -WorkingDirectory $projectRoot | Out-Null

$isReady = $false
for ($i = 0; $i -lt 50; $i++) {
    Start-Sleep -Milliseconds 300
    try {
        & $venvPython -c $httpsReadyScript $url *> $null
        if ($LASTEXITCODE -eq 0) {
            $isReady = $true
            break
        }
    } catch {
    }
}

if (-not $isReady) {
    throw "HTTPS service did not become ready in time."
}

Start-Process $url
