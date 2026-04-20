$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPythonw = Join-Path $projectRoot ".venv\Scripts\pythonw.exe"
$url = "http://127.0.0.1:7870/"

if (-not (Test-Path $venvPythonw)) {
    throw "Virtual environment not found at $venvPythonw"
}

Set-Location $projectRoot

$existing = Get-NetTCPConnection -LocalPort 7870 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existing) {
    Start-Process $url
    return
}

$server = Start-Process -FilePath $venvPythonw -ArgumentList "app.py" -WorkingDirectory $projectRoot -PassThru

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

Start-Process $url
