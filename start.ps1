# Starts Backdoor Watch as administrator. Elevation is needed for per-connection byte
# counters, firewall rules, service/task removal and full process details.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$python = Join-Path $root "backend\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "Creating Python environment..."
    python -m venv (Join-Path $root "backend\.venv")
    & $python -m pip install -r (Join-Path $root "backend\requirements.txt")
}

if (-not (Test-Path (Join-Path $root "frontend\dist\index.html"))) {
    Write-Host "Building UI..."
    Push-Location (Join-Path $root "frontend")
    npm install
    npm run build
    Pop-Location
}

Set-Location (Join-Path $root "backend")
& $python run.py @args
