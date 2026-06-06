# AMHF tasks for Windows PowerShell. Mirrors Makefile targets.
# Usage: .\tasks.ps1 <target>
#   e.g. .\tasks.ps1 install

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Target
)

$ErrorActionPreference = "Stop"
$VenvDir = ".venv"
$VenvPy  = Join-Path $VenvDir "Scripts\python.exe"

function Invoke-Install {
    py -3.14 -m venv $VenvDir
    & $VenvPy -m pip install --upgrade pip
    & $VenvPy -m pip install -e ".[dev]"
}

function Invoke-Lint     { & $VenvPy -m ruff check amhf tests }
function Invoke-Typecheck{ & $VenvPy -m mypy --strict amhf }
function Invoke-Test     { & $VenvPy -m pytest --cov=amhf --cov-fail-under=70 }
function Invoke-Cov      { & $VenvPy -m pytest --cov=amhf --cov-report=html }
function Invoke-Demo     { & $VenvPy -m amhf demo }
function Invoke-Baseline { & $VenvPy -m amhf run -c configs/scenarios/s1_baseline_modsec_p1_flag.yaml }
function Invoke-Full     { & $VenvPy -m amhf run -c configs/scenarios/s4_adaptive_modsec_p1_flag.yaml }

function Invoke-StandUp   { docker compose -f stand/docker-compose.yml up -d --build }
function Invoke-StandDown { docker compose -f stand/docker-compose.yml down }
function Invoke-StandReset {
    docker compose -f stand/docker-compose.yml down -v
    docker compose -f stand/docker-compose.yml up -d --build
}

function Invoke-Clean {
    Get-ChildItem -Path . -Recurse -Force -Include `
        "build","dist","*.egg-info",".pytest_cache",".mypy_cache",".ruff_cache" `
        -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

switch ($Target.ToLowerInvariant()) {
    "install"     { Invoke-Install }
    "lint"        { Invoke-Lint }
    "typecheck"   { Invoke-Typecheck }
    "test"        { Invoke-Test }
    "cov"         { Invoke-Cov }
    "demo"        { Invoke-Demo }
    "baseline"    { Invoke-Baseline }
    "full"        { Invoke-Full }
    "stand-up"    { Invoke-StandUp }
    "stand-down"  { Invoke-StandDown }
    "stand-reset" { Invoke-StandReset }
    "clean"       { Invoke-Clean }
    default {
        Write-Host "Unknown target: $Target" -ForegroundColor Red
        Write-Host "Targets: install, lint, typecheck, test, cov, demo, baseline, full, stand-up, stand-down, stand-reset, clean"
        exit 1
    }
}
