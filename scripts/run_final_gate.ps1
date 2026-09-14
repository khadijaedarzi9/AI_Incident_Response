$ErrorActionPreference = "Stop"
$env:PYTHONDONTWRITEBYTECODE = "1"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
New-Item -ItemType Directory -Force artifacts\proof | Out-Null
Get-ChildItem artifacts\proof -File |
    Where-Object { $_.Name -ne "README.md" } |
    Remove-Item -Force

function Invoke-Checked {
    param(
        [string]$Name,
        [scriptblock]$Command,
        [string]$Log
    )
    Write-Host "=== $Name ==="
    & $Command | Tee-Object -FilePath $Log
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$docker = "docker"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    $docker = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
}

try {
    Invoke-Checked "Pinned package install" {
        python -m pip install -e ".[test]"
    } "artifacts\proof\install.txt"

    Invoke-Checked "Schema export" {
        python scripts\export_schemas.py
    } "artifacts\proof\schema-export.txt"

    Invoke-Checked "Judge scenarios" {
        python -m demo.scenarios.run --output artifacts\scenarios\results.json
    } "artifacts\proof\judge-scenarios.txt"

    Invoke-Checked "Control ablations" {
        python -m benchmarks.ablation --output artifacts\benchmark
    } "artifacts\proof\ablation-benchmark.txt"

    Invoke-Checked "Auditability gap" {
        python -m benchmarks.auditability `
            --output artifacts\benchmark\auditability.json
    } "artifacts\proof\auditability-gap.txt"

    Invoke-Checked "Signed canary demo" {
        python -m demo.run --output artifacts\demo
    } "artifacts\proof\demo-generation.txt"

    Invoke-Checked "Offline evidence audit" {
        python -m auditor.verify `
            --manifest artifacts\demo\manifest.json `
            --evidence artifacts\demo\evidence.jsonl `
            --receipt artifacts\demo\receipt.json `
            --operator-key artifacts\demo\operator-key.json
    } "artifacts\proof\offline-audit.txt"

    Invoke-Checked "Full test suite" {
        python -m pytest `
            --cov=app `
            --cov=auditor `
            --cov=benchmarks `
            --cov-branch `
            --cov-report=term-missing `
            --cov-report=json:artifacts\proof\coverage.json `
            --junitxml=artifacts\proof\junit.xml
    } "artifacts\proof\pytest-coverage.txt"

    Invoke-Checked "Docker network ablation" {
        & .\scripts\run_network_ablation.ps1
    } "artifacts\proof\network-ablation.txt"

    Invoke-Checked "Docker boundary image build" {
        $buildArguments = @()
        if ($env:BCP1_DOCKER_BASE_IMAGE) {
            $buildArguments = @(
                "--build-arg",
                "PYTHON_IMAGE=$($env:BCP1_DOCKER_BASE_IMAGE)"
            )
        }
        & $docker compose -f compose.boundary-smoke.yaml build @buildArguments
    } "artifacts\proof\docker-boundary-build.txt"

    Invoke-Checked "Docker boundary smoke" {
        & $docker compose -f compose.boundary-smoke.yaml up --no-build `
            --abort-on-container-exit --exit-code-from agent-probe
    } "artifacts\proof\docker-boundary-smoke.txt"

    Remove-Item -Recurse -Force .pytest_cache -ErrorAction SilentlyContinue
    Get-ChildItem -Directory -Recurse -Force |
        Where-Object { $_.Name -eq "__pycache__" } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Force .coverage -ErrorAction SilentlyContinue

    Invoke-Checked "Derived final-gate summary" {
        python scripts\summarize_final_gate.py
    } "artifacts\proof\final-gate-summary.txt"

    python scripts\capture_proof.py
    if ($LASTEXITCODE -ne 0) {
        throw "proof capture failed"
    }
    python scripts\build_submission.py
    if ($LASTEXITCODE -ne 0) {
        throw "submission package build failed"
    }
}
finally {
    & $docker compose -f compose.boundary-smoke.yaml down `
        --volumes --remove-orphans 2>$null | Out-Null
    & $docker compose -f compose.network-ablation.yaml down `
        --volumes --remove-orphans 2>$null | Out-Null
}

Write-Host "=== FINAL GATE PASSED ==="

