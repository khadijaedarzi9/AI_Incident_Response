$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$compose = Join-Path $root "compose.network-ablation.yaml"
$docker = "docker"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    $docker = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
}

$result = 1
try {
    $buildArguments = @()
    if ($env:BCP1_DOCKER_BASE_IMAGE) {
        $buildArguments = @(
            "--build-arg",
            "PYTHON_IMAGE=$($env:BCP1_DOCKER_BASE_IMAGE)"
        )
    }
    & $docker compose -f $compose build @buildArguments
    if ($LASTEXITCODE -ne 0) {
        throw "image build failed"
    }

    & $docker compose -f $compose up -d gateway
    if ($LASTEXITCODE -ne 0) {
        throw "gateway startup failed"
    }

    $closedOutput = & $docker compose -f $compose run --rm closed-probe
    $closedOutput | Write-Output
    if ($LASTEXITCODE -ne 0) {
        throw "default-deny probe failed"
    }

    $openOutput = & $docker compose -f $compose run --rm open-probe
    $openOutput | Write-Output
    if ($LASTEXITCODE -ne 0) {
        throw "open-network control probe failed"
    }

    $closedJson = $closedOutput |
        Where-Object { $_ -is [string] -and $_.StartsWith("{") } |
        Select-Object -Last 1
    $openJson = $openOutput |
        Where-Object { $_ -is [string] -and $_.StartsWith("{") } |
        Select-Object -Last 1
    if (-not $closedJson -or -not $openJson) {
        throw "probe JSON output was not found"
    }
    $artifactDirectory = Join-Path $root "artifacts\benchmark"
    New-Item -ItemType Directory -Force $artifactDirectory | Out-Null
    [ordered]@{
        schema_version = "bcp1-network-ablation-v1"
        scope = "container-network-ablation-only"
        results = @(
            $closedJson | ConvertFrom-Json
            $openJson | ConvertFrom-Json
        )
    } | ConvertTo-Json -Depth 5 |
        Set-Content -Encoding UTF8 (Join-Path $artifactDirectory "network-results.json")
    $result = 0
}
finally {
    & $docker compose -f $compose down --volumes --remove-orphans
}

exit $result

