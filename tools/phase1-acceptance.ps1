param([string]$ModelEndpoint = '')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$output = Join-Path $root '.local'
$required = @('docs/180单事件一期输入材料-2026-10-15.json', 'docs/第一轮验收-180-快照34-2026-10-15.json')
foreach ($file in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $file))) { throw "离线验收材料缺失：$file" }
}
New-Item -ItemType Directory -Force -Path $output | Out-Null
$names = @('PHASE_ONE_ACCEPTANCE_OUTPUT','PHASE_ONE_REAL_OUTPUT','PHASE_ONE_MODEL_ENDPOINT','PHASE_ONE_MODEL_OUTPUT')
$previous = @{}
foreach ($name in $names) { $previous[$name] = [Environment]::GetEnvironmentVariable($name,'Process') }
Push-Location (Join-Path $root 'vulnscan-backend')
try {
    $env:PHASE_ONE_ACCEPTANCE_OUTPUT = Join-Path $output 'phase1-v1-snapshot34.json'
    $env:PHASE_ONE_REAL_OUTPUT = Join-Path $output 'phase1-v1-real-samples.json'
    [Environment]::SetEnvironmentVariable('PHASE_ONE_MODEL_ENDPOINT',$null,'Process')
    go build ./traffic/... 2>&1 | Tee-Object (Join-Path $output 'phase1-v1-build.log')
    if ($LASTEXITCODE -ne 0) { throw 'Go build failed' }
    go test ./evidence ./traffic/... -count=1 2>&1 | Tee-Object (Join-Path $output 'phase1-v1-full-tests.log')
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
    go vet ./evidence ./traffic/internal/store ./traffic/internal/service 2>&1 | Tee-Object (Join-Path $output 'phase1-v1-vet.log')
    if ($LASTEXITCODE -ne 0) { throw 'Go vet failed' }
    if ($ModelEndpoint) {
        if (-not $ModelEndpoint.StartsWith('http://127.0.0.1:')) { throw 'Model integration requires an isolated localhost proxy' }
        $env:PHASE_ONE_MODEL_ENDPOINT = $ModelEndpoint
        $env:PHASE_ONE_MODEL_OUTPUT = Join-Path $output 'phase1-v1-model.json'
        go test ./traffic/internal/service -run '^TestPhaseOneModelIsolated$' -v -count=1 -timeout 8m 2>&1 | Tee-Object (Join-Path $output 'phase1-v1-model.log')
        if ($LASTEXITCODE -ne 0) { throw 'Isolated model integration failed; inspect output and actual provider identity' }
    }
} finally {
    Pop-Location
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name,$previous[$name],'Process') }
}
