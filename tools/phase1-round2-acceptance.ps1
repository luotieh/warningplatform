param(
    [string]$ArchiveDir = (Join-Path $PSScriptRoot '../.local'),
    [string]$OutputPrefix = 'round2-coverage180'
)
$ErrorActionPreference = 'Stop'
$ArchiveDir = (Resolve-Path -LiteralPath $ArchiveDir).Path
$module = Join-Path (Split-Path -Parent $PSScriptRoot) 'vulnscan-backend'
$names = @('PHASE_ONE_COVERAGE_ARCHIVE','PHASE_ONE_COVERAGE_SUPPLEMENT','PHASE_ONE_COVERAGE_OUTPUT_PREFIX','PHASE_ONE_COVERAGE_MODEL_EVENT','PHASE_ONE_COVERAGE_EXPANDED_DIAGNOSTIC','PHASE_ONE_MODEL_ENDPOINT')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
Push-Location $module
try {
    # Offline by default, even when the caller has model variables configured.
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
    & go build ./traffic/...
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    & go test ./evidence ./traffic/... -count=1
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    & go vet ./evidence ./traffic/internal/store ./traffic/internal/service
    if ($LASTEXITCODE -ne 0) { throw 'Vet failed' }
    $env:PHASE_ONE_COVERAGE_ARCHIVE = $ArchiveDir
    $env:PHASE_ONE_COVERAGE_SUPPLEMENT = Join-Path $ArchiveDir 'round2-history-metadata.json'
    $env:PHASE_ONE_COVERAGE_OUTPUT_PREFIX = $OutputPrefix
    if (-not (Test-Path -LiteralPath $env:PHASE_ONE_COVERAGE_SUPPLEMENT)) { throw 'Frozen supplemental snapshot metadata missing' }
    & go test ./traffic/internal/service -run '^TestPhaseOneCoverageFrozenReportReplay$' -count=1 -v
    if ($LASTEXITCODE -ne 0) { throw 'Real frozen report acceptance failed' }
} finally {
    Pop-Location
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
}
