param(
    [string]$ArchiveDir = (Join-Path $PSScriptRoot '../.local'),
    [switch]$ExpandedDiagnostic
)
$ErrorActionPreference = 'Stop'
$ArchiveDir = (Resolve-Path -LiteralPath $ArchiveDir).Path
$repo = Split-Path -Parent $PSScriptRoot
$module = Join-Path $repo 'vulnscan-backend'
$names = @('PHASE_ONE_COVERAGE_SCREEN', 'PHASE_ONE_COVERAGE_SCREEN_OUTPUT', 'PHASE_ONE_COVERAGE_ARCHIVE', 'PHASE_ONE_COVERAGE_EXPANDED_DIAGNOSTIC')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
Push-Location $module
try {
    foreach ($pair in @(@('coverage180-screen-summary.json','coverage180-f-screen.json'), @('coverage180-event-screen.json','coverage180-f-event-screen.json'))) {
        $env:PHASE_ONE_COVERAGE_SCREEN = Join-Path $ArchiveDir $pair[0]
        $env:PHASE_ONE_COVERAGE_SCREEN_OUTPUT = Join-Path $ArchiveDir $pair[1]
        if (-not (Test-Path -LiteralPath $env:PHASE_ONE_COVERAGE_SCREEN)) { throw "Frozen screen input missing: $($pair[0])" }
        & go test ./traffic/internal/service -run '^TestPhaseOneCoverageScreen$' -count=1 -v
        if ($LASTEXITCODE -ne 0) { throw 'Real candidate screen failed' }
    }
    $env:PHASE_ONE_COVERAGE_ARCHIVE = $ArchiveDir
    $env:PHASE_ONE_COVERAGE_EXPANDED_DIAGNOSTIC = if ($ExpandedDiagnostic) { '1' } else { '0' }
    & go test ./traffic/internal/service -run '^TestPhaseOneCoverage(BindingRows|FrozenReportReplay)$' -count=1 -v
    if ($LASTEXITCODE -ne 0) { throw 'Frozen report replay failed' }
} finally {
    Pop-Location
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
}
