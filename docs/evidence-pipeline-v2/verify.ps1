param([switch]$ReplayArchive,[switch]$Race)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$backend = Join-Path $repo 'vulnscan-backend'
function Run-Go([string[]]$GoArgs) {
 & go @GoArgs
 if ($LASTEXITCODE -ne 0) {throw "go $GoArgs failed: $LASTEXITCODE"}
}
Push-Location $backend
try {
 Run-Go -GoArgs @('build','./...')
 Run-Go -GoArgs @('test','./evidence','./traffic/...','-count=1')
 Run-Go -GoArgs @('vet','./evidence','./traffic/...')
 if ($Race) {Run-Go -GoArgs @('test','-race','./evidence','./traffic/internal/service','-run','TestSemanticPipeline|TestEvidencePipeline','-count=1')}
 if ($ReplayArchive) {
  $archive=Join-Path $repo '.local'
  $supplement=Join-Path $archive 'round2-history-metadata.json'
  if (!(Test-Path -LiteralPath $supplement)) {throw 'Required frozen archive metadata is missing; do not count skipped replay as passed.'}
  $keys=@('PHASE_ONE_COVERAGE_ARCHIVE','PHASE_ONE_COVERAGE_SUPPLEMENT','PHASE_ONE_COVERAGE_OUTPUT_PREFIX')
  $saved=@{}
  foreach($key in $keys){$saved[$key]=[Environment]::GetEnvironmentVariable($key,'Process')}
  try {
   $env:PHASE_ONE_COVERAGE_ARCHIVE=$archive
   $env:PHASE_ONE_COVERAGE_SUPPLEMENT=$supplement
   $env:PHASE_ONE_COVERAGE_OUTPUT_PREFIX='pipeline-v2-coverage180'
   Run-Go -GoArgs @('test','./traffic/internal/service','-run','^TestPhaseOneCoverageFrozenReportReplay$','-count=1','-v')
  } finally {foreach($key in $keys){[Environment]::SetEnvironmentVariable($key,$saved[$key],'Process')}}
 }
} finally {Pop-Location}
