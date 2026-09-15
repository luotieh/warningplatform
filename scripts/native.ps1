#Requires -Version 7.0
param(
    [ValidateSet('InstallFrontend', 'BuildFrontend', 'BuildBackend', 'Start', 'Stop', 'Status', 'Preview', 'StopPreview')]
    [string]$Action = 'Status'
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$localDir = Join-Path $repo '.local'
$logs = Join-Path $localDir 'logs'
$frontend = Join-Path $repo 'vulnscan-frontend'
$backend = Join-Path $repo 'vulnscan-backend'
$node = Join-Path $localDir 'tools/node/node.exe'
$pnpm = Join-Path $localDir 'tools/pnpm/bin/pnpm.cjs'
$go = Join-Path $localDir 'tools/go/bin/go.exe'
$server = Join-Path $localDir 'bin/manage-platform.exe'
New-Item -ItemType Directory -Force $logs | Out-Null
$env:PATH = "$(Split-Path $node);$(Join-Path $localDir 'tools/bin');$(Split-Path $go);$env:PATH"

function Invoke-Pnpm([string[]]$Arguments) {
    if (!(Test-Path $node) -or !(Test-Path $pnpm)) { throw 'Local Node.js 22 and pnpm 10.28.2 are required in .local/tools.' }
    Push-Location $frontend
    try {
        & $node $pnpm @Arguments
        if ($LASTEXITCODE -ne 0) { throw "pnpm failed with exit code $LASTEXITCODE" }
    } finally { Pop-Location }
}

function Get-ManagedProcess([string]$Name) {
    $state = Join-Path $localDir "$Name.json"
    if (!(Test-Path $state)) { return $null }
    $saved = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json
    $process = Get-Process -Id $saved.ProcessId -ErrorAction SilentlyContinue
    if ($process -and $process.StartTime.ToUniversalTime().Ticks.ToString() -eq $saved.StartTicks -and $process.Path -eq $saved.Executable) { return $process }
    return $null
}

function Stop-Managed([string]$Name) {
    $process = Get-ManagedProcess $Name
    if ($process) { Stop-Process -Id $process.Id; $process.WaitForExit(10000) | Out-Null }
    $state = Join-Path $localDir "$Name.json"
    if (Test-Path $state) { Remove-Item -LiteralPath $state }
    Write-Host "$Name stopped."
}

function Start-Managed([string]$Name, [string]$Executable, [string[]]$Arguments, [string]$Directory, [int]$Port, [string]$HealthPath) {
    if (Get-ManagedProcess $Name) { Write-Host "$Name is already running at http://127.0.0.1:$Port"; return }
    if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { throw "Port $Port is already occupied." }
    $params = @{
        FilePath = $Executable; WorkingDirectory = $Directory; WindowStyle = 'Hidden'; PassThru = $true
        RedirectStandardOutput = (Join-Path $logs "$Name.out.log")
        RedirectStandardError = (Join-Path $logs "$Name.err.log")
    }
    if ($Arguments.Count) { $params.ArgumentList = $Arguments }
    $process = Start-Process @params
    try {
        $process.Refresh()
        @{
            ProcessId = $process.Id
            StartTicks = $process.StartTime.ToUniversalTime().Ticks.ToString()
            Executable = $process.Path
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $localDir "$Name.json") -Encoding utf8
        for ($attempt = 0; $attempt -lt 60; $attempt++) {
            if ($process.HasExited) { throw "$Name exited. See .local/logs/$Name.err.log and $Name.out.log." }
            try {
                $response = Invoke-WebRequest "http://127.0.0.1:$Port$HealthPath" -UseBasicParsing -TimeoutSec 2 -NoProxy
                if ($response.StatusCode -eq 200) { Write-Host "$Name is running at http://127.0.0.1:$Port"; return }
            } catch { }
            Start-Sleep -Seconds 1
        }
        throw "$Name did not become ready. See .local/logs."
    } catch {
        Stop-Managed $Name
        throw
    }
}

switch ($Action) {
    'InstallFrontend' { Invoke-Pnpm @('install', '--frozen-lockfile') }
    'BuildFrontend' { Invoke-Pnpm @('run', 'build:prod') }
    'BuildBackend' {
        if (!(Test-Path $go)) { throw 'Go 1.26.3 is required in .local/tools/go.' }
        if (!(Test-Path (Join-Path $backend 'frontend/dist/index.html'))) { throw 'Run BuildFrontend first.' }
        $env:GOPRIVATE = (@($env:GOPRIVATE, 'code.yt-security.com') | Where-Object { $_ }) -join ','
        New-Item -ItemType Directory -Force (Split-Path $server) | Out-Null
        Push-Location $backend
        try {
            & $go mod download
            if ($LASTEXITCODE -ne 0) { throw 'Go dependency download failed. Check private dependency access.' }
            & $go run github.com/google/wire/cmd/wire@v0.7.0 ./di
            if ($LASTEXITCODE -ne 0) { throw 'Wire generation failed.' }
            & $go build -trimpath -o $server ./cmd/server
            if ($LASTEXITCODE -ne 0) { throw 'Backend build failed.' }
        } finally { Pop-Location }
    }
    'Start' {
        if (!(Test-Path $server)) { throw 'Run BuildBackend first.' }
        $config = Join-Path $backend 'config.toml'
        if (!(Test-Path $config)) { throw 'Copy scripts/local.config.example.toml to vulnscan-backend/config.toml and configure MySQL/IAM.' }
        if ((Get-Content $config -Raw).Contains('REPLACE_ME')) { throw 'Complete the local MySQL and IAM configuration first.' }
        Start-Managed 'backend' $server @() $backend 8090 '/health/ready'
    }
    'Stop' { Stop-Managed 'backend' }
    'Preview' {
        if (!(Test-Path (Join-Path $backend 'frontend/dist/index.html'))) { throw 'Run BuildFrontend first.' }
        # Vite preview serves the built frontend only. Backend APIs still require port 8090.
        $vite = Join-Path $frontend 'node_modules/vite/bin/vite.js'
        Start-Managed 'preview' $node @(('"' + $vite + '"'), 'preview', '--host', '127.0.0.1', '--port', '5889', '--strictPort') (Join-Path $frontend 'apps/web') 5889 '/'
    }
    'StopPreview' { Stop-Managed 'preview' }
    'Status' {
        foreach ($name in @('backend', 'preview')) {
            $process = Get-ManagedProcess $name
            if ($process) { Write-Host "$name running (PID $($process.Id))" } else { Write-Host "$name stopped" }
        }
    }
}
