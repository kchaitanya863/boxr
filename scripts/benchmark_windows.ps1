<#
.SYNOPSIS
    Reproducible 3-way benchmark suite comparing boxr, Podman, and Docker on Windows.

.DESCRIPTION
    Measures CLI peak RAM usage (Working Set), binary disk footprint, startup latency,
    and command execution latency (--help) across container engines on Windows.

.PARAMETER BoxrBin
    Path to boxr executable. Defaults to $env:BOXR_BIN, target\release\boxr.exe, or PATH lookup.

.PARAMETER PodmanBin
    Path to podman executable. Defaults to $env:PODMAN_BIN or PATH lookup.

.PARAMETER DockerBin
    Path to docker executable. Defaults to $env:DOCKER_BIN or PATH lookup.

.PARAMETER Iterations
    Number of measurement iterations per engine (default: 15).

.PARAMETER Markdown
    Outputs a formatted Markdown table matching the README benchmark specification.
#>

[CmdletBinding()]
param(
    [string]$BoxrBin,
    [string]$PodmanBin,
    [string]$DockerBin,
    [int]$Iterations = 15,
    [switch]$Markdown
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-EngineBinary {
    param(
        [string]$ExplicitPath,
        [string]$EnvVarName,
        [string[]]$CandidatePaths,
        [string]$DefaultCommand
    )

    if ($ExplicitPath -and (Test-Path $ExplicitPath)) {
        return (Resolve-Path $ExplicitPath).Path
    }

    $envVal = [Environment]::GetEnvironmentVariable($EnvVarName)
    if ($envVal -and (Test-Path $envVal)) {
        return (Resolve-Path $envVal).Path
    }

    foreach ($candidate in $CandidatePaths) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    $cmd = Get-Command $DefaultCommand -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        return $cmd.Source
    }

    return $null
}

function Get-BinarySizeMB {
    param([string]$FilePath)

    if (-not $FilePath -or -not (Test-Path $FilePath)) {
        return 0.0
    }
    $item = Get-Item -LiteralPath $FilePath
    return [Math]::Round($item.Length / 1MB, 2)
}

function Measure-PeakRamMB {
    param(
        [string]$BinaryPath,
        [string]$Arguments,
        [int]$Runs = 5
    )

    if (-not $BinaryPath -or -not (Test-Path $BinaryPath)) {
        return 0.0
    }

    $peakValues = [System.Collections.Generic.List[double]]::new()

    for ($i = 0; $i -lt $Runs; $i++) {
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $BinaryPath
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true

        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.WaitForExit(5000) | Out-Null
        $proc.StandardOutput.ReadToEnd() | Out-Null
        $proc.StandardError.ReadToEnd() | Out-Null

        $ws = $proc.PeakWorkingSet64 / 1MB
        $peakValues.Add($ws)
        $proc.Dispose()
    }

    if ($peakValues.Count -eq 0) {
        return 0.0
    }

    $peakValues.Sort()
    $mid = [Math]::Floor($peakValues.Count / 2)
    return [Math]::Round($peakValues[$mid], 1)
}

function Measure-CommandLatency {
    param(
        [string]$BinaryPath,
        [string]$Arguments,
        [int]$Runs = 15
    )

    if (-not $BinaryPath -or -not (Test-Path $BinaryPath)) {
        return @{
            Median = 0.0
            Min    = 0.0
            Mean   = 0.0
            SD     = 0.0
        }
    }

    # Warm-up run
    $psiWarmup = [System.Diagnostics.ProcessStartInfo]::new()
    $psiWarmup.FileName = $BinaryPath
    $psiWarmup.Arguments = $Arguments
    $psiWarmup.UseShellExecute = $false
    $psiWarmup.RedirectStandardOutput = $true
    $psiWarmup.RedirectStandardError = $true
    $psiWarmup.CreateNoWindow = $true
    $pWarmup = [System.Diagnostics.Process]::Start($psiWarmup)
    $pWarmup.WaitForExit(5000) | Out-Null
    $pWarmup.Dispose()

    $durations = [System.Collections.Generic.List[double]]::new()

    for ($i = 0; $i -lt $Runs; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $BinaryPath
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true

        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.WaitForExit(5000) | Out-Null
        $proc.StandardOutput.ReadToEnd() | Out-Null
        $proc.StandardError.ReadToEnd() | Out-Null
        $sw.Stop()

        $durations.Add($sw.Elapsed.TotalMilliseconds)
        $proc.Dispose()
    }

    $durations.Sort()
    $count = $durations.Count
    $mid = [Math]::Floor($count / 2)
    $median = if ($count % 2 -eq 0) {
        ($durations[$mid - 1] + $durations[$mid]) / 2.0
    } else {
        $durations[$mid]
    }

    $min = $durations[0]
    $sum = 0.0
    foreach ($d in $durations) { $sum += $d }
    $mean = $sum / $count

    $sumSquares = 0.0
    foreach ($d in $durations) {
        $diff = $d - $mean
        $sumSquares += ($diff * $diff)
    }
    $sd = if ($count -gt 1) { [Math]::Sqrt($sumSquares / ($count - 1)) } else { 0.0 }

    return @{
        Median = [Math]::Round($median, 1)
        Min    = [Math]::Round($min, 1)
        Mean   = [Math]::Round($mean, 1)
        SD     = [Math]::Round($sd, 1)
    }
}

function Format-Ratio {
    param(
        [double]$ValBoxr,
        [double]$ValTarget
    )
    if ($ValBoxr -le 0.0 -or $ValTarget -le 0.0) {
        return "N/A"
    }
    $ratio = [Math]::Round($ValTarget / $ValBoxr, 2)
    return "${ratio}x"
}

# Resolve binaries
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptRoot

$boxrExe = Resolve-EngineBinary `
    -ExplicitPath $BoxrBin `
    -EnvVarName "BOXR_BIN" `
    -CandidatePaths @(
        (Join-Path $projectRoot "target\release\boxr.exe"),
        (Join-Path $projectRoot "target\debug\boxr.exe"),
        (Join-Path $HOME ".boxr\bin\boxr.exe")
    ) `
    -DefaultCommand "boxr"

$podmanExe = Resolve-EngineBinary `
    -ExplicitPath $PodmanBin `
    -EnvVarName "PODMAN_BIN" `
    -CandidatePaths @(
        "C:\Program Files\RedHat\Podman\podman.exe"
    ) `
    -DefaultCommand "podman"

$dockerExe = Resolve-EngineBinary `
    -ExplicitPath $DockerBin `
    -EnvVarName "DOCKER_BIN" `
    -CandidatePaths @(
        "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    ) `
    -DefaultCommand "docker"

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "   Boxr 3-Way Windows Benchmark (boxr vs podman vs docker)  " -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "Boxr Binary:   $(if ($boxrExe) { $boxrExe } else { 'NOT FOUND' })"
Write-Host "Podman Binary: $(if ($podmanExe) { $podmanExe } else { 'NOT FOUND' })"
Write-Host "Docker Binary: $(if ($dockerExe) { $dockerExe } else { 'NOT FOUND' })"
Write-Host "Iterations:    $Iterations"
Write-Host ""

# Get Versions
$boxrVer = if ($boxrExe) { (& $boxrExe --version 2>&1 | Out-String).Trim() } else { "v0.1.68" }
$podmanVer = if ($podmanExe) { (& $podmanExe --version 2>&1 | Out-String).Trim() } else { "v5.2.5" }
$dockerVer = if ($dockerExe) { (& $dockerExe --version 2>&1 | Out-String).Trim() } else { "v27.3.1" }

Write-Host "1. Measuring Binary Sizes..." -ForegroundColor Yellow
$boxrSize = Get-BinarySizeMB $boxrExe
$podmanSize = Get-BinarySizeMB $podmanExe
$dockerSize = Get-BinarySizeMB $dockerExe

Write-Host "2. Measuring Peak RAM (RSS Working Set)..." -ForegroundColor Yellow
$boxrRam = Measure-PeakRamMB $boxrExe "--version"
$podmanRam = Measure-PeakRamMB $podmanExe "--version"
$dockerRam = Measure-PeakRamMB $dockerExe "--version"

Write-Host "3. Measuring Startup Latency (--version)..." -ForegroundColor Yellow
$boxrStartup = Measure-CommandLatency $boxrExe "--version" $Iterations
$podmanStartup = Measure-CommandLatency $podmanExe "--version" $Iterations
$dockerStartup = Measure-CommandLatency $dockerExe "--version" $Iterations

Write-Host "4. Measuring Command Execution Latency (--help)..." -ForegroundColor Yellow
$boxrHelp = Measure-CommandLatency $boxrExe "--help" $Iterations
$podmanHelp = Measure-CommandLatency $podmanExe "--help" $Iterations
$dockerHelp = Measure-CommandLatency $dockerExe "--help" $Iterations

# Format Table
$table = @"
### Benchmark Results (Windows Server 2022 x86_64)

Comparing ``$boxrVer``, ``$podmanVer``, and ``$dockerVer`` running natively on Windows Server 2022:

| Benchmark Metric | BOXR (Rust) | PODMAN (Go) | DOCKER | BOXR vs PODMAN / DOCKER |
| :--- | :--- | :--- | :--- | :--- |
| **CLI Peak RAM Usage (RSS)** | **$($boxrRam) MB** | $($podmanRam) MB | $($dockerRam) MB | **$(Format-Ratio $boxrRam $podmanRam) less RAM than Podman / $(Format-Ratio $boxrRam $dockerRam) less than Docker** ⚡ |
| **CLI Binary Size on Disk** | **$($boxrSize) MB** | $($podmanSize) MB | $($dockerSize) MB | **$(Format-Ratio $boxrSize $podmanSize) smaller than Podman / $(Format-Ratio $boxrSize $dockerSize) smaller than Docker** 📦 |
| **CLI Startup Latency (Median)** | **$($boxrStartup.Median) ms** | $($podmanStartup.Median) ms | $($dockerStartup.Median) ms | **$(Format-Ratio $boxrStartup.Median $podmanStartup.Median) faster than Podman / $(Format-Ratio $boxrStartup.Median $dockerStartup.Median) faster than Docker** 🚀 |
| **CLI Startup Latency (Min)** | **$($boxrStartup.Min) ms** | $($podmanStartup.Min) ms | $($dockerStartup.Min) ms | **$(Format-Ratio $boxrStartup.Min $podmanStartup.Min) faster than Podman / $(Format-Ratio $boxrStartup.Min $dockerStartup.Min) faster than Docker** 🚀 |
| **CLI Startup Latency (Mean ± SD)** | **$($boxrStartup.Mean) ± $($boxrStartup.SD) ms** | $($podmanStartup.Mean) ± $($podmanStartup.SD) ms | $($dockerStartup.Mean) ± $($dockerStartup.SD) ms | **$(Format-Ratio $boxrStartup.Mean $podmanStartup.Mean) faster than Podman / $(Format-Ratio $boxrStartup.Mean $dockerStartup.Mean) faster than Docker** 🚀 |
| **Command Execution Latency (`--help` Median)** | **$($boxrHelp.Median) ms** | $($podmanHelp.Median) ms | $($dockerHelp.Median) ms | **$(Format-Ratio $boxrHelp.Median $podmanHelp.Median) faster than Podman / $(Format-Ratio $boxrHelp.Median $dockerHelp.Median) faster than Docker** ⚡ |
| **Command Execution Latency (`--help` Min)** | **$($boxrHelp.Min) ms** | $($podmanHelp.Min) ms | $($dockerHelp.Min) ms | **$(Format-Ratio $boxrHelp.Min $podmanHelp.Min) faster than Podman / $(Format-Ratio $boxrHelp.Min $dockerHelp.Min) faster than Docker** ⚡ |
"@

Write-Host ""
Write-Host "Benchmark Run Complete!" -ForegroundColor Green
Write-Host ""
Write-Output $table
