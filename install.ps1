# boxr Universal Windows PowerShell Installer
# Fast, rootless, zero-dependency OCI container engine in Rust
#
# Usage:
#   irm https://raw.githubusercontent.com/kchaitanya863/boxr/main/install.ps1 | iex
#
# Advanced options:
#   $env:VERSION="v0.1.68"; irm https://raw.githubusercontent.com/kchaitanya863/boxr/main/install.ps1 | iex
#   $env:DRY_RUN="1"; irm https://raw.githubusercontent.com/kchaitanya863/boxr/main/install.ps1 | iex
#   $env:BOXR_INSTALL_DIR="C:\tools\boxr\bin"; irm https://raw.githubusercontent.com/kchaitanya863/boxr/main/install.ps1 | iex

[CmdletBinding()]
param (
    [string]$Version = $env:VERSION,
    [string]$InstallDir = $env:BOXR_INSTALL_DIR,
    [switch]$DryRun = ($env:DRY_RUN -eq "1" -or $env:DRY_RUN -eq "true")
)

$ErrorActionPreference = 'Stop'

Write-Host "=========================================="
Write-Host "          Installing boxr 📦             "
Write-Host "  Fast OCI Container Engine & Runtime     "
Write-Host "=========================================="

$repo = "kchaitanya863/boxr"
$artifactName = "boxr-windows-x86_64.zip"

# 1. Resolve Release Tag
$tag = $Version
if (-not $tag) {
    try {
        $headers = @{ "User-Agent" = "boxr-installer" }
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers $headers -ErrorAction Stop
        if ($release -and $release.tag_name) {
            $tag = $release.tag_name
        }
    } catch {
        # Fallback to redirect resolution
        try {
            $webReq = [System.Net.WebRequest]::Create("https://github.com/$repo/releases/latest")
            $webReq.AllowAutoRedirect = $false
            $webResp = $webReq.GetResponse()
            $location = $webResp.GetResponseHeader("Location")
            if ($location) {
                $tag = Split-Path -Leaf $location
            }
            $webResp.Close()
        } catch {
            # Ignore and fallback
        }
    }
}

if (-not $tag -or $tag -eq "latest") {
    $tag = "v0.1.68"
} elseif (-not $tag.StartsWith("v")) {
    $tag = "v$tag"
}

$downloadUrl = "https://github.com/$repo/releases/download/$tag/$artifactName"

# 2. Determine Target Installation Directory and Elevation
$isAdmin = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $isAdmin = $false
}

$scope = "User"
if ($InstallDir) {
    # Custom installation directory specified
    $scope = if ($isAdmin) { "Machine" } else { "User" }
} elseif ($isAdmin) {
    $commonAppData = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)
    if (-not $commonAppData) {
        $commonAppData = "C:\ProgramData"
    }
    $InstallDir = Join-Path $commonAppData "boxr\bin"
    $scope = "Machine"
} else {
    $userProfile = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
    $InstallDir = Join-Path $userProfile ".boxr\bin"
    $scope = "User"
}

# 3. Handle Dry Run Mode
if ($DryRun) {
    Write-Host ""
    Write-Host "--- DRY RUN MODE (No changes will be applied) ---"
    Write-Host "  Platform         : Windows (x86_64)"
    Write-Host "  Release Tag      : $tag"
    Write-Host "  Archive Name     : $artifactName"
    Write-Host "  Download URL     : $downloadUrl"
    Write-Host "  Install Location : $InstallDir\boxr.exe"
    Write-Host "  Elevation        : $(if ($isAdmin) { 'Administrator (Machine PATH)' } else { 'Standard User (User PATH)' })"
    Write-Host "  Environment Scope: $scope"
    Write-Host "------------------------------------------------"
    return
}

# 4. Create Directories
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$boxrHome = Split-Path $InstallDir -Parent
$completionsDir = Join-Path $boxrHome "completions"
if (-not (Test-Path $completionsDir)) {
    New-Item -ItemType Directory -Path $completionsDir -Force | Out-Null
}

# 5. Download and Extract Release Archive
$tempDir = [System.IO.Path]::GetTempPath()
$tempZip = Join-Path $tempDir ("boxr-windows-" + [System.Guid]::NewGuid().ToString("N") + ".zip")
$tempExtract = Join-Path $tempDir ("boxr-extract-" + [System.Guid]::NewGuid().ToString("N"))

try {
    Write-Host "Downloading $artifactName ($tag)..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing

    Write-Host "Extracting $artifactName..."
    Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force

    # Locate boxr.exe
    $exeSource = Join-Path $tempExtract "bin\boxr.exe"
    if (-not (Test-Path $exeSource)) {
        $exeSource = Join-Path $tempExtract "boxr.exe"
    }
    if (-not (Test-Path $exeSource)) {
        $found = Get-ChildItem -Path $tempExtract -Filter "boxr.exe" -Recurse | Select-Object -First 1
        if ($found) {
            $exeSource = $found.FullName
        } else {
            throw "Could not find boxr.exe inside the extracted archive."
        }
    }

    $targetExe = Join-Path $InstallDir "boxr.exe"
    Copy-Item -Path $exeSource -Destination $targetExe -Force
    Write-Host "✓ Installed boxr.exe to $targetExe"

    # Copy shell completions if present
    $extractedCompletions = Join-Path $tempExtract "completions"
    if (Test-Path $extractedCompletions) {
        Copy-Item -Path (Join-Path $extractedCompletions "*") -Destination $completionsDir -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "✓ Installed completions to $completionsDir"
    }
} finally {
    if (Test-Path $tempZip) {
        Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $tempExtract) {
        Remove-Item -Path $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 6. Add to PATH Environment Variable
try {
    $currentPath = [Environment]::GetEnvironmentVariable("Path", $scope)
    $pathParts = if ($currentPath) { $currentPath -split ';' } else { @() }
    $trimmedDir = $InstallDir.TrimEnd('\')

    $alreadyInPath = $false
    foreach ($p in $pathParts) {
        if ($p.TrimEnd('\') -ieq $trimmedDir) {
            $alreadyInPath = $true
            break
        }
    }

    if (-not $alreadyInPath) {
        $newPath = if ($currentPath) { "$currentPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
        Write-Host "✓ Added $InstallDir to $scope PATH"
    }

    # Also update current session PATH
    $sessionPaths = $env:PATH -split ';'
    $inSession = $false
    foreach ($sp in $sessionPaths) {
        if ($sp.TrimEnd('\') -ieq $trimmedDir) {
            $inSession = $true
            break
        }
    }
    if (-not $inSession) {
        $env:PATH = "$env:PATH;$InstallDir"
    }
} catch {
    Write-Warning "Could not automatically update persistent PATH: $_"
    Write-Host "Please manually add $InstallDir to your PATH."
}

# 7. Validate Installation
$exePath = Join-Path $InstallDir "boxr.exe"
Write-Host ""
Write-Host "Validating installation..."
try {
    & $exePath --version
} catch {
    Write-Warning "Installed binary check returned: $_"
}

Write-Host ""
Write-Host "=========================================="
Write-Host "      boxr installation complete! 🎉      "
Write-Host "=========================================="
Write-Host ""
Write-Host "To get started right away in this session:"
Write-Host "  `$env:Path = `"$InstallDir;`$env:Path`""
Write-Host ""
Write-Host "Verify installation:"
Write-Host "  boxr --version"
Write-Host ""
Write-Host "(Optional) Docker & Podman Drop-in Aliases:"
Write-Host "  Set-Alias -Name docker -Value boxr"
Write-Host "  Set-Alias -Name podman -Value boxr"
Write-Host ""
Write-Host "Run your first container:"
Write-Host "  boxr run hello-world"
Write-Host ""
