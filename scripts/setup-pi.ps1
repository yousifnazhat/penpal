param(
    [switch]$ForceInstall
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
$PiVersion = (Get-Content "$RootDir/.pi-version" -Raw).Trim()
$PiPackage = if ($env:PI_PACKAGE) { $env:PI_PACKAGE } else { "@earendil-works/pi-coding-agent@$PiVersion" }
$AllowVersionMismatch = $false

function Test-PenPalPython($Command) {
    & $Command -c 'import sys; raise SystemExit(0 if (3, 11) <= sys.version_info[:2] < (3, 14) else 1)' 2>$null
    return $LASTEXITCODE -eq 0
}

if ($env:PENPAL_PYTHON) {
    if (-not (Get-Command $env:PENPAL_PYTHON -ErrorAction SilentlyContinue) -or -not (Test-PenPalPython $env:PENPAL_PYTHON)) {
        throw "PENPAL_PYTHON must name Python 3.11, 3.12, or 3.13."
    }
} else {
    foreach ($Candidate in @("python3.13", "python3.12", "python3.11", "python3", "python")) {
        if ((Get-Command $Candidate -ErrorAction SilentlyContinue) -and (Test-PenPalPython $Candidate)) {
            $env:PENPAL_PYTHON = $Candidate
            break
        }
    }
    if (-not $env:PENPAL_PYTHON) {
        throw "Python 3.11, 3.12, or 3.13 is required."
    }
}
Write-Host "PenPal Python: $env:PENPAL_PYTHON ($(& $env:PENPAL_PYTHON --version))"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js is required for PI. Install Node.js, then rerun scripts/setup-pi.ps1."
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "npm is required for PI. Install npm, then rerun scripts/setup-pi.ps1."
}

& node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit(major > 22 || (major === 22 && minor >= 19) ? 0 : 1)'
if ($LASTEXITCODE -ne 0) {
    throw "PI $PiVersion requires Node.js 22.19.0 or newer; found $(& node --version)."
}

function Install-Pi {
    Write-Host "Installing tested PI: $PiPackage"
    & npm.cmd install --global --ignore-scripts $PiPackage
    if ($LASTEXITCODE -ne 0) {
        throw "PI installation failed."
    }
}

$PiCommand = Get-Command pi -ErrorAction SilentlyContinue
if ($PiCommand) {
    $InstalledVersion = (& pi --version).Trim()
    if ($InstalledVersion -eq $PiVersion) {
        Write-Host "PI already installed at tested version: $InstalledVersion"
    } elseif ($ForceInstall -or $env:PI_FORCE_INSTALL -eq "1") {
        Write-Host "Replacing PI $InstalledVersion with tested version $PiVersion."
        Install-Pi
    } else {
        Write-Host "PI $InstalledVersion is installed; PenPal is pinned and tested with $PiVersion."
        Write-Host "Keeping the installed version and running the compatibility smoke. Use -ForceInstall to replace it."
        $AllowVersionMismatch = $true
    }
} else {
    Install-Pi
}

if ($AllowVersionMismatch) {
    $env:PI_ALLOW_VERSION_MISMATCH = "1"
}
& node "$RootDir/scripts/check-pi.mjs"
if ($LASTEXITCODE -ne 0) {
    throw "PI compatibility smoke failed."
}

Write-Host ""
Write-Host "Next:"
Write-Host "  pi"
Write-Host "  /login"
Write-Host "  /penpal-status"
Write-Host ""
Write-Host "Approve project-local files if PI asks, then run /login if a provider is not configured."
