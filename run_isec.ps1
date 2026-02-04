param(
    [switch]$SkipNpmInstall,
    [switch]$ResetDatabase
)

$ErrorActionPreference = "Stop"

# Move to the directory where this script lives (project root)
Set-Location -Path $PSScriptRoot

$uiDir = Join-Path $PSScriptRoot "ui"
if (-not (Test-Path $uiDir)) {
    Write-Error "UI directory not found: $uiDir"
    exit 1
}

# Optionally ensure Node dependencies are installed
if (-not $SkipNpmInstall) {
    if (-not (Test-Path (Join-Path $uiDir "node_modules"))) {
        Write-Host "node_modules not found in UI directory. Running 'npm install'..." -ForegroundColor Yellow
        Push-Location $uiDir
        try {
            npm install
        }
        catch {
            Write-Error "npm install failed. Ensure Node.js and npm are installed and try again. Error: $($_.Exception.Message)"
            exit 1
        }
        finally {
            Pop-Location
        }
    }
}

# Ensure evidence output directory exists (Python backend will use this path)
$evidenceDir = Join-Path $PSScriptRoot "evidence_output"
if (-not (Test-Path $evidenceDir)) {
    New-Item -ItemType Directory -Path $evidenceDir | Out-Null
}

# Optionally reset database and related encrypted state for a clean run
if ($ResetDatabase) {
    Write-Host "Resetting ISEC evidence database and local state..." -ForegroundColor Yellow
    $dbPath = Join-Path $evidenceDir "evidence.db"
    if (Test-Path $dbPath) {
        Remove-Item $dbPath -Force
    }

    $consentEnc = Join-Path $PSScriptRoot "consents.encrypted"
    if (Test-Path $consentEnc) {
        Remove-Item $consentEnc -Force
    }

    $rolesEnc = Join-Path $PSScriptRoot "user_roles.encrypted"
    if (Test-Path $rolesEnc) {
        Remove-Item $rolesEnc -Force
    }
}

# Start the Electron UI (which in turn starts the Python backend in --electron-mode)
Push-Location $uiDir
try {
    Write-Host "Starting ISEC Electron interface..." -ForegroundColor Cyan
    npm start
}
finally {
    Pop-Location
}
