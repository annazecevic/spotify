# Script to run SonarQube analysis for a specific service

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("user-service", "content-service", "notifications-service", "storage-service", "subscriptions-service")]
    [string]$ServiceName,
    
    [Parameter(Mandatory=$true)]
    [string]$Token
)

$ErrorActionPreference = "Stop"

# Check if Docker is running
try {
    docker info | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not running"
    }
} catch {
    Write-Host "Error: Docker Desktop is not running!" -ForegroundColor Red
    Write-Host "Please start Docker Desktop and try again." -ForegroundColor Yellow
    exit 1
}

# Check if SonarQube is running
$sonarqubeRunning = docker ps --filter "name=sonarqube-server" --format "{{.Names}}" 2>$null
if ($sonarqubeRunning -ne "sonarqube-server") {
    Write-Host "Error: SonarQube server is not running!" -ForegroundColor Red
    Write-Host "Please start it first with: .\scripts\sonarqube-start.ps1" -ForegroundColor Yellow
    exit 1
}

# Check if SonarQube is ready
try {
    $response = Invoke-WebRequest -Uri "http://localhost:9001/api/system/status" -UseBasicParsing -TimeoutSec 5
    $status = $response.Content | ConvertFrom-Json
    if ($status.status -ne "UP") {
        Write-Host "Error: SonarQube is not ready yet. Status: $($status.status)" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Error: Cannot connect to SonarQube server at http://localhost:9001" -ForegroundColor Red
    Write-Host "Please make sure SonarQube is running and accessible." -ForegroundColor Yellow
    exit 1
}

$servicePath = "services\$ServiceName"
$projectProperties = "$servicePath\sonar-project.properties"

if (-not (Test-Path $projectProperties)) {
    Write-Host "Error: sonar-project.properties not found at $projectProperties" -ForegroundColor Red
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Running SonarQube analysis for: $ServiceName" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get the project root (parent of scripts folder) and service directory
$projectRoot = (Resolve-Path (Split-Path -Parent $PSScriptRoot)).Path
$serviceDir = Join-Path $projectRoot "services\$ServiceName"

# Docker on Windows: use forward slashes for the mount target; source can stay as Windows path
$mountTarget = "/usr/src"

$sonarHost = "http://host.docker.internal:9001"
$projectKey = "spotify-$ServiceName"
# e.g. content-service -> Content Service
$projectName = (Get-Culture).TextInfo.ToTitleCase(($ServiceName -replace '-', ' '))

# Run SonarScanner using Docker — mount only the service dir so the container definitely sees the Go files
Write-Host "Starting analysis..." -ForegroundColor Yellow
Write-Host "Connecting to SonarQube at: $sonarHost" -ForegroundColor Gray
Write-Host "Source: $serviceDir" -ForegroundColor Gray

$dockerArgs = @(
    "run", "--rm",
    "--add-host=host.docker.internal:host-gateway",
    "-v", "${serviceDir}:${mountTarget}",
    "-w", $mountTarget,
    "sonarsource/sonar-scanner-cli:latest",
    "-Dsonar.host.url=$sonarHost",
    "-Dsonar.projectKey=$projectKey",
    "-Dsonar.projectName=$projectName",
    "-Dsonar.sources=.",
    "-Dsonar.inclusions=**/*.go",
    "-Dsonar.exclusions=**/*_test.go,**/vendor/**",
    "-Dsonar.token=$Token"
)

& docker @dockerArgs

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Analysis completed successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "View results at: http://localhost:9001/dashboard?id=spotify-$ServiceName" -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "Analysis failed with exit code: $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
