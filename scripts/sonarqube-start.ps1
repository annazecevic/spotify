# Script to start SonarQube server

Write-Host "Starting SonarQube server..." -ForegroundColor Green

# Check if Docker is running
try {
    docker info | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not running"
    }
} catch {
    Write-Host "Error: Docker Desktop is not running!" -ForegroundColor Red
    Write-Host "Please start Docker Desktop and try again." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To start Docker Desktop:" -ForegroundColor Yellow
    Write-Host "  1. Open Docker Desktop application" -ForegroundColor Yellow
    Write-Host "  2. Wait for it to fully start (whale icon in system tray)" -ForegroundColor Yellow
    Write-Host "  3. Run this script again" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Check if SonarQube is already running
$sonarqubeRunning = docker ps --filter "name=sonarqube-server" --format "{{.Names}}" 2>$null
if ($sonarqubeRunning -eq "sonarqube-server") {
    Write-Host "SonarQube server is already running!" -ForegroundColor Yellow
    Write-Host "Access SonarQube at: http://localhost:9001" -ForegroundColor Cyan
    Write-Host "Default credentials: admin / admin" -ForegroundColor Cyan
    exit 0
}

# Start SonarQube and PostgreSQL
Write-Host "Starting SonarQube containers..." -ForegroundColor Yellow
docker-compose up -d sonarqube-db sonarqube

Write-Host "Waiting for SonarQube to be ready (this may take 1-2 minutes)..." -ForegroundColor Yellow

# Wait for SonarQube to be ready
$maxAttempts = 60
$attempt = 0
$ready = $false

while ($attempt -lt $maxAttempts -and -not $ready) {
    Start-Sleep -Seconds 5
    $attempt++
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:9001/api/system/status" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            $status = $response.Content | ConvertFrom-Json
            if ($status.status -eq "UP") {
                $ready = $true
                Write-Host "SonarQube is ready!" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "." -NoNewline -ForegroundColor Gray
    }
}

if (-not $ready) {
    Write-Host "`nSonarQube did not start in time. Please check logs with: docker logs sonarqube-server" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "SonarQube is ready!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Access SonarQube at: http://localhost:9001" -ForegroundColor Cyan
Write-Host "Default credentials: admin / admin" -ForegroundColor Cyan
Write-Host ""
Write-Host "On first login, you will be prompted to change the password." -ForegroundColor Yellow
Write-Host "After that, go to: My Account > Security > Generate Token" -ForegroundColor Yellow
Write-Host "Save the token - you'll need it to run scans." -ForegroundColor Yellow
Write-Host ""
