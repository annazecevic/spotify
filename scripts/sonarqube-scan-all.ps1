# Script to run SonarQube analysis for all services

param(
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

$services = @(
    "user-service",
    "content-service",
    "notifications-service",
    "storage-service",
    "subscriptions-service"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Running SonarQube analysis for all services" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$failedServices = @()

foreach ($service in $services) {
    Write-Host ""
    Write-Host "Analyzing: $service" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    
    & "$PSScriptRoot\sonarqube-scan.ps1" -ServiceName $service -Token $Token
    
    if ($LASTEXITCODE -ne 0) {
        $failedServices += $service
        Write-Host "Failed to analyze: $service" -ForegroundColor Red
    } else {
        Write-Host "Successfully analyzed: $service" -ForegroundColor Green
    }
    
    Write-Host ""
    Start-Sleep -Seconds 2  
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($failedServices.Count -eq 0) {
    Write-Host "All services analyzed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "View all results at: http://localhost:9001/projects" -ForegroundColor Cyan
} else {
    Write-Host "Failed services: $($failedServices -join ', ')" -ForegroundColor Red
    Write-Host "Successful services: $($services.Count - $failedServices.Count) / $($services.Count)" -ForegroundColor Yellow
}

Write-Host ""
