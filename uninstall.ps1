#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Uninstalls the Advanced Sender Based Routing Agent from Microsoft Exchange 2019.

.DESCRIPTION
    This script:
    1. Stops the transport services
    2. Disables and removes the transport agent
    3. Optionally removes agent files
    4. Starts the transport services

    Must be run from Exchange Management Shell with Administrator privileges.

.PARAMETER RemoveFiles
    Remove agent DLL and configuration files after uninstall.

.PARAMETER KeepConfig
    Keep configuration file when removing files (only with -RemoveFiles).

.PARAMETER Force
    Skip confirmation prompts.

.EXAMPLE
    .\uninstall.ps1
    Uninstall agent with prompts.

.EXAMPLE
    .\uninstall.ps1 -RemoveFiles
    Uninstall agent and remove all files.

.EXAMPLE
    .\uninstall.ps1 -RemoveFiles -KeepConfig
    Uninstall agent, remove DLL but keep config file.
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$RemoveFiles,

    [Parameter(Mandatory=$false)]
    [switch]$KeepConfig,

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$AgentName = "Advanced Sender Based Routing Agent"

function Get-ExchangeInstallPath {
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup",
        "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup"
    )

    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            $installPath = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).MsiInstallPath
            if ($installPath) {
                return $installPath.TrimEnd('\')
            }
        }
    }

    return "C:\Program Files\Microsoft\Exchange Server\V15"
}

function Stop-AllTransportServices {
    Write-Host "[*] Stopping transport services..." -ForegroundColor Green

    $servicesToStop = @(
        'MSExchangeFrontEndTransport',
        'MSExchangeTransport',
        'MSExchangeEdgeSync',
        'MSExchangeTransportLogSearch'
    )

    foreach ($svcName in $servicesToStop) {
        $svc = Get-Service $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Host "    Stopping $svcName..." -ForegroundColor White
            Stop-Service $svcName -Force -ErrorAction SilentlyContinue
        }
    }

    # Wait for EdgeTransport.exe to fully exit
    Write-Host "    Waiting for EdgeTransport.exe to exit..." -ForegroundColor White
    $timeout = 20
    $waited = 0
    while ($waited -lt $timeout) {
        $edgeProc = Get-Process EdgeTransport -ErrorAction SilentlyContinue
        if (-not $edgeProc) {
            break
        }
        Start-Sleep -Seconds 2
        $waited += 2
    }

    # Force kill if still running
    $edgeProc = Get-Process EdgeTransport -ErrorAction SilentlyContinue
    if ($edgeProc) {
        Write-Host "    Force killing EdgeTransport.exe..." -ForegroundColor Yellow
        taskkill /F /IM EdgeTransport.exe 2>$null
        Start-Sleep -Seconds 3
    }

    Start-Sleep -Seconds 3
    Write-Host "    Services stopped" -ForegroundColor Green
}

function Start-TransportServices {
    Write-Host "[*] Starting transport services..." -ForegroundColor Green

    Write-Host "    Starting MSExchangeTransport..." -ForegroundColor White
    Start-Service MSExchangeTransport -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5

    $frontendService = Get-Service MSExchangeFrontEndTransport -ErrorAction SilentlyContinue
    if ($frontendService) {
        Write-Host "    Starting MSExchangeFrontEndTransport..." -ForegroundColor White
        Start-Service MSExchangeFrontEndTransport -ErrorAction SilentlyContinue
    }

    Write-Host "    Services started" -ForegroundColor Green
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Advanced Sender Based Routing Agent Uninstaller" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running in Exchange Management Shell
Write-Host "[*] Checking Exchange Management Shell..." -ForegroundColor Green
try {
    $null = Get-TransportAgent -ErrorAction SilentlyContinue
    Write-Host "    Exchange Management Shell: OK" -ForegroundColor White
}
catch {
    Write-Host "[X] ERROR: This script must be run from Exchange Management Shell." -ForegroundColor Red
    Write-Host ""
    Write-Host "    Please run:" -ForegroundColor Yellow
    Write-Host "    1. Open Exchange Management Shell as Administrator" -ForegroundColor White
    Write-Host "    2. Navigate to script directory" -ForegroundColor White
    Write-Host "    3. Run: .\uninstall.ps1" -ForegroundColor White
    exit 1
}

# Check if agent exists
Write-Host "[*] Checking for existing installation..." -ForegroundColor Green
$existingAgent = Get-TransportAgent -Identity $AgentName -ErrorAction SilentlyContinue

if (-not $existingAgent) {
    Write-Host "    Agent '$AgentName' is not installed." -ForegroundColor Yellow

    if ($RemoveFiles) {
        Write-Host ""
        Write-Host "[*] Checking for leftover files..." -ForegroundColor Green
        $ExchangePath = Get-ExchangeInstallPath
        $AgentPath = Join-Path $ExchangePath "TransportRoles\agents\AdvancedSenderRouting"

        if (Test-Path $AgentPath) {
            Write-Host "    Found agent directory: $AgentPath" -ForegroundColor Yellow
            if (-not $Force) {
                $response = Read-Host "Remove leftover files? (y/n)"
                if ($response -ne 'y' -and $response -ne 'Y') {
                    Write-Host "    Skipped file removal." -ForegroundColor Yellow
                    exit 0
                }
            }

            if ($KeepConfig) {
                Get-ChildItem -Path $AgentPath -Exclude "*.xml" | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                Write-Host "    Removed DLL files (kept config)" -ForegroundColor Green
            } else {
                Remove-Item -Path $AgentPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "    Removed agent directory" -ForegroundColor Green
            }
        } else {
            Write-Host "    No leftover files found" -ForegroundColor White
        }
    }
    exit 0
}

# Display current status
Write-Host ""
Write-Host "[*] Current agent status:" -ForegroundColor Green
$existingAgent | Format-Table Identity, Enabled, Priority -AutoSize

# Get agent path for file removal
$ExchangePath = Get-ExchangeInstallPath
$AgentPath = Join-Path $ExchangePath "TransportRoles\agents\AdvancedSenderRouting"

Write-Host "    Agent path: $AgentPath" -ForegroundColor White

# Confirm uninstall
if (-not $Force) {
    Write-Host ""
    $response = Read-Host "Are you sure you want to uninstall this agent? (y/n)"

    if ($response -ne 'y' -and $response -ne 'Y') {
        Write-Host "Uninstall cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Stop transport services
Write-Host ""
Stop-AllTransportServices

# Disable the agent
Write-Host ""
Write-Host "[*] Disabling transport agent..." -ForegroundColor Green
if ($existingAgent.Enabled) {
    try {
        Disable-TransportAgent -Identity $AgentName -Confirm:$false
        Write-Host "    Agent disabled" -ForegroundColor Green
    }
    catch {
        Write-Host "    WARNING: Failed to disable agent: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "    Agent already disabled" -ForegroundColor White
}

# Uninstall the agent
Write-Host ""
Write-Host "[*] Uninstalling transport agent..." -ForegroundColor Green
try {
    Uninstall-TransportAgent -Identity $AgentName -Confirm:$false
    Write-Host "    Agent uninstalled" -ForegroundColor Green
}
catch {
    Write-Host "[X] ERROR: Failed to uninstall agent: $_" -ForegroundColor Red
    Start-TransportServices
    exit 1
}

# Verify removal
$checkAgent = Get-TransportAgent -Identity $AgentName -ErrorAction SilentlyContinue
if ($checkAgent) {
    Write-Host "    WARNING: Agent may still be registered" -ForegroundColor Yellow
}
else {
    Write-Host "    Agent removal verified" -ForegroundColor Green
}

# Remove files if requested
if ($RemoveFiles) {
    Write-Host ""
    Write-Host "[*] Removing agent files..." -ForegroundColor Green

    if (Test-Path $AgentPath) {
        if ($KeepConfig) {
            # Remove everything except XML config files
            Get-ChildItem -Path $AgentPath -Exclude "*.xml" | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            Write-Host "    Removed DLL files (kept config)" -ForegroundColor Green
            Write-Host "    Config location: $AgentPath" -ForegroundColor White
        } else {
            Remove-Item -Path $AgentPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "    Removed agent directory" -ForegroundColor Green
        }
    } else {
        Write-Host "    Agent directory not found" -ForegroundColor Yellow
    }
}

# Start transport services
Write-Host ""
Start-TransportServices

# Complete
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Uninstall Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not $RemoveFiles) {
    Write-Host "Agent files were NOT removed. To remove them, run:" -ForegroundColor Yellow
    Write-Host "  .\uninstall.ps1 -RemoveFiles" -ForegroundColor White
    Write-Host ""
    Write-Host "Or to keep config:" -ForegroundColor Yellow
    Write-Host "  .\uninstall.ps1 -RemoveFiles -KeepConfig" -ForegroundColor White
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host ""
