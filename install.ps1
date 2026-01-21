#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Advanced Sender Based Routing Agent on Microsoft Exchange 2019.

.DESCRIPTION
    This script:
    1. Stops the transport services
    2. Removes existing installation if present
    3. Copies agent files to Exchange transport agents directory
    4. Installs and enables the transport agent
    5. Starts the transport services
    6. Optionally launches the configuration manager

    Must be run from Exchange Management Shell with Administrator privileges.

.PARAMETER SkipConfig
    Skip launching configuration manager after install.

.PARAMETER KeepConfig
    Keep existing configuration file (don't overwrite).

.EXAMPLE
    .\install.ps1
    Full installation with automatic reinstall if needed.

.EXAMPLE
    .\install.ps1 -KeepConfig
    Install/reinstall but keep existing configuration.
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipConfig,

    [Parameter(Mandatory=$false)]
    [switch]$KeepConfig
)

$ErrorActionPreference = "Stop"

$AgentName = "Advanced Sender Based Routing Agent"
$AgentFactory = "AdvancedSenderRouting.AdvancedSenderRoutingAgentFactory"
$DllName = "AdvancedSenderRouting.dll"
$ConfigName = "routing-config.xml"
$SourcePath = $PSScriptRoot

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
    Write-Host "[*] Stopping ALL transport-related services..." -ForegroundColor Green
    Write-Host "    This will temporarily stop mail flow" -ForegroundColor Yellow

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

    # Wait for EdgeTransport.exe to fully exit (graceful)
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
        Write-Host "    Waiting... ($waited s)" -ForegroundColor Yellow
    }

    # Force kill if still running
    $edgeProc = Get-Process EdgeTransport -ErrorAction SilentlyContinue
    if ($edgeProc) {
        Write-Host "    Force killing EdgeTransport.exe..." -ForegroundColor Yellow
        taskkill /F /IM EdgeTransport.exe 2>$null
        Start-Sleep -Seconds 3
    }

    # Also kill any MSExchangeTransport worker processes
    $workerProcs = Get-Process | Where-Object { $_.ProcessName -like "*Exchange*Transport*" } -ErrorAction SilentlyContinue
    if ($workerProcs) {
        foreach ($proc in $workerProcs) {
            Write-Host "    Killing $($proc.ProcessName) (PID: $($proc.Id))..." -ForegroundColor Yellow
            try { $proc.Kill() } catch {}
        }
        Start-Sleep -Seconds 2
    }

    # Extra wait for file handles to release
    Write-Host "    Waiting for file handles to release..." -ForegroundColor White
    Start-Sleep -Seconds 5
    Write-Host "    Services stopped" -ForegroundColor Green
}

function Start-TransportServices {
    Write-Host "[*] Starting transport services..." -ForegroundColor Green

    # Start main Transport service
    Write-Host "    Starting MSExchangeTransport..." -ForegroundColor White
    Start-Service MSExchangeTransport -ErrorAction SilentlyContinue

    # Wait for it to start
    Start-Sleep -Seconds 5

    # Start Frontend Transport
    $frontendService = Get-Service MSExchangeFrontEndTransport -ErrorAction SilentlyContinue
    if ($frontendService) {
        Write-Host "    Starting MSExchangeFrontEndTransport..." -ForegroundColor White
        Start-Service MSExchangeFrontEndTransport -ErrorAction SilentlyContinue
    }

    Write-Host "    Services started" -ForegroundColor Green
}

function Copy-FileWithRetry {
    param(
        [string]$Source,
        [string]$Destination,
        [int]$MaxRetries = 10,
        [int]$RetryDelaySeconds = 2
    )

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            # If destination exists, try multiple approaches
            if (Test-Path $Destination) {
                $removed = $false

                # Approach 1: Try .NET File.Delete (sometimes works when PS fails)
                try {
                    [System.IO.File]::Delete($Destination)
                    $removed = $true
                    Write-Host "    Deleted old file (.NET)" -ForegroundColor Gray
                }
                catch {
                    # Approach 2: Try rename
                    try {
                        $backupName = $Destination + ".old." + (Get-Date -Format "yyyyMMddHHmmss")
                        [System.IO.File]::Move($Destination, $backupName)
                        $removed = $true
                        Write-Host "    Renamed old file (.NET)" -ForegroundColor Gray
                    }
                    catch {
                        # Approach 3: Use cmd.exe del
                        try {
                            $result = cmd /c "del /f /q `"$Destination`" 2>&1"
                            if (-not (Test-Path $Destination)) {
                                $removed = $true
                                Write-Host "    Deleted old file (cmd)" -ForegroundColor Gray
                            }
                        }
                        catch {}
                    }
                }

                if (-not $removed -and (Test-Path $Destination)) {
                    throw "Could not remove existing file"
                }
            }

            # Copy using .NET (sometimes bypasses PS issues)
            [System.IO.File]::Copy($Source, $Destination, $true)
            return $true
        }
        catch {
            if ($i -eq $MaxRetries) {
                Write-Host "[X] ERROR: Failed after $MaxRetries attempts: $_" -ForegroundColor Red

                # Show what might be locking the file
                Write-Host ""
                Write-Host "    Checking for locking processes..." -ForegroundColor Yellow
                try {
                    $procs = Get-Process | Where-Object { $_.Modules.FileName -like "*AdvancedSenderRouting*" } -ErrorAction SilentlyContinue
                    if ($procs) {
                        Write-Host "    Processes using the DLL:" -ForegroundColor Red
                        $procs | ForEach-Object { Write-Host "      - $($_.ProcessName) (PID: $($_.Id))" -ForegroundColor Red }
                    }
                    else {
                        Write-Host "    No processes found with DLL loaded" -ForegroundColor Gray
                        Write-Host "    File may be locked by antivirus or Windows" -ForegroundColor Yellow
                    }
                }
                catch {}

                return $false
            }
            Write-Host "    Retry $i/$MaxRetries - file locked, waiting $RetryDelaySeconds sec..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
    return $false
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host " Advanced Sender Based Routing Agent Installer" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
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
    Write-Host "    2. Navigate to: $SourcePath" -ForegroundColor White
    Write-Host "    3. Run: .\install.ps1" -ForegroundColor White
    exit 1
}

# Verify source files exist
Write-Host "[*] Checking source files..." -ForegroundColor Green
$SourceDll = Join-Path $SourcePath $DllName
$SourceConfig = Join-Path $SourcePath $ConfigName

if (-not (Test-Path $SourceDll)) {
    Write-Host "[X] ERROR: Agent DLL not found at: $SourceDll" -ForegroundColor Red
    Write-Host "    Please run build.ps1 first." -ForegroundColor Yellow
    exit 1
}
Write-Host "    DLL: OK" -ForegroundColor White

if (-not (Test-Path $SourceConfig)) {
    Write-Host "[!] WARNING: Config not found at: $SourceConfig" -ForegroundColor Yellow
}
else {
    Write-Host "    Config: OK" -ForegroundColor White
}

# Get Exchange install path and set target directory
$ExchangePath = Get-ExchangeInstallPath
$TargetPath = Join-Path $ExchangePath "TransportRoles\agents\AdvancedSenderRouting"
$TargetDll = Join-Path $TargetPath $DllName
$TargetConfig = Join-Path $TargetPath $ConfigName

Write-Host ""
Write-Host "[*] Installation paths:" -ForegroundColor Green
Write-Host "    Source: $SourcePath" -ForegroundColor White
Write-Host "    Target: $TargetPath" -ForegroundColor White

# Check for existing installation
Write-Host ""
Write-Host "[*] Checking for existing installation..." -ForegroundColor Green
$existingAgent = Get-TransportAgent -Identity $AgentName -ErrorAction SilentlyContinue
$needsUninstall = $false

if ($existingAgent) {
    Write-Host "    Found existing installation" -ForegroundColor Yellow
    Write-Host "    Enabled: $($existingAgent.Enabled)" -ForegroundColor White
    $needsUninstall = $true
}
else {
    Write-Host "    No existing installation found" -ForegroundColor White
}

# Stop transport services
Write-Host ""
Stop-AllTransportServices

# Uninstall existing agent if present
if ($needsUninstall) {
    Write-Host ""
    Write-Host "[*] Removing existing installation..." -ForegroundColor Green

    # Disable if enabled
    if ($existingAgent.Enabled) {
        Write-Host "    Disabling agent..." -ForegroundColor Yellow
        Disable-TransportAgent -Identity $AgentName -Confirm:$false
        Write-Host "    Agent disabled" -ForegroundColor Green
    }

    # Uninstall
    Write-Host "    Uninstalling agent..." -ForegroundColor Yellow
    Uninstall-TransportAgent -Identity $AgentName -Confirm:$false
    Write-Host "    Agent uninstalled" -ForegroundColor Green

    # Wait a bit for unload
    Start-Sleep -Seconds 3
}

# Copy files to Exchange directory
Write-Host ""
Write-Host "[*] Copying files to Exchange directory..." -ForegroundColor Green

# Create target directory if needed
if (-not (Test-Path $TargetPath)) {
    New-Item -Path $TargetPath -ItemType Directory -Force | Out-Null
    Write-Host "    Created: $TargetPath" -ForegroundColor White
}

# Copy DLL with retry
$copySuccess = Copy-FileWithRetry -Source $SourceDll -Destination $TargetDll

if (-not $copySuccess) {
    Write-Host ""
    Write-Host "[!] Standard copy failed. Trying versioned DLL workaround..." -ForegroundColor Yellow

    # Use versioned filename as fallback
    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $versionedDllName = "AdvancedSenderRouting.$timestamp.dll"
    $TargetDll = Join-Path $TargetPath $versionedDllName

    try {
        [System.IO.File]::Copy($SourceDll, $TargetDll, $true)
        Write-Host "    Copied to versioned filename: $versionedDllName" -ForegroundColor Green
        $copySuccess = $true
    }
    catch {
        Write-Host "[X] ERROR: Even versioned copy failed: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "[!] MANUAL WORKAROUND:" -ForegroundColor Yellow
        Write-Host "    1. Reboot the server" -ForegroundColor White
        Write-Host "    2. Run install.ps1 again immediately after boot" -ForegroundColor White
        Write-Host ""
        Start-TransportServices
        exit 1
    }
}
else {
    Write-Host "    Copied: $DllName" -ForegroundColor White
}

# Copy config
if (Test-Path $SourceConfig) {
    if ($KeepConfig -and (Test-Path $TargetConfig)) {
        Write-Host "    Preserved existing config (-KeepConfig)" -ForegroundColor Yellow
    }
    else {
        Copy-Item -Path $SourceConfig -Destination $TargetConfig -Force
        Write-Host "    Copied: $ConfigName" -ForegroundColor White
    }
}

# Clean up old DLL backups
$oldFiles = Get-ChildItem -Path $TargetPath -Filter "*.dll.old.*" -ErrorAction SilentlyContinue
if ($oldFiles) {
    Write-Host "    Cleaning up old files..." -ForegroundColor Gray
    $oldFiles | Remove-Item -Force -ErrorAction SilentlyContinue
}

# Install the agent
Write-Host ""
Write-Host "[*] Installing transport agent..." -ForegroundColor Green
Write-Host "    Name: $AgentName" -ForegroundColor White
Write-Host "    Factory: $AgentFactory" -ForegroundColor White
Write-Host "    Assembly: $TargetDll" -ForegroundColor White

try {
    Install-TransportAgent -Name $AgentName `
                           -TransportAgentFactory $AgentFactory `
                           -AssemblyPath $TargetDll

    Write-Host "    Agent installed" -ForegroundColor Green
}
catch {
    Write-Host "[X] ERROR: Failed to install agent: $_" -ForegroundColor Red
    Start-TransportServices
    exit 1
}

# Enable the agent
Write-Host ""
Write-Host "[*] Enabling transport agent..." -ForegroundColor Green
try {
    Enable-TransportAgent -Identity $AgentName
    Write-Host "    Agent enabled" -ForegroundColor Green
}
catch {
    Write-Host "[X] ERROR: Failed to enable agent: $_" -ForegroundColor Red
    Start-TransportServices
    exit 1
}

# Set priority
Write-Host ""
Write-Host "[*] Setting agent priority..." -ForegroundColor Green
try {
    Set-TransportAgent -Identity $AgentName -Priority 1
    Write-Host "    Priority set to 1" -ForegroundColor Green
}
catch {
    Write-Host "[!] WARNING: Could not set priority: $_" -ForegroundColor Yellow
}

# Display status
Write-Host ""
Write-Host "[*] Agent status:" -ForegroundColor Green
Get-TransportAgent | Where-Object { $_.Identity -eq $AgentName } | Format-Table Identity, Enabled, Priority -AutoSize

# Start transport services
Write-Host ""
Start-TransportServices

# Installation complete
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Installation Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration file: $TargetConfig" -ForegroundColor White
Write-Host ""

# Launch configuration manager
if (-not $SkipConfig) {
    $response = Read-Host "Launch configuration manager? (y/n)"

    if ($response -eq 'y' -or $response -eq 'Y') {
        $configScript = Join-Path $SourcePath "configure.ps1"
        if (Test-Path $configScript) {
            Write-Host ""
            & $configScript -ConfigPath $TargetConfig
        }
        else {
            Write-Host "[!] configure.ps1 not found" -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "Done! Check Event Viewer for 'AdvancedSenderRouting' logs after sending test email." -ForegroundColor Green
Write-Host ""
