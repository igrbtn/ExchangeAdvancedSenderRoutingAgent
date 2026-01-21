<#
.SYNOPSIS
    Builds the Advanced Sender Based Routing Agent for Exchange 2019.

.DESCRIPTION
    This script builds the AdvancedSenderRouting project on Windows.
    It can automatically copy required Exchange DLLs from Exchange server or local path.

.PARAMETER ExchangeDllPath
    Path to Exchange DLLs (Microsoft.Exchange.Data.dll and Microsoft.Exchange.Data.Transport.dll).
    Defaults to Exchange 2019 installation path.

.PARAMETER Configuration
    Build configuration (Debug or Release). Defaults to Release.

.PARAMETER Clean
    Clean build output before building.

.EXAMPLE
    .\build.ps1
    Builds using default settings, looks for Exchange DLLs in default location.

.EXAMPLE
    .\build.ps1 -ExchangeDllPath "C:\ExchangeDlls"
    Builds using Exchange DLLs from specified path.

.EXAMPLE
    .\build.ps1 -Clean -Configuration Debug
    Clean build in Debug configuration.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExchangeDllPath = "",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [Parameter(Mandatory=$false)]
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
$SrcDir = Join-Path $ScriptDir "src"
$LibDir = Join-Path $SrcDir "lib"
$OutputDir = $ScriptDir

# Required Exchange DLLs
$RequiredDlls = @(
    "Microsoft.Exchange.Data.Common.dll",
    "Microsoft.Exchange.Data.Transport.dll"
)

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    Write-Host "[*] $Text" -ForegroundColor Green
}

function Write-Info {
    param([string]$Text)
    Write-Host "    $Text" -ForegroundColor White
}

function Write-Warn {
    param([string]$Text)
    Write-Host "[!] $Text" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Text)
    Write-Host "[X] $Text" -ForegroundColor Red
}

function Get-ExchangeDllPath {
    # Common Exchange installation paths
    $paths = @(
        "C:\Program Files\Microsoft\Exchange Server\V15\Public",
        "C:\Program Files\Microsoft\Exchange Server\V15\Bin",
        "${env:ExchangeInstallPath}\Public",
        "${env:ExchangeInstallPath}\Bin"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            $testDll = Join-Path $path "Microsoft.Exchange.Data.Transport.dll"
            if (Test-Path $testDll) {
                return $path
            }
        }
    }

    return $null
}

function Find-MSBuild {
    # Try to find MSBuild
    $msbuildPaths = @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\*\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2019\*\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\*\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\*\MSBuild\Current\Bin\MSBuild.exe",
        "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
        "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
    )

    foreach ($pattern in $msbuildPaths) {
        $found = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
    }

    # Try dotnet
    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($dotnet) {
        return "dotnet"
    }

    return $null
}

Write-Header "Advanced Sender Based Routing Agent Build"

# Step 1: Locate or copy Exchange DLLs
Write-Step "Checking Exchange DLLs..."

if (-not (Test-Path $LibDir)) {
    New-Item -Path $LibDir -ItemType Directory -Force | Out-Null
}

$dllsPresent = $true
foreach ($dll in $RequiredDlls) {
    $dllPath = Join-Path $LibDir $dll
    if (-not (Test-Path $dllPath)) {
        $dllsPresent = $false
        break
    }
}

if (-not $dllsPresent) {
    Write-Info "Exchange DLLs not found in lib folder"

    # Try to find Exchange DLLs
    if ([string]::IsNullOrEmpty($ExchangeDllPath)) {
        $ExchangeDllPath = Get-ExchangeDllPath
    }

    if ($ExchangeDllPath -and (Test-Path $ExchangeDllPath)) {
        Write-Info "Found Exchange DLLs at: $ExchangeDllPath"
        Write-Info "Copying DLLs to lib folder..."

        foreach ($dll in $RequiredDlls) {
            $sourceDll = Join-Path $ExchangeDllPath $dll
            $targetDll = Join-Path $LibDir $dll

            if (Test-Path $sourceDll) {
                Copy-Item -Path $sourceDll -Destination $targetDll -Force
                Write-Info "  Copied: $dll"
            }
            else {
                Write-Err "  Not found: $dll"
                $dllsPresent = $false
            }
        }
    }
    else {
        Write-Err "Exchange DLLs not found!"
        Write-Host ""
        Write-Host "Please copy the following DLLs to the 'src\lib' folder:" -ForegroundColor Yellow
        foreach ($dll in $RequiredDlls) {
            Write-Host "  - $dll" -ForegroundColor White
        }
        Write-Host ""
        Write-Host "These can be found on your Exchange server at:" -ForegroundColor Yellow
        Write-Host "  C:\Program Files\Microsoft\Exchange Server\V15\Public" -ForegroundColor White
        Write-Host ""
        Write-Host "Or specify the path:" -ForegroundColor Yellow
        Write-Host "  .\build.ps1 -ExchangeDllPath 'C:\path\to\dlls'" -ForegroundColor White
        exit 1
    }
}
else {
    Write-Info "Exchange DLLs found in lib folder"
}

# Step 2: Find build tool
Write-Step "Locating build tools..."

$buildTool = Find-MSBuild

if (-not $buildTool) {
    Write-Err "No build tool found!"
    Write-Host ""
    Write-Host "Please install one of the following:" -ForegroundColor Yellow
    Write-Host "  - Visual Studio 2019/2022 with .NET desktop development workload" -ForegroundColor White
    Write-Host "  - .NET SDK (dotnet build)" -ForegroundColor White
    Write-Host "  - .NET Framework 4.7.2 Developer Pack" -ForegroundColor White
    exit 1
}

Write-Info "Using: $buildTool"

# Step 3: Clean if requested
if ($Clean) {
    Write-Step "Cleaning previous build..."

    $binDir = Join-Path $SrcDir "bin"
    $objDir = Join-Path $SrcDir "obj"

    if (Test-Path $binDir) {
        Remove-Item -Path $binDir -Recurse -Force
        Write-Info "Removed: bin"
    }

    if (Test-Path $objDir) {
        Remove-Item -Path $objDir -Recurse -Force
        Write-Info "Removed: obj"
    }

    # Clean output files
    $outputDll = Join-Path $OutputDir "AdvancedSenderRouting.dll"
    $outputPdb = Join-Path $OutputDir "AdvancedSenderRouting.pdb"

    if (Test-Path $outputDll) { Remove-Item $outputDll -Force }
    if (Test-Path $outputPdb) { Remove-Item $outputPdb -Force }
}

# Step 4: Build
Write-Step "Building project..."

$projectFile = Join-Path $SrcDir "AdvancedSenderRouting.csproj"

if ($buildTool -eq "dotnet") {
    $buildArgs = @(
        "build",
        "`"$projectFile`"",
        "-c", $Configuration,
        "-o", "`"$OutputDir`""
    )

    Write-Info "Running: dotnet $($buildArgs -join ' ')"
    $process = Start-Process -FilePath "dotnet" -ArgumentList $buildArgs -NoNewWindow -Wait -PassThru
}
else {
    $buildArgs = @(
        "`"$projectFile`"",
        "/p:Configuration=$Configuration",
        "/p:OutputPath=`"$OutputDir`"",
        "/t:Build",
        "/v:minimal"
    )

    Write-Info "Running: MSBuild $($buildArgs -join ' ')"
    $process = Start-Process -FilePath $buildTool -ArgumentList $buildArgs -NoNewWindow -Wait -PassThru
}

if ($process.ExitCode -ne 0) {
    Write-Err "Build failed with exit code: $($process.ExitCode)"
    exit 1
}

# Step 5: Verify output
Write-Step "Verifying build output..."

$outputDll = Join-Path $OutputDir "AdvancedSenderRouting.dll"

if (Test-Path $outputDll) {
    $dllInfo = Get-Item $outputDll
    Write-Info "Built: AdvancedSenderRouting.dll ($([math]::Round($dllInfo.Length / 1KB, 2)) KB)"
}
else {
    Write-Err "Output DLL not found!"
    exit 1
}

# Step 6: List installation package contents
Write-Header "Build Complete"

Write-Host "Installation package contents:" -ForegroundColor Cyan
Write-Host ""

$packageFiles = @(
    "AdvancedSenderRouting.dll",
    "routing-config.xml",
    "install.ps1",
    "uninstall.ps1",
    "configure.ps1",
    "deploy.ps1"
)

foreach ($file in $packageFiles) {
    $filePath = Join-Path $OutputDir $file
    if (Test-Path $filePath) {
        $fileInfo = Get-Item $filePath
        $size = if ($fileInfo.Length -gt 1KB) { "$([math]::Round($fileInfo.Length / 1KB, 1)) KB" } else { "$($fileInfo.Length) B" }
        Write-Host "  [OK] $file ($size)" -ForegroundColor Green
    }
    else {
        Write-Host "  [--] $file (not found)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Copy this folder to your Exchange server" -ForegroundColor White
Write-Host "  2. Edit routing-config.xml with your routing rules" -ForegroundColor White
Write-Host "  3. Run install.ps1 from Exchange Management Shell" -ForegroundColor White
Write-Host ""
