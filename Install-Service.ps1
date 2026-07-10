param(
    $ReleaseUrl = "https://github.com/atg-cloudops/eks-windows-bootstrapper/releases/download/v1.36.0",
    [switch]$SkipSsmConfiguration,
    [switch]$ShutdownOnCriticalFailure
)
$ErrorActionPreference = 'Stop'

function Invoke-RequiredDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [int]$MinBytes = 1
    )

    $parentDirectory = Split-Path -Parent $OutFile
    if (-not [string]::IsNullOrEmpty($parentDirectory) -and -not (Test-Path $parentDirectory)) {
        New-Item -ItemType Directory -Path $parentDirectory -Force | Out-Null
    }

    try {
        $response = Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -PassThru
        if ($response.StatusCode -ge 400) {
            throw "HTTP $($response.StatusCode) downloading $Uri"
        }
    }
    catch {
        if (Test-Path $OutFile) {
            Remove-Item $OutFile -Force
        }
        throw "Failed to download $Uri : $_"
    }

    if (-not (Test-Path $OutFile)) {
        throw "Download completed but file is missing: $OutFile"
    }

    $fileLength = (Get-Item $OutFile).Length
    if ($fileLength -lt $MinBytes) {
        Remove-Item $OutFile -Force
        throw "Downloaded file is too small ($fileLength bytes, expected at least $MinBytes): $Uri"
    }
}

function Invoke-ScCommand {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    & sc.exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage (exit code $LASTEXITCODE)"
    }
}

function Test-RequiredFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$MinBytes = 1
    )

    if (-not (Test-Path $Path)) {
        throw "Required file is missing: $Path"
    }

    $fileLength = (Get-Item $Path).Length
    if ($fileLength -lt $MinBytes) {
        throw "Required file is too small ($fileLength bytes): $Path"
    }
}

Write-Host "EKS Windows Bootstrapper Installation Script Started at $(Get-Date -Format "yyyy-MM-ddTHH:mm:ss")"

if ([string]::IsNullOrEmpty($ReleaseUrl)) {
    throw "ReleaseUrl is required to download the bootstrapper."
}

$bootstrapperExe = "C:\EKS-Windows-Bootstrapper.exe"
$appSettings = "C:\appsettings.json"
$startBootstrapScript = "C:\Program Files\Amazon\EKS\Start-EKSBootstrap.ps1"

Invoke-RequiredDownload -Uri "$ReleaseUrl/EKS-Windows-Bootstrapper.exe" -OutFile $bootstrapperExe -MinBytes 10240
$exeHeader = Get-Content -Path $bootstrapperExe -Encoding Byte -TotalCount 2
if ($exeHeader[0] -ne 0x4D -or $exeHeader[1] -ne 0x5A) {
    throw "Downloaded bootstrapper is not a valid executable: $bootstrapperExe"
}

Invoke-RequiredDownload -Uri "$ReleaseUrl/appsettings.json" -OutFile $appSettings -MinBytes 2
try {
    Get-Content $appSettings -Raw | ConvertFrom-Json | Out-Null
}
catch {
    throw "Downloaded appsettings.json is not valid JSON: $_"
}

if ($ShutdownOnCriticalFailure) {
    $config = Get-Content $appSettings -Raw | ConvertFrom-Json
    $config.ShutdownOnCriticalFailure = "true"
    $config | ConvertTo-Json -Depth 10 | Set-Content $appSettings -NoNewline
}

Invoke-RequiredDownload -Uri "$ReleaseUrl/Start-EKSBootstrap.ps1" -OutFile $startBootstrapScript -MinBytes 10

Invoke-ScCommand -Arguments @('create', 'EKSWindowsBootstrapper', 'binPath=', $bootstrapperExe, 'start=', 'auto') -FailureMessage "Failed to create EKSWindowsBootstrapper service"
Invoke-ScCommand -Arguments @('query', 'EKSWindowsBootstrapper') -FailureMessage "EKSWindowsBootstrapper service was not registered"

Test-RequiredFile -Path $bootstrapperExe -MinBytes 10240
Test-RequiredFile -Path $appSettings -MinBytes 2
Test-RequiredFile -Path $startBootstrapScript -MinBytes 10

if (-not $SkipSsmConfiguration) {
    if (Get-Service AmazonSSMAgent -ErrorAction SilentlyContinue) {
        Invoke-ScCommand -Arguments @('config', 'AmazonSSMAgent', 'start=', 'delayed-auto') -FailureMessage "Failed to configure AmazonSSMAgent service"
    }
}

Write-Host "EKS Windows Bootstrapper Installation Script Completed at $(Get-Date -Format "yyyy-MM-ddTHH:mm:ss")"
