param(
    $ReleaseUrl = "https://github.com/atg-cloudops/eks-windows-bootstrapper/releases/download/v1.32.0",
    [switch]$SkipSsmConfiguration
)
Write-Host "EKS Windows Bootstrapper Installation Script Started at $(Get-Date -Format "yyyy-MM-ddTHH:mm:ss")"

#Download the bootstrapper
if(-not [string]::IsNullOrEmpty($ReleaseUrl)) {
    Invoke-WebRequest -Uri "$ReleaseUrl/EKS-Windows-Bootstrapper.exe" -OutFile "C:\EKS-Windows-Bootstrapper.exe"
    Invoke-WebRequest -Uri "$ReleaseUrl/appsettings.json" -OutFile "C:\appsettings.json"
    Invoke-WebRequest -Uri "$ReleaseUrl/Start-EKSBootstrap.ps1" -OutFile "C:\Program Files\Amazon\EKS\Start-EKSBootstrap.ps1"
    
    # Install the bootstrapper
    sc.exe create "EKSWindowsBootstrapper" binPath= "C:\EKS-Windows-Bootstrapper.exe" start= auto
}
else {
    Write-Error "ReleaseUrl is required to download the bootstrapper."
    exit 1
}

if(-not $SkipSsmConfiguration) {
    if (Get-Service AmazonSSMAgent -ErrorAction SilentlyContinue) {
        sc.exe config AmazonSSMAgent start=delayed-auto
    }
}

Write-Host "EKS Windows Bootstrapper Installation Script Completed at $(Get-Date -Format "yyyy-MM-ddTHH:mm:ss")"
 
