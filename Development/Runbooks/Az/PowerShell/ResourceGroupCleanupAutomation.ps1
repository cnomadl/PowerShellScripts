param (
    [Parameter(mandatory = $true)]
        [ValidateNotNullOrEmpty("yes","Yes")]
        [string]$cleanupResourceGroup,

        [int]$throttleLimit = 20,
        [string]$removeUnmanagedOsdiskVhdBlob = 'No',
        [string]$showWarnings = 'Yes'
)

$ErrorActionPreference = "Stop"
$WarningPreference = @("SilentlyContinue", "Continue")[$showWarnings -eq "Yes"]
$VerbosePreference = "Continue"

. ./azLogin.ps1

try {
    $start = Get-Date
    $checkTime = Get-Date -Format F

    if ($cleanupResourceGroup -ieq "Yes") {

    }
    else {
        Write-Output "No VM resources exist with the tag 'Cleanup' enabled."
        exit
    }
}
catch {

}
