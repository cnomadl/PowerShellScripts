##############################################
# Script to configure lab client environment #
# Author: Chris Langford                     #
# Version: 2.4.1                             #
##############################################

# Install the new C&G Software Verison

### Create temporary download folders
Write-Output "Step 1:"
Write-Output "Creating a temporary working directory for and downloading the City and Guilds Secure Assess Client"
New-Item C:\PSDownloads -ItemType Directory -Force

#### Download and install City & Guild SecureAccess
Invoke-WebRequest -Uri https://secureclient.cityandguilds.com/secureclientinstaller.msi -OutFile C:\PSDownloads\SecureClientinstaller.msi

Write-Output "Step 2: Checking if the Secure Assess Client and .Net Framework 3.5 are installed"

$secureClient = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*').DisplayName -Match "SecureClient"

if($secureClient){
    Write-Output "Step 3: Updating City and Guilds Secure Assess Client"
    Start-Process msiexec.exe -Wait -ArgumentList '/i "C:\PSDownloads\SecureClientinstaller.msi" /qn'
}
else {
    Write-Output "Step 3: Secure Assess Client is not installed. Now installing the Secure Assess client."

    $dotNet35 = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5"
    if (Test-Path $dotNet35){
        Write-Output ".Net Framework 3.5 is already installed"
    }
    else{
        ## Install .Net 3.5
        Write-Output "Installing .Net Framework 3.5"
        Enable-WindowsOptionalFeature -FeatureName "NetFx3" -Online
    }      

    Write-Output "Installing the City and Guilds Secure Assess Client"
    Start-Process msiexec.exe -Wait -ArgumentList '/i "C:\PSDownloads\SecureClientinstaller.msi" /qn'
}

# Clean up folder
## Remove PS Temp Directory
#Write-Output "Removing temporary PowerShell files and folders"
#Remove-Item 'C:\PSDownloads\*' -Force -Recurse
#Remove-Item "C:\PSDownloads" -Force
