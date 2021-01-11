##################################################
# Script to install City and Guilds SecureClient #
# Author: Chris Langford                         #
# Version: 0.9.0                                 #
##################################################

# Download link iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/SecureAssess'))

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# This will allow the script to self elevate with a UAC prompt as the script need to run as an Administrator in order to function correctly

$ErrorActionPreference = 'SilentlyContinue'
$wshell = New-Object -ComObject Wscript.Shell
$button = [System.Windows.MessageBoxButton]::YesNoCancel
$errorIcon = [System.Windows.MessageBoxImage]::Error
$ask = 'Do you want to run this as an Administrator?
        Select "Yes" to run as Administrator
        Select "No" to run this as a none administrator
        Select "Cancel" to stop the script.'

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')){
    $prompt = [Security.Windows.MessageBox]::Show($ask, "Run as an Administrator or not?", $button, $errorIcon)
    switch ($prompt) {
        Yes {
            Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
            Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
            Exit
        }
        No{
            Break
        }
    }
}

$form_CandG                      = New-Object system.Windows.Forms.Form
$form_CandG.ClientSize           = New-Object System.Drawing.Point(500,500)
$form_CandG.text                 = "City & Guilds SecureClient"
$form_CandG.TopMost              = $false
$form_CandG.ShowIcon             = $false
$form_CandG.MaximizeBox          = $false
$form_CandG.MinimizeBox          = $false

$lbl_Header                      = New-Object system.Windows.Forms.Label
$lbl_Header.text                 = "Update or Install City and Guilds Secure Client"
$lbl_Header.AutoSize             = $false
$lbl_Header.enabled              = $true
$lbl_Header.TextAlign            = 'TopCenter'
$lbl_Header.width                = 422
$lbl_Header.height               = 57
$lbl_Header.location             = New-Object System.Drawing.Point(30,32)
$lbl_Header.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',18)

$pnl_Buttons                     = New-Object system.Windows.Forms.Panel
$pnl_Buttons.height              = 180
$pnl_Buttons.width               = 428
$pnl_Buttons.location            = New-Object System.Drawing.Point(31,111)

$btn_UpdateSecureClient          = New-Object system.Windows.Forms.Button
$btn_UpdateSecureClient.text     = "Update SecureClient"
$btn_UpdateSecureClient.width    = 175
$btn_UpdateSecureClient.height   = 145
$btn_UpdateSecureClient.location = New-Object System.Drawing.Point(8,16)
$btn_UpdateSecureClient.Font     = New-Object System.Drawing.Font('Microsoft Sans Serif',16)

$btn_InstallSecureClinet         = New-Object system.Windows.Forms.Button
$btn_InstallSecureClinet.text    = "Install SecureClient"
$btn_InstallSecureClinet.width   = 175
$btn_InstallSecureClinet.height  = 145
$btn_InstallSecureClinet.location  = New-Object System.Drawing.Point(244,16)
$btn_InstallSecureClinet.Font    = New-Object System.Drawing.Font('Microsoft Sans Serif',16)

$pnl_Footer                      = New-Object system.Windows.Forms.Panel
$pnl_Footer.height               = 125
$pnl_Footer.width                = 428
$pnl_Footer.location             = New-Object System.Drawing.Point(32,336)

$picBox_Logo                     = New-Object system.Windows.Forms.PictureBox
$picBox_Logo.width               = 171
$picBox_Logo.height              = 110
$picBox_Logo.location            = New-Object System.Drawing.Point(125,7)
$picBox_Logo.imageLocation       = "undefined"
$picBox_Logo.SizeMode            = [System.Windows.Forms.PictureBoxSizeMode]::zoom

$form_CandG.controls.AddRange(@($lbl_Header,$pnl_Buttons,$pnl_Footer))
$pnl_Buttons.controls.AddRange(@($btn_UpdateSecureClient,$btn_InstallSecureClinet))
$pnl_Footer.controls.AddRange(@($picBox_Logo))

$btn_UpdateSecureClient.Add_Click({
    $secureClient = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*').DisplayName -Match "SecureClient" -or "SecureAssess C"
    if($secureClient){
        Write-Host "Downloading City and Guilds SecureClient"
        Invoke-WebRequest -Uri https://secureclient.cityandguilds.com/secureclientinstaller.msi -OutFile $env:USERPROFILE\Downloads\SecureClientinstaller.msi

        Write-Host "Updating City and Guilds Secure Assess Client"
        Start-Process msiexec.exe -Wait -ArgumentList '/i "$env:USERPROFILE\Downloads\SecureClientinstaller.msi" /qn'

        # Remove Folders
        Remove-Item "C:\PSDownloads\*" -Force -Recurse
        Remove-Item "C:\PSDownloads" -Force

        $wShell.popup("Update completed",0)
    }else{
        $wshell.popup("SecureClient is not installed. Please install the client",0)
    }
})

$btn_InstallSecureClinet.Add_Click({
    $dotNet35 = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5"
    if (!(Test-Path $dotNet35)){
        Write-Host "Installing .Net Framework 3.5"
        Enable-WindowsOptionalFeature -FeatureName "NetFx3" -Online        
    }
    else{        
        Write-Host ".Net Framework 3.5 is already installed"
    }

    Write-Host "Downloading City and Guilds SecureClient"
    New-Item C:\PSDownloads -ItemType Directory
    Invoke-WebRequest -Uri https://secureclient.cityandguilds.com/secureclientinstaller.msi -OutFile C:\PSDownloads\SecureClientinstaller.msi

    Write-Host "Installing SecureClinet_CANDG"
    Start-Process msiexec.exe -Wait -ArgumentList '/i "C:\PSDownloads\SecureClientinstaller.msi" /qn'

    # Remove Folders
    Remove-Item "C:\PSDownloads\*" -Force -Recurse
    Remove-Item "C:\PSDownloads" -Force

    $wshell.Popup("Installation Completed",0)
})

#function btn_InstallSecureClinet_Click { }
#function btn_UpdaeSecureClient_Click { }


#Write your logic code here

[void]$form_CandG.ShowDialog()