##############################################
# Script to configure lab client environment #
# Author: Chris Langford                     #
# Version: 2.4.1                             #
##############################################

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# This will allow the script to self elevate with a UAC prompt as the script need to run as an Administrator in order to function correctly

$ErrorActionPreference = 'SilentlyContinue'
$wShell = New-Object -ComObject Wscript.Shell
$button = [System.Windows.MessageBoxButton]::YesNoCancel
$errorIcon = [System.Windows.MessageBoxImage]::Error
$ask = 'Do you want to run this as an Administrator?
        Select "Yes" to run as Administrator
        Select "No" to run this as a none administrator
        Select "Cancel" to stop the script.'

if (!([Security.Principle.WindowsPrinciple][Security.Principle.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principle.WindowsBuiltInRole]'Administrator')){
    $prompt = [Security.WindowsMessageBox]::Show($ask, "Run as an Administrator or not?", $button, $errorIcon)
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

# The GUI using Windows Forms
$form = New-Object System.Windows.Form.Form
$form.ClientSize = New-Object System.Drawing.Point(1050,700)
$form.Text = "Form"
$form.TopMost = $false

$panel1 = New-Object System.Windows.Form.Panel
$panel1.Height = 156
$panel1.Width = 1032
$panel1.Location = New-Object System.Drawing.Point(9,90)

$label1 = New-Object System.Windows.Forms.Label
$label1.Text = "Update City and Guilds Secure Assess Client"
$label1.AutoSize = $true
$label1.Width = 25
$label1.Height = 10
$label1.Location = New-Object System.Drawing.Point(10,30)
$label1.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',30)

$updateSecureClient = New-Object System.Windows.Form.Button
$updateSecureClient.Text = "Update SecureClient"
$updateSecureClient.Width = 200
$updateSecureClient.Height = 115
$updateSecureClient.Location = New-Object System.Drawing.Point(16,19)
$updateSecureClient.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',30)

$form.controls.AddRange(@($panel1,$label1))
$panel1.controls.AddRange(@($updateSecureClient))

$updateSecureClient.Add_Click({
    $secureClient = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*').DisplayName -Match "SecureClient"
    if($secureClient){
        Write-Output "Updating City and Guilds Secure Assess Client"
        Start-Process msiexec.exe -Wait -ArgumentList '/i "C:\PSDownloads\SecureClientinstaller.msi" /qn'
        $wShell.popup("Update completed",0,"Done",0x0)
    }else{
        $wShell.popup("SecureClient is not installed. Please install the client",0,"Done",0x0)
    }
})

[void]$form.ShowDialog()