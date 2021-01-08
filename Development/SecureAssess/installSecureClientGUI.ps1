##################################################
# Script to install City and Guilds SecureClient #
# Author: Chris Langford                         #
# Version: 0.5.1                                 #
##################################################

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
            Write-Output "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
            Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
            Exit
        }
        No{
            Break
        }
    }
}

# The GUI using Windows Forms
$form = New-Object System.Windows.Forms.Form
$form.ClientSize = New-Object System.Drawing.Point(500,500)
$form.Text = "City & Guilds SecureClient"
$form.TopMost = $false
$form.ShowIcon = $false

$panel1 = New-Object System.Windows.Forms.Panel
$panel1.Height = 72
$panel1.Width = 428
$panel1.Location = New-Object System.Drawing.Point(31,31)
$panel1.TabIndex = 0

$label1 = New-Object System.Windows.Forms.Label
$label1.Text = "Update or Install City and Guilds Secure Client"
$label1.AutoSize = $true
#$label1.Width = 422
#$label1.Height = 57
$label1.Size = New-Object System.Drawing.Size(422,57)
$label1.Location = New-Object System.Drawing.Point(3,7)
$label1.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',18)
$label1.TabIndex = 0
$label1.TextAlign = [System.Drawing.ContentAlignment]::TopCenter
$label1.UseCompatibleTextRendering = $true

$updateSecureClient = New-Object System.Windows.Forms.Button
$updateSecureClient.Text = "Update SecureClient"
$updateSecureClient.TabIndex = 1
$updateSecureClient.Width = 175
$updateSecureClient.Height = 145
$updateSecureClient.Location = New-Object System.Drawing.Point(31,128)
$updateSecureClient.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',16)

$installSecureClinet = New-Object System.windows.Forms.Button
$installSecureClinet.Text = "Install SecureClient"
$installSecureClinet.TabIndex = 0
$installSecureClinet.Width = 175
$installSecureClinet.Height = 145
$installSecureClinet.Location = New-Object System.Drawing.Point(284,128)
$installSecureClinet.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',16)

#Logo Panel
$panel2 = New-Object System.Windows.Forms.Panel
$panel2.Width = 425
$panel2.Height = 125
$panel2.Location = New-Object System.Drawing.Point(31,310)
$panel2.TabIndex = 3

$logoBox = New-Object System.Windows.Forms.PictureBox
$logoBox.Width = 200
$logoBox.Height = 118
$logoBox.Location = New-Object System.Drawing.Point(117,3)
$logoBox.imageLocation = "https://github.com/ChrisTitusTech/win10script/blob/master/titus-toolbox.png?raw=true"
$logoBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::zoom
$logoBox.TabIndex = 3



$form.controls.AddRange(@($panel1,$label1,$panel2,$logoBox))
$panel1.controls.AddRange(@($updateSecureClient,$installSecureClinet))

$updateSecureClient.Add_Click({
    $secureClient = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*').DisplayName -Match "SecureClient"
    if($secureClient){
        Write-Output "Updating City and Guilds Secure Assess Client"
        Start-Process msiexec.exe -Wait -ArgumentList '/i "C:\PSDownloads\SecureClientinstaller.msi" /qn'
        $wShell.popup("Update completed",0,"Done",0x0)
    }else{
        $wshell.popup("SecureClient is not installed. Please install the client",0,"Done",0x0)
    }
})

$installSecureClinet.Add_Click({
    $dotNet35 = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5"
    if (!(Test-Path $dotNet35)){
        Write-Output "Installing .Net Framework 3.5"
        Enable-WindowsOptionalFeature -FeatureName "NetFx3" -Online        
    }
    else{        
        Write-Output ".Net Framework 3.5 is already installed"
    }
    Write-Output "Installing SecureClinet_CANDG"
    Start-Process msiexec.exe -Wait -ArgumentList '/i "C:\PSDownloads\SecureClientinstaller.msi" /qn'
    $wshell.Popup("Installation Comppleted",0,"Done",0x0)
})

[void]$form.ShowDialog()