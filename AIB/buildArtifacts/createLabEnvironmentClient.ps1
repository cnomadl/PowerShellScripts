#Download and install the required testing environments features for the Windows 10 Client.

# Install the testing software
## Create a temporary download folder
Write-Warning -MessageData 'Creating a temporary working directory for PowerShell downloads' -InformationAction Continue
New-Item D:\PSDownloads -ItemType Directory

## Download and install Compass for MTA exams
Invoke-WebRequest -Uri http://downloads.certiport.com/Admin/CertiportConsole/Compass_Setup.exe -OutFile D:\PSDownloads\Compass_Setup.exe

Write-Information -MessageData 'Installing Certiport Compass' -InformationAction Continue
$compassArgs = @('/Silent','path="C:\Certiport\Compass"','/TestCenterID 90040934','/CertiportID 90040934','/TestCenterName "Baltic Training Services"','/Iuser ITAdmin','/Ipwd Dfe500tx08','/UpdateSchedule Daily','/UpdateTime 09:00:00','/LanguageCode ENU')
Start-Process -FilePath "D:\PSDownloads/Compass_Setup.exe" -ArgumentList $compassArgs -Wait

### Install exams
Write-Information -MessageData 'Connecting to your Azure storage account' -InformationAction Continue
Connect-AzAccount

### Connect to Azure storage
$StorageAccountName = "balticaibsa"
$saResourceGroup = "BalticImagesRg"
$storageAccountKey = Get-AzStorageAccountKey -AccountName $StorageAccountName -ResourceGroupName $saResourceGroup
$ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $storageAccountKey[0].value

$blobName = "CompassExams.zip"
$psTempDirectory = "D:\PSDownloads"
$targetDirectory = "C:\Certiport\Compass"
$containerName = "testingcpexams"

Write-Information -MessageData 'Downloading files from sorage account' -InformationAction Continue
Get-AzStorageBlobContent -Blob $blobName -Container $containerName -Destination $psTempDirectory -Context $ctx -Force

Write-Information -MessageData 'Extracting downloaded files' -InformationAction Continue
Expand-Archive -Path $psTempDirectory'\compassexams.zip' -DestinationPath $targetDirectory -Force

# Disconnect Azure account
Write-Information -MessageData 'Disconnecting from Azure' -InformationAction Continue
Disconnect-AzAccount

### Download and install SecureClient for City and Guilds
Invoke-WebRequest -Uri https://evolve.cityandguilds.com/secureassess/SecureClientinstaller.msi -OutFile D:\PSDownloads\SecureClientinstaller.msi

Write-Information -MessageData 'Install the City and Guild SecureClient' -InformationAction Continue
$cgArgs = @('/quiet','/norestart')
Start-Process -FilePath "D:\PSDownloads\SecureClientinstaller.msi" -ArgumentList $cgArgs -Wait

#### Clean up folder
Remove-Item 'D:\PSDownloads' -Recurse