#Download and install the required testing environments features.

## Create download folder
New-Item C:\PSDownloads -ItemType Directory

### Download and install compass
Invoke-WebRequest -Uri https://downloads.certiport.com/Admin/CertiportConsole/Compass_Setup.exe -OutFile C:\PSDownloads\Compass_Setup.exe

$compassArgs = @('/Silent','path="C:\Certiport\Compass"','/TestCenterID 90040934','/CertiportID 90040934','/TestCenterName "Baltic Training Services"','/Iuser ITAdmin','/Ipwd Dfe500tx08','/UpdateSchedule Daily','/UpdateTime 09:00:00','/LanguageCode ENU')
Start-Process -FilePath "C:\PSDownloads/Compass_Setup.exe" -ArgumentList $compassArgs

### Download and install SecureClient
Invoke-WebRequest -Uri https://evolve.cityandguilds.com/secureassess/SecureClientinstaller.msi -OutFile C:\PSDownloads\SecureClientinstaller.msi

$cgArgs = @('/quiet','/norestart')
Start-Process -FilePath "C:\PSDownloads\SecureClientinstaller.msi" -ArgumentList $cgArgs
