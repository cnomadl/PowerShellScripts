#Download and install the required testing environments features.

## Create download folder
New-Item C:\PSDownloads -ItemType Directory

### Download and install compass
Invoke-WebRequest -Uri https://downloads.certiport.com/Admin/CertiportConsole/Compass_Setup.exe -OutFile C:\PSDownloads

# $compassArgs = @('/Silent','path="C:\Certiport\Compass"','/CertiportID 90040934','/UpdateSchedule Daily','/UpdateTime 09:00:00','/LanguageCode ENU' )
Start-Process -FilePath "C:\PSDownloads/Compass_Setup.exe" -ArgumentList $compassArgs


