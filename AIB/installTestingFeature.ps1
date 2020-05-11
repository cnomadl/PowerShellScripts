#Download and install the required testing environments features.

## Create download folder
New-Item C:\PSDownloads -ItemType Directory

### Download and install compass
Invoke-WebRequest -Uri https://downloads.certiport.com/Admin/CertiportConsole/Compass_Setup.exe -OutFile C:\PSDownloads

# $compassArgs = @('comma','seperated','arguments')
Start-Process -FilePath "C:\PSDownloads/Compass_Setup.exe" -ArgumentList $compassArgs


