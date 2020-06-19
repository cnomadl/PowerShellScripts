# Download and configure the required lab environment artifacts
## Create the ISO images folder for Hyper-V
New-Item C:\ISOs -ItemType Directory

### Connect to Azure storage
$sasToken = New-AzStorageContainerSASToken -Container testingiso -Permission r1
$ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -SasToken $sasToken

### Download ISO images
$blobName = @('Windows_Server_2016_Datacenter.iso','Windows_10_Pro.iso','Office2013.iso')
#$blobName1 = "Windows_Server_2016_Datacenter.iso"
#$blobName2 = "Windows_10_Pro.iso"
#$blobName3 = "Office2013.iso"

$targetDirectory = "C:\ISOs"
$containerName = "testingiso"

Get-AzStorageBlobContent -Blob $blobName -Container $containerName -Destination $targetDirectory -Context $ctx
#Get-AzStorageBlobContent -Blob $blobName1 -Container $containerName -Destination $targetDirectory -Context $ctx -wait
#Get-AzStorageBlobContent -Blob $blobName2 -Container $containerName -Destination $targetDirectory -Context $ctx -wait
#Get-AzStorageBlobContent -Blob $blobName3 -Container $containerName -Destination $targetDirectory -Context $ctx
#Invoke-WebRequest -Uri -OutFile C:\ISOs\Windows_Server_2016_Datacenter
#Invoke-WebRequest -Uri -OutFile C:\ISOs\Windows_10_Pro
#Invoke-WebRequest -Uri -OutFile C:\ISOs\Office2013