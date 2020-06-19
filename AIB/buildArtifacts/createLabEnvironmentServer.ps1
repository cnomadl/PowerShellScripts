# Download and configure the required lab environment artifacts
## Create the ISO images folder for Hyper-V
Write-Information -MessageData 'Creating Hyper-V ISO directory' -InformationAction Continue
New-Item C:\ISOs -ItemType Directory

# Connect to Azure Account
Write-Information -MessageData 'Connecting to the Azure storage account' -InformationAction Continue
Connect-AzAccount

#Selecting the subscription if you have access to more than one subscriptions in your Azure account
#$context = Get-AzSubscription -SubscriptionId ""
#Set-AzContext $context

### Connect to Azure storage and Set the context as per the security requirements (i will be trying different options to see which is best)
$StorageAccountName = "balticaibsa"
$saResourceGroup = "BalticImagesRg"

$storageAccountKey = Get-AzStorageAccountKey -AccountName $StorageAccountName -ResourceGroupName $saResourceGroup
$ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $storageAccountKey[0].value

### Download ISO images
$containerName = "testingiso"
$blobs = Get-AzStorageBlob -Container $containerName -Context $ctx
$targetDirectory = "C:\ISOs"

Write-Information -MessageData 'Downloading the ISO files' -InformationAction Continue
foreach ($blob in $blobs) {
    Get-AzStorageBlobContent -Container $containerName -Blob $blob.Name -Destination $targetDirectory -Context $ctx
}

# Disconnect from Azure
Write-Information -MessageData 'Disconnecting from Azure' -InformationAction Continue
Disconnect-AzAccount