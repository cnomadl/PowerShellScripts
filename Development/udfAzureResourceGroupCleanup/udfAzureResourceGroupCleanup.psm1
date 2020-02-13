
function New-udAzureResourceGroupCleanup {
    <#
	    .SYNOPSIS
        New-udfAzureResourceGroupCleanup will remove all of the resources VM's, vNets etc from the selected Resource Group

	    .PARAMETER depDate
        The date you are removing the resource group resources (eg 020120)

        .PARAMETER resGroup
        The name of your resource group (eg AzureDemoRg)

        .PARAMETER filePath
        This is the URL to the  RAW Github file (https://raw.githubusercontent.com/[YOUR USER ACCOUNT]/[REPO]/master/[FILE])
 
        .NOTES
        1. I already had a Resource Group in Azure therefore I put all the VMs in the same group.
        2. I already had a VM network created, all my VMs are in the same network.
 
        .LINK
        URLs to related sites
 
        .INPUTS
        Deployment date
        Resource Group
        File Path
 
        .OUTPUTS
        None

        .EXAMPLE
        New-AzureRmResourceGroupDeployment -Name "ResourceGroupCleanup020120" ResourceGroupName "AzureDemoRg" -TemplateFile "[PATH TO RAW GITHUB FILE]" -Mode Complete
    #>

    param (
        [cmdletbinding()]
        [Parameter(Mandatory=$True, Position=0)]
        [String]$depDate,

        [Parameter(Madatory=$True, Position=1)]
        [String]$resGroup,

        [Paremeter(Mandatory=$True, Position=2)]
        [String]$filePath
    )

    #Connect to your Azure subscription
    Write-Information -MessageData "Connecting you to your Azure Subscription" -InformationAction Continue
    Connect-AzureRmAccount

    #Delete all the resources within the give resource group
    Write-Warning -Message "Removing all resources from $resGroup. This action CAN NOT be undone"
    New-AzureRmResourceGroupDeployment -Name "ResourceGroupCleanup$depDate" -ResourceGroupName $resGroup -TemplateFile $filePath -Mode Complete

}