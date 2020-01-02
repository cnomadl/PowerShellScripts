function New-udfBaResourceGroupCleanup {
    <#
    .SYNOPSIS
    New-CleanResourceGroup will remove all of the resources VM's, vNets etc from the selected Resource Group
 
    .DESCRIPTION 
    The function will remove all of the resources VM's, vNets etc from the selected Resource Group
    
    .PARAMETER depDate
    The date you are removing the resource group resources (eg 020120)

    .PARAMETER resGroup
    The name of your resource group (eg ChrisLangfordRg)
 
    .EXAMPLE
 
    .NOTES
    1. I already had a Resource Group in Azure therefore I put all the VMs in the same group.
    2. I already had a VM network created, all my VMs are in the same network.
 
    .LINK
    URLs to related sites
 
    .INPUTS
    Deployment Name with date
    Resource Group
 
    .OUTPUTS
    None
 
    .EXAMPLE
    New-AzureRmResourceGroupDeployment -Name "ResourceGroupCleanup020120" ResourceGroupName "ChrisLangfordRg" -TemplateFile "https://raw.githubusercontent.com/balticapprenticeships/Azure-Templates/master/resourcegroup-cleanup/removeall.json" -Mode Complete
    #>

    param (
        [cmdletbinding()]
        [Parameter(Mandatory=$True, position=0)]
        [string]$depName,

        [parameter(Mandatory=$True, position=1)]
        [string]$resGroup
    )

    # Connect to the Training Team Azure subscription
    Write-Information -MessageData "Connecting you to the Balic Azure's subscription" -InformationAction Continue
    Connect-AzureRmAccount

    # Delete all the resources within the given resource group. 
    Write-Warning -Message "Removing all resources from: $resGroup. This action CAN NOT be undone"
    New-AzureRmResourceGroupDeployment -Name "ResourceGroupCleanUp$depDate" -ResourceGroupName $resGroup -TemplateFile "https://raw.githubusercontent.com/balticapprenticeships/Azure-Templates/master/resourcegroup-cleanup/removeall.json" -Mode Complete
    
}