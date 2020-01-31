function udfStopAzureRMVm {
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
        [Parameter(Mandatory=$True)]
        [string]$power,

        [Parameter(Mandatory=$True)]
        [string]$resGroup
    )

    if (!$power){Write-Warning -Message "No powerstate specified. Use -Power start|stop"}
    if (!$resGroup){Write-Warning -Message "No Azure Resorce Group specified. Use -ResourceGroupName 'ResourceGroupName'"}

    # Connect to the Training Team Azure subscription
    Write-Information -MessageData "Connecting you to the Balic Azure's subscription" -InformationAction Continue
    Connect-AzureRmAccount

    Write-Information -MessageData "Listing VM's in Resource Group '"$resGroup"'" -InformationAction Continue
    $vms = Get-AzureRmVM -ResourceGroupName $resGroup
    $vmRunningList = @()
    $vmStoppedList = @()

    foreach($vm in $vms){
        $vmStatus = Get-AzureRmVM -ResourceGroupName $resGroup -Name $vm.name -Status
        $powerState = (Get-Culture).TextInfo.ToTitleCase(($vmStatus.Statuses)[1].code.split("/")[1])

        Write-Output "VM: '"$vm.name"' is" $powerState
        if ($powerState -eq 'Running')
        {
            $vmRunningList = $vmRunningList + $vm.name
        }
        if ($powerState -eq 'Deallocated')
        {
            $vmStoppedList = $vmStoppedList + $vm.name
        }
    }

    if ($power -eq 'start') {
        Write-Output "Starting VM's "$vmStoppedList " in Resource Group "$resGroup
        $vmStoppedList | Invoke-Parallel -ImportVariables -NoCloseOnTimeout -ScriptBlock {
            Start-AzureRmVM -ResourceGroupName $resGroup -Name $_ -Verbose
        }
    }

    if ($power -eq 'stop') {
        Write-Output "Stopping VM's "$vmRunningList " in Resource Group "$resGroup
        $vmRunningList | Invoke-Parallel -ImportVariables -NoCloseOnTimeout -ScriptBlock {
            Stop-AzureRmVM -ResourceGroupName $resGroup -Name $_ -Verbose
        }
    }
    
}