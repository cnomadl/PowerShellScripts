function stopStartParallel {
    [CmdletBinding()]

    param (
        # Stop or Start
        [Parameter(Mandatory)]
        [string]
        $powerState,

        # M
        [Parameter(Mandatory)]
        [string]
        $resourceGroup
    )

    if (!$powerState){Write-Warning -Message "No powerstate specified. Use -Power start|stop"}
    if (!$resourceGroup){Write-Warning -Message "No Azure Resorce Group specified. Use -ResourceGroupName 'ResourceGroupName'"}

    # Connect to the Azure subscription
    Write-Information -MessageData "Connecting you to the Azure subscription" -InformationAction Continue
    Connect-AzAccount

    Write-Information -MessageData "Listing VM's in Resource Group '"$resourceGroup"'" -InformationAction Continue
    $vms = Get-AzVM -ResourceGroupName $resourceGroup
    $vmRunningList = @()
    $vmStoppedList = @()

    foreach($vm in $vms){
        $vmStatus = Get-AzVM -ResourceGroupName $resourceGroup -Name $vm.name -Status
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

    if ($powerState -eq 'start') {
        Write-Output "Starting VM's "$vmStoppedList " in Resource Group "$resourceGroup
        $vmStoppedList | ForEach-Object -Parallel {
            Start-AzVM -ResourceGroupName $resourceGroup -Name $_ -Verbose
        }
    }

    if ($powerState -eq 'stop') {
        Write-Output "Stopping VM's "$vmRunningList " in Resource Group "$resourceGroup
        $vmRunningList | ForEach-Object -Parallel {
            Stop-AzVM -ResourceGroupName $resourceGroup -Name $_ -Verbose
        }
    }
    
}