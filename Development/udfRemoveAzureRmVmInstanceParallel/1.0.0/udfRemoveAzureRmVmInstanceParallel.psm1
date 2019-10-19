<#
Copyright (c) Chris Langford. All rights reserved.
Licensed under the MIT License.
#>

<#
.SYNOPSIS
Remove Virtual Machine and resources in parallel.

.DESCRIPTION
This Azure Automation runbook removes all the virtual machines and their resources from
the chosen Resource group in parallel.


Prerequisite: an Azure Automation account with an Azure Run As account credential.

.PARAMETER resourceGroupName
The Azure resource group name.

.PARAMETER vmName
The virtual machine name, Regex can be used.
#>
function Remove-udfAzureRmVmInstanceparallel {
    [cmdletbinding()]
    param (
        # Name of Resource Group        
        [Parameter(Mandatory)]
        [string]
        $resourceGroup,

        # VM's to remove. Regex are allowed
        [Parameter(Mandatory)]
        [String]
        $vmName,

        # Use this switch to make the script waite for background jobs
        [switch]
        $wait,

        # Delete public IP. Default is False
        $removePublicIP = $false
    )

    # Remove the VMs, disks, Nics, vNet, & NSG
    $jobs = Get-AzureRmVM -ResourceGroupName $resourceGroup | Where-Object Name -Match $vmName | ForEach-Object 
    {

        $vm=$_

        # Avoid locks on tokencache.dat file
        Start-Sleep -Seconds 3

        Start-Job -ScriptBlock 
        {
            try {
                $ctx = Get-AzureRmContext

                $resourceGroup = $using:resourceGroup
                $vmName = $using:VM
                $removePublicIP = $using:removePublicIP

                Write-Verbose -Message "Connected to $($ctx.Context.Subscription.name)" -Verbose
                Write-Verbose -Message "The following resources were found:"

                $VM = Get-AzureRmVM -ResourceGroupName $resourceGroup -Name $vmName.Name -Verbose

                $dataDisk = @($vm.StorageProfile.DataDisks.Name)
                $osDisk = @($vm.StorageProfile.OsDisk.Name)
                $nics = @($vm.NetworkProfile.NetworkInterfaces)
                $managedDisk = $vm.StorageProfile.OsDisk.ManagedDisk
                ($osDisk + $dataDisk)
                $nics | ForEach-Object ID
                $nsg | ForEach-Object ID
                $nsgName = (Get-AzureRmNetworkSecurityGroup -ResourceGroupName $resourceGroup).Name
                $vNet | ForEach-Object ID
                $vNetname = (Get-AzureRmVirtualNetwork -ResourceGroupName $resourceGroup).Name

                Write-Warning -Message "Deleting Virtual Machine: $($vmName.Name) from Resource Group: $resourceGroup"

                # Delete the Virtual Machine
                $VM | Remove-AzureRmVM -Force -Confirm:$false

                # Delete the Nics
                $nics | Where-Object {$_.ID} | ForEach-Object 
                {
                    $nicName = Split-Path $_.ID -Leaf
                    Write-Warning -Message "Removing NIC: $nicName"
                    $nic = Get-AzureRmNetworkInterface -ResourceGroupName $resourceGroup -Name $nicName
                    $nic | Remove-AzureRmNetworkInterface -Force

                    # Remove the public Ip. this will not save the static IP
                    if ($removePublicIP)
                    {
                        $nic.IpConfigurations.PublicIpAddress | Where-Object {$_.ID} | ForEach-Object
                        {
                            $publicIpName = Split-Path $_.ID -Leaf
                            Write-Warning -Message "Removing the Public IP: $publicIpName"
                            $publicIp = Get-AzureRmPublicIpAddress -ResourceGroupName $resourceGroup -Name $publicIpName
                            $publicIp | Remove-AzureRmPublicIpAddress -Force
                        }
                    }#$removePublicIP
                }#$nics

                # Delete vNet. This will delete all Virtual networks in the resource group
                Write-Warning -Message "Removing Virtual Network: $vNetName"
                $vNet = Get-AzureRmVirtualNetwork -ResourceGroupName $resourceGroup -Name $vNetname
                $vNet | Remove-AzureRmVirtualNetwork -Force

                # Delete managed disks
                if($managedDisk)
                {
                    ($osDisk + $dataDisk) | Where-Object {$_.ID} | ForEach-Object
                    {
                        Write-Warning -Message "Removing Disk: $_"
                        Get-AzureRmDisk -ResourceGroupName $resourceGroup -DiskName $_ | Remove-AzureRmDisk -Force
                    }
                } else {
                    # Delete data disk
                    $saName = ($VM.StorageProfile.DataDisks.Vhd.Uri -split '\' | Select-Object -First 1) -split '//' | Select-Object -Last 1

                    $sa = Get-AzureRmStorageAccount -ResourceGroupName $resourceGroup -Name $saName
                    $VM.StorageProfile.DataDisks | ForEach-Object 
                    {
                        $disk = $_.Vhd.Uri | Split-Path -Leaf
                        Get-AzureStorageContainer -Name vhds -Context $sa.Context | Get-AzureStorageBlob -Blob $disk | Remove-AzureStorageBlob
                    }

                    # Delete OS Disk
                    $saName = ($VM.StorageProfile.DataDisks.Vhd.Uri -split '\' | Select-Object -First 1) -split '//' | Select-Object -Last 1
                    $disk = $VM.StorageProfile.OsDisk.Vhd.Uri | Split-Path -Leaf
                    $sa = Get-AzureRmStorageAccount -ResourceGroupName $resourceGroup -Name $saName
                    Get-AzureStorageContainer -Name vhds -Context $sa.Context | Get-AzureStorageBlob -Blob $disk | Remove-AzureStorageBlob
                }

                # Delete Network Security Group (NSG). This will remove all NSG's in the resource group
                Write-Warning -Message "Removing Network Security Group: $nsgName"
                $nsg = Get-AzureRmNetworkSecurityGroup -ResourceGroupName $resourceGroup -Name $nsgName
                $nsg | Remove-AzureRmNetworkSecurityGroup -Force

            }
            catch {
                Write-Warning -Message "You must save your Context first"
                Write-Warning -Message $_
            }
        }#Start-Job

    }#$jobs

    Start-Sleep -Seconds 30
    $jobs | Receive-Job -Keep

    if ($wait)
    {
        Start-Sleep -Seconds 30
        $jobs | Wait-Job | Receive-Job
    } else {
        Write-Warning -Message "Run the following to view the status of parallel delete'nGet-Job | Receive-Job -Keep"
    }
    
}#function