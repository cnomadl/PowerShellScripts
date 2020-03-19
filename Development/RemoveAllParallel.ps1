function Remove-AzureRmVmInstanceParallel {
    [cmdletbinding()]
    param (
        #Name of Resource Group
        [parameter(Mandatory, Position=0)]
        [string]$ResourceGroup,

        #VMs to remove. Regex are supported
        [parameter(Mandatory, Position=1)]
        [string]$VmName,

        # The script will not wait for background jobs by default, use this switch to wait
        [switch]$wait,

        # Delete public IP, true by default
        $RemovePublicIp = $true
    )

    # Enable Context Autosave
    Enable-AzureRmContextAutosave

    #Connect to your Azure subscription
    Write-Information -MessageData "Connecting you to your Azure Subscription" -InformationAction Continue
    #Connect-AzureRmAccount
    Login-AzureRmAccount

    # Remove the VMs and then datadisk, OSdisk, Nics and NSG
    $jobs = Get-AzureRmVM -ResourceGroupName $ResourceGroup | Where-Object Name -Match $VmName | ForEach-Object {
        $vm=$_

        # to avoid locks on tokecache.dat file
        Start-Sleep -Seconds 3

        Start-Job -ScriptBlock {
            try {
                $ctx = Get-AzureRmContext

                $resourceGroup = $using:ResourceGroup
                $VmName = $using:VM
                $RemovePublicIp = $using:RemovePublicIp

                Write-Verbose -Message "Connected to $($ctx.Context.Subscription.Name)" -Verbose
                Write-Verbose -Message "The following resources were found:"

                $VM = Get-AzureRmVM -ResourceGroupName $resourceGroup -Name $VmName.Name -Verbose
                
                $DataDisk =@($vm.StorageProfile.DataDisks.Name)
                $OsDisk = @($vm.StorageProfile.OsDisk.Name)
                $Nics = @($vm.NetworkProfile.NetworkInterfaces)
                $managedDisk = $vm.StorageProfile.OsDisk.ManagedDisk
                ($OsDisk + $DataDisk)
                $Nics | ForEach-Object ID
                $Nsgs | ForEach-Object ID
                $NsgName = (Get-AzureRmNetworkSecurityGroup -ResourceGroupName $resourceGroup).Name 
                $vNetName = (Get-AzureRmVirtualNetwork -ResourceGroupName $resourceGroup).Name

                Write-Warning -Message "Deleting VM:[$($VmName.Name)] from Resource Group:[$resourceGroup]"

                # Delete Virtual Machine
                $VM | Remove-AzureRmVM -Force -Confirm:$false

                # Delete NIC
                $Nics | Where-Object {$_.ID} | ForEach-Object {
                    $NicName = Split-Path $_.ID -Leaf
                    Write-Warning -Message "Removing NIC: $NicName"
                    $Nic = Get-AzureRmNetworkInterface -ResourceGroupName $resourceGroup -Name $NicName
                    $Nic | Remove-AzureRmNetworkInterface -Force

                    # Remove the public IP. This will not save the static IP
                    if ($RemovePublicIp)
                    {
                        $Nic.IpConfigurations.PublicIpAddress | Where-Object {$_.ID} | ForEach-Object {
                            $PublicIpName = Split-Path -Path $_.ID -Leaf
                            Write-Warning -Message "Removing the Public IP: $PublicIpName"
                            $PublicIp = Get-AzureRmPublicIpAddress -ResourceGroupName $resourceGroup -Name $PublicIpName
                            $PublicIp | Remove-AzureRmPublicIpAddress -Force
                        }
                    }
                }

                # Delete VNet. This will delete all Virtual networks in the resource group
                Write-Warning -Message "Removing Virtual Network: $vNetName"
                $vNet = Get-AzureRmVirtualNetwork -ResourceGroupName $resourceGroup -Name $vNetName
                $vNet | Remove-AzureRmVirtualNetwork -Force

                # Delete managed disks
                if($managedDisk) {
                    ($OsDisk + $DataDisk) | Where-Object {$_} | ForEach-Object {
                        Write-Warning -Message "Removing Disk: $_"
                        Get-AzureRmDisk -ResourceGroupName $resourceGroup -DiskName $_ | Remove-AzureRmDisk -Force
                    }
                } else {
                    # Delete Data disk
                    $saName = ($VM.StorageProfile.DataDisks.Vhd.Uri -split '\.' | Select-Object -First 1) -split '//' | Select-Object -Last 1

                    $Sa = Get-AzureRmStorageAccount -ResourceGroupName $resourceGroup -Name $saName
                    $VM.StorageProfile.DataDisks | ForEach-Object {
                        $disk = $_.vhd.Uri | Split-Path -Leaf
                        Get-AzureStorageContainer -Name vhds -Context $Sa.Context | 
                        Get-AzureStorageBlob -Blob $disk | 
                        Remove-AzureStorageBlob
                    }

                    # Delete OS Disk
                    $saName = ($VM.StorageProfile.DataDisks.Vhd.Uri -split '\.' | Select-Object -First 1) -split '//' | Select-Object -Last 1
                    $disk = $VM.StorageProfile.OsDisk.Vhd.Uri | Split-Path -Leaf
                    $Sa = Get-AzureRmStorageAccount -ResourceGroupName $resourceGroup -Name $saName
                    Get-AzureStorageContainer -Name vhds -Context $Sa.Context | 
                    Get-AzureStorageBlob -Blob $disk |
                    Remove-AzureStorageBlob
                }

                # Delete NSG. This will delete all the NGSs in the resource group
                #$Nsgs | Where-Object {$_.ID} | ForEach-Object {
                #    $NsgName = Split-Path $_.ID -Leaf
                #    Write-Warning -Message "Removing Network Security Group: $NsgName"
                #    $Nsg = Get-AzureRmNetworkSecurityGroup -ResourceGroupName $resourceGroup -Name $NsgName
                #    $Nsg | Remove-AzureRmNetworkSecurityGroup -Force
                #}

                Write-Warning -Message "Removing Network Security Group: $NsgName"
                $Nsg = Get-AzureRmNetworkSecurityGroup -ResourceGroupName $resourceGroup -Name $NsgName
                $Nsg | Remove-AzureRmNetworkSecurityGroup -Force                

            }
            catch {
                Write-Warning -Message 'You must save your Context first'
                Write-Warning $_
            }
        }#Start-job

    }#ForEach-Object(Get-AzureRmVm)

    Start-Sleep -Seconds 30
    $jobs | Receive-Job -Keep

    if ($wait)
    {
        Start-Sleep -Seconds 30
        $jobs | Wait-Job | Receive-Job
    } else {
        Write-Warning -Message "Run the following to view the status of parallel delete 'nGet-Job | Receive-Job -Keep"
    }
    
}#function

# Execute the function
Remove-AzureRMVMInstanceParallel ChrisLangfordRg -VmName $VirtualMachineName -wait -RemovePublicIp $true