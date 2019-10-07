# Login to Azure
Add-AzureRmAccount

# Save your context
Save-AzureRmContext -Path $home\ctx.json -Force

#Define your resource group
$rg = ''

# define the VM or VMs to be removed
$VirtualMachineName = ''

# Run the following command to confirm which VMs will be deleted as no confirmation is provided.
Get-AzureRmVM -ResourceGroup $rg | Where-Object Name -Match $VirtualMachineName

# Execute the function
Remove-AzureRMVMInstanceParallel -ResourceGroup $rg -VmName $VirtualMachineName -wait -RemovePublicIp $true