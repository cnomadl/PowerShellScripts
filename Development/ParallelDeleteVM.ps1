#run these steps 
 
# 1 login to azure 
add-azurermaccount 
 
# 2 save your context 
Save-AzureRmContext -Path $home\ctx.json -Force 
 
# 3 define The resource group where the VMs are deployed  
$rg = 'AZEUS2-MY-APP'  
  
# 4 define the role (or VM name) to delete the role or Virtual Machine  
$role = '^client'  
  
# 5 Run the following first to confirm which machines/s will be deleted.   
Get-AzureRMVM -ResourceGroup $rg | Where-Object Name -Match $role 
 
# 6 execute the function. 
# choose to delete public ip? default is on. 
# (update param to default value $false to alsways keep the public ip) 
 
Remove-AzureRMVMInstanceParallel -ResourceGroup $rg  -VMName $role  -Wait -RemovePublicIP