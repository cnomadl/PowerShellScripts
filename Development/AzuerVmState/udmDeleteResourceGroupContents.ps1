#$null = Set-AzureRmContext -SubscriptionName $SubscriptionName

@(
  'Microsoft.Compute/virtualMachineScaleSets'
  'Microsoft.Compute/virtualMachines'
  'Microsoft.Storage/storageAccounts'
  'Microsoft.Compute/availabilitySets'
  'Microsoft.ServiceBus/namespaces'
  'Microsoft.Network/connections'
  'Microsoft.Network/virtualNetworkGateways'
  'Microsoft.Network/loadBalancers'
  'Microsoft.Network/networkInterfaces'
  'Microsoft.Network/publicIPAddresses'
  'Microsoft.Network/networkSecurityGroups'
  'Microsoft.Network/virtualNetworks'

  # this will remove everything else in the resource group regardless of resource type
  #'*'
) | ForEach-Object {
  $odataQuery = "`$filter=resourcegroup eq '$ResourceGroupName'"

  if ($_ -ne '*') {
    $odataQuery += " and resourcetype eq '$_'"
  }

  $resources = Get-AzureRmResource -ODataQuery $odataQuery
  $resources | Where-Object { $_.ResourceGroupName -eq $ResourceGroupName } | ForEach-Object { 
    Write-Host ('Processing {0}/{1}' -f $_.ResourceType, $_.ResourceName)
    $_ | Remove-AzureRmResource -Verbose -Force
  }
}