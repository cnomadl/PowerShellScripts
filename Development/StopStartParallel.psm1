[cmdletbinding()]
param (
    [ValidateSet("Start","Stop")]
    [string]
    $Action,
    $labName = "BalticDevLab",
    $labResourceGroup = "BalticDevLabRG"
)

if ($Action -eq "Start") {
    Write-Verbose "Starting Bastian first"
    Get-AzureRmResource | Where-Object {
        $_.Name -match "bastian" -and 
        $_.ResourceType -eq "Microsoft.Compute/virtualMachines" -and
        $_.ResourceGroupName -match $labResourceGroup } | Start-AzureRmVM

    Write-Verbose "Starting other machines in the lab as background jobs"
    foreach ($AzureRMResource in Get-AzureRmResource | 
    Where-Object {
        $_.Name -notmatch "bastian" -and 
        $_.ResourceType -eq "Microsoft.Compute/virtualMachines" -and
        $_.ResourceGroupName -match $labResourceGroup } )
        {
            Start-Job { 
                $myResource = $using:AzureRMResource                
                Start-AzureRMVM -Name $myResource.Name -ResourceGroupName $myResource.ResourceGroupName
               }            
        }

    # wait for all machines to start before exiting the session
    Get-Job | Wait-Job
    Get-Job | Remove-Job
}