<#
    .DESCRIPTION
        An Azure automation run as account login
#>

$connectionName = "AzureRunAsConnection"
try {
    # Get the connection "AzureRunAsConnectin"
    $servicePrincipleConnection=Get-AutomationConnection -Name $connectionName

    "Logging in to Azure..."
    Add-AzureAccount 
        -ServicePrincipal 
        -TenantId $servicePrincipleConnection.TenantId 
        -ApplicationId $servicePrincipleConnection.ApplicationId 
        -CertificateThumbprint $servicePrincipleConnection.CertificateThumbprint
}
catch {
    if (!$servicePrincipleConnection)
    {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    } else {
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
    
}