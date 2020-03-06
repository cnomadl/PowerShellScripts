function Restart-VMs
{
    param
    (
        [Parameter(Mandatory=$true, HelpMessage="Virtual Machine name (use * for all)")] 
        [string] $vmName,
        [Parameter(Mandatory=$true, HelpMessage="Resource Group name")] 
        [string] $resourceGroupName
    )

    $vmsToRestart = Get-AzureRmVm | Where-Object { $_.Name -like $vmName -and $_.ResourceGroupName -like $resourceGroupName }
    Write-Host "Restarting $($vmsToRestart.Length) VMs"

    # Need to save the profile so that the login from Login-AzureRmAccount works in the background jobs
    $profilePath = [System.IO.Path]::GetTempFileName()
    Remove-Item $profilePath
    Write-Host "Temporarily saving Azure profile to $profilePath"
    Save-AzureRmProfile -Path $profilePath
    $ErrorActionPreference = "Continue" # Continue restarting other machines if some fail

    try
    {
        $restartScriptBlock =
        {
            param ($vmToRestart, $profilePath)

            Select-AzureRmProfile -Path $profilePath | Out-Null
            Write-Host "Restarting VM: $($vmToRestart.Name)"

            try
            {
                Restart-AzureRmVM -Name $vmToRestart.Name -ResourceGroupName $vmToRestart.ResourceGroupName
            }
            catch
            {
                Write-Error "FAILED to restart VM: $($vmToRestart.Name)"
                Write-Error -ErrorRecord $_
            }

            Write-Host "DONE restarting VM: $($vmToRestart.Name)"
        }

        $jobs = @()
        foreach ($vmToRestart in $vmsToRestart)
        {
            $jobs += Start-Job -ScriptBlock $restartScriptBlock -ArgumentList $vmToRestart,$profilePath
        }

        Write-Host "Restart jobs started, waiting..."
        Wait-Job -Job $jobs | Out-Null
        Receive-Job -Job $jobs
        Write-Host "DONE restarting $($vmsToRestart.Length) VMs"
    }
    finally
    {
        Write-Host "Deleting saved Azure profile $profilePath"
        Remove-Item $profilePath -Force
        $ErrorActionPreference = "Stop"
    }
}