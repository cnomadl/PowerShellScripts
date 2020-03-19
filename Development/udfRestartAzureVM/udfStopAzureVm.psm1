function Stop-VMs
{
    param
    (
        [Parameter(Mandatory=$true, HelpMessage="Virtual Machine name (use * for all)")] 
        [string] $vmName,
        [Parameter(Mandatory=$true, HelpMessage="Resource Group name")] 
        [string] $resourceGroupName
    )

    $vmsToStop = Get-AzureRmVm | Where-Object { $_.Name -like $vmName -and $_.ResourceGroupName -like $resourceGroupName }
    Write-Host "Stopping $($vmsToStop.Length) VMs"

    # Need to save the profile so that the login from Login-AzureRmAccount works in the background jobs
    $profilePath = [System.IO.Path]::GetTempFileName()
    Remove-Item $profilePath
    Write-Host "Temporarily saving Azure profile to $profilePath"
    Save-AzureRmProfile -Path $profilePath
    $ErrorActionPreference = "Continue" # Continue stopping other machines if some fail

    try
    {
        $stopScriptBlock =
        {
            param ($vmToStop, $profilePath)

            Select-AzureRmProfile -Path $profilePath | Out-Null
            Write-Host "Stopping VM: $($vmToStop.Name)"

            try
            {
                Stop-AzureRmVM -Name $vmToStop.Name -ResourceGroupName $vmToStop.ResourceGroupName
            }
            catch
            {
                Write-Error "FAILED to stop VM: $($vmToStop.Name)"
                Write-Error -ErrorRecord $_
            }

            Write-Host "DONE stopping VM: $($vmToStop.Name)"
        }

        $jobs = @()
        foreach ($vmToStop in $vmsToStop)
        {
            $jobs += Start-Job -ScriptBlock $stopScriptBlock -ArgumentList $vmToStop,$profilePath
        }

        Write-Host "Stop jobs started, waiting..."
        Wait-Job -Job $jobs | Out-Null
        Receive-Job -Job $jobs
        Write-Host "DONE stopping $($vmsToStop.Length) VMs"
    }
    finally
    {
        Write-Host "Deleting saved Azure profile $profilePath"
        Remove-Item $profilePath -Force
        $ErrorActionPreference = "Stop"
    }
}