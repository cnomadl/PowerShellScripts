function udfStopStartVm {
    param (
    
        # Action to perform Stop | Start
        [Parameter(Mandatory=$true)]
        [String]$action,

        # Tag name
        [Parameter(Mandatory=$false)]
        [String]$tagName,

        # Tag Value
        [Parameter(Mandatory=$false)]
        [String]$tagValue

    )

    #Authentication
    Write-Output ""
    Write-Output "------------------------ Authentication ------------------------"
    Write-Output "Logging into Azure ..."

    Connect-AzureRmAccount

    #End Authentication

    #Getting all the Virtual Machines
    Write-Output ""
    Write-Output "------------------------ Status ------------------------"
    Write-Output "Getting all virtual machines from all resource group ..."

    try {
        if ($tagName)
        {
            $instances = Get-AzureRmResource -TagName $tagName -TagValue $tagValue -ResourceType "Microsoft.Compute/virtualMachines"
            
            if ($instances)
            {
                $resourceGroupContent = @()

                foreach ($instance in $instances)
                {
                     $instancePowerState = (((Get-AzureRmVM -ResourceGroupName $($instance.ResourceGroupName) -Name $($instance.Name) -Status).Statuses.Code[1]) -replace "PowerState/", "")

                     $resourceGroupContent = New-Object -Type PSObject -Property @{
                         "Resource group name" = $($instance.ResourceGroupName)
                         "Instance name" =$ ($instance.Name)
                         "Instance type" = (($instance.ResourceType -split "/")[0].Substring(10))
                         "Instance state" = ([System.Threading.Thread]::CurrentThread.CurrentCulture.TextInfo.ToTitleCase($instancePowerState))
                         $tagName = $tagValue
                     }

                     $resourceGroupContent += $resourceGroupContent
                }
            }
            else {
                #Do nothing
            }
        }
        else {
            $instance = Get-AzureRmResource -ResourceType "Microsoft.Compute/virtualmachines"

            if ($instances)
            {
                $resourceGroupContent = @()

                foreach ($instance in $instances)
                {
                    $instancePowerState = (((Get-AzureRmVM -ResourceGroupName $($instance.ResourceGroupName) -Name $($instance.Name) -Status).Statuses.Code[1]) -replace "PowerState/", "")

                    $resourceGroupContent = New-Object -Type PSObject -Property @{
                        "Resource group name" = $($instance.ResourceGroupName)
                        "Instance name" =$ ($instance.Name)
                        "Instance type" = (($instance.ResourceType -split "/")[0].Substring(10))
                        "Instance state" = ([System.Threading.Thread]::CurrentThread.CurrentCulture.TextInfo.ToTitleCase($instancePowerState))
                        $tagName = $tagValue
                    }

                    $resourceGroupContent += $resourceGroupContent
                }
            }
            else {
                #Do nothing
            }
        }
        $resourceGroupContent | Format-Table -AutoSize
    }
    catch {
        Write-Error -Message $_.Exception
        throe $_.Exception
    }
    #End getting all Virtual Machines

    $runningInstances = ($resourceGroupContent | Where-Object {$_.("Instance state") -eq "Running" -or $_.("Instance state") -eq "Starting"})
    $deallocatedInstance = ($resourceGroupContent | Where-Object {$_.("Instance state") -eq "Deallocated" -or $_.("Instance state") -eq "Deallocating"})

    #Updating virtual machine power state
    if (($runningInstances) -and ($action -eq "Stop"))
    {
        Write-Output "------------------------ Updating ------------------------"
        Write-Output "Trying to stop virtual machines ..."

        try {
            $updateStatuses = @()

            foreach ($runningInstance in $runningInstances)
            {
                Write-Output "$($runningInstance.("Instance name")) is shutting down ..."

                $startTime = Get-Date -Format G

                $null = Stop-AzureRmVM -ResourceGroupName ($runningInstance.("Resource group name")) -Name $($runningInstance.("Instance name")) -Force

                $endtime = Get-Date -Format G

                $updateStatus = New-Object -Type PSObject -Property @{
                    "Resource group name" = $($runningInstance.("Resource group name"))
                    "Instance name" = $($runningInstance.("Instance name"))
                    "Start time" = $startTime
                    "End time" = $endtime
                }

                $updateStatuses += $updateStatus
            }

            $updateStatuses | Format-Table -AutoSize
        }
        catch {
            Write-Error -Message $_.Exception
            throw $_.Exception
        }
    }
    elseif (($deallocatedInstance) -and ($action -eq "Start")) 
    {
        Write-Output "------------------------ Status ------------------------"
        Write-Output "Trying to start virtual machines ..."

        try {
            $updateStatuses = @()

            foreach ($deallocatedInstance in $deallocatedInstances)
            {
                Write-Output "$($deallocatedInstance.("Instance name")) is starting ..."

                $startTime = Get-Date -Format G

                $null = Start-AzureRmVM -ResourceGroupName ($runningInstance.("Resource group name")) -Name $($runningInstance.("Instance name")) -Force

                $endtime = Get-Date -Format G

                $updateStatus = New-Object -Type PSObject -Property @{
                    "Resource group name" = $($deallocatedInstance.("Resource group name"))
                    "Instance name" = $($deallocatedInstance.("Instance name"))
                    "Start time" = $startTime
                    "End time" = $endtime
                }

                $updateStatuses += $updateStatus
            }

            $updateStatuses | Format-Table -AutoSize
        }
        catch {
            Write-Error -Message $_.Exception
            throw $_.Exception
        }
    }
    #End updating virtual machine power state
}