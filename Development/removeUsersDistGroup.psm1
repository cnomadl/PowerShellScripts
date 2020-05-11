function udfRemoveUsersFromDistGroup {

    # Example usage udfRemoveUsersFromDistGroup 'c:/file.csv'
    [CmdletBinding()]

    param (
        [parameter(Mandatory)]
        [string]
        $csvPath
    )

    $testPath = Test-Path -Path $csvPath
    if (!$testPath){
        Clear-Host
        Write-Warning -Message '***** Invalid CSV Path *****' -ErrorAction Stop
    } else {
        # Import the username from the CSV
        Import-Csv -Path $csvPath| ForEach-Object {             
            Remove-DistributionGroupMember -Identity $_.'Distribution-List' -Member $_.'User-Name'
        }
    }
}