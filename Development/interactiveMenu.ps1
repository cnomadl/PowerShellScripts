do
{
    Show-Menu -Title "TechSnips"
    $UserInput = Read-Host "Please make a selection"
    switch ($userInput)
    {
        '1' {'Install AzreRm Module'}
        '2' {'You chose option #2'}
        '3' {'You chose option #3'}
    }
    Pause
}
until ($UserInput -eq 'q')