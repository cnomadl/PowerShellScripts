# Connect ot Azure Ad
connect-AzureAD

#Confirm Connection
Get-AzureADUser
#or
#Connect-MSOlService

#Generate a Password Profile
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.$PasswordProfile
$PasswordProfile.Password = "P@ssw0rd"

#Splat paramerters
$params = @{    
    DisplayName = $displayName
    GiveName = $firstname
    SurName = $surname    
    UserPrincipalName = "$firstname.$surname@balticazure.com"
    UsageLocation = UK
    PasswordProfile = $PasswordProfile
    MailNickName = $displayName
    AccounEnable = $true
}

#Create User
New-AzureADUser @params
#or
#New-MsolsUser

#Check results
Get-AzureADUser