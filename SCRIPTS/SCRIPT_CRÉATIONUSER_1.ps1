# Check if user running the script is an administrator
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "You must be an administrator to run this script." -ForegroundColor Red
    Exit
}

# Define Active Directory connection parameters
$domainName = "ProNGF.ca"
$ouPath = "OU=Users,DC=prongf,DC=ca"
$adminGroupName = "Administrators"

# Connect to Active Directory and get the administrators group
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$root = $domain.GetDirectoryEntry()
$administratorsGroup = [ADSI]("LDAP://CN=$adminGroupName," + $root.distinguishedName)

# Create 5 users with specified names, one of them named Bob who is an administrator
$users = @("User1", "User2", "User3", "User4", "Bob")
foreach ($user in $users) {
    $password = ConvertTo-SecureString -AsPlainText "Password123!" -Force
    $userParams = @{
        Name = $user
        GivenName = $user
        Surname = "LastName"
        DisplayName = $user
        SamAccountName = $user
        UserPrincipalName = "$user@$domainName"
        Path = "LDAP://$ouPath"
        AccountPassword = $password
        Enabled = $true
        ChangePasswordAtLogon = $true
    }
    $newUser = New-LocalUser @userParams
    if ($userName -eq "Bob") {
        $administratorsGroup.Add("LDAP://" + $newUser.distinguishedName)
    }
}
Write-Host "User creation complete." -ForegroundColor Green
