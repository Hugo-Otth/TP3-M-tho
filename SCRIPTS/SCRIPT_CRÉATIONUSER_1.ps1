Param(
    [string] $domainName,
    [string] $listeUsers,
    [string] $Admin
)

# Vérifie que l'utilisateur est un Admin
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "You must be an administrator to run this script." -ForegroundColor Red
    Exit
}

# Active Directory connection parameters
$domainName = "ProNGF.ca"
$ouPath = "OU=Users,DC=prongf,DC=ca"
$adminGroupName = "Administrators"

# Connection au Active Directory
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$root = $domain.GetDirectoryEntry()
$administratorsGroup = [ADSI]("LDAP://CN=$adminGroupName," + $root.distinguishedName)

# Création des users
$users = Get-Content -Path $listeUsers | ConvertFrom-String -Delimiter " "

$usernames = @()
$passwords = @()

foreach ($user in $users) {
    $usernames += $user.UserName
    $passwords += $
}

foreach ($user in $users) {
    $password = ConvertTo-SecureString -AsPlainText $user.Password -Force
    $UPN = "$user@$domainName"
    if($user -eq $admin) {
        $ = "A_$user@$domainName"
    }
    $userParams = @{
        Name = $user
        GivenName = $user
        DisplayName = $user
        SamAccountName = $user
        UserPrincipalName = $UPN
        Path = "LDAP://$ouPath"
        AccountPassword = $password
        Enabled = $true
    }
    
    #Ajotue l'utilisateur en admin s'il est mis en parametre
    $newUser = New-LocalUser @userParams
    if ($userName -eq $admin) {
        $administratorsGroup.Add("LDAP://" + $newUser.distinguishedName)
    }
}
Write-Host "User creation complete." -ForegroundColor Green
