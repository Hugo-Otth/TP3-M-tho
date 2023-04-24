# Spécifiez les informations d'identification d'un compte avec des privilèges d'administration dans le domaine Active Directory
$credential = Get-Credential

# Spécifiez le chemin d'accès complet du fichier texte contenant les informations d'utilisateur
$userDataFilePath = ".\user.txt"

# Spécifiez le nom de domaine Active Directory
$domainName = "ad.prongf.ca"

# Spécifiez le chemin d'accès à l'unité d'organisation Active Directory où les utilisateurs seront créés
$ouPath = "OU=Utilisateurs,DC=ad,DC=prongf,DC=ca"

# Récupérez les informations d'utilisateur depuis le fichier texte et créez les comptes d'utilisateur dans Active Directory
Get-Content $userDataFilePath | ForEach-Object {
    # Séparez le nom d'utilisateur et le mot de passe sur chaque ligne
    $userData = $_ -split '\s+'
    $username = $userData[0]
    $password = $userData[1]

    # Créez un objet SecureString à partir du mot de passe
    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

    # Spécifiez les propriétés de l'utilisateur à créer
    $userProperties = @{
        Name = $username
        GivenName = $username
        Surname = "NomDeFamille"
        DisplayName = $username
        SamAccountName = $username
        UserPrincipalName = "$username@$domainName"
        Path = "LDAP://$ouPath"
        AccountPassword = $securePassword
        Enabled = $true
        ChangePasswordAtLogon = $true
    }

    # Créez l'utilisateur dans Active Directory
    New-ADUser @userProperties -Credential $credential
}
