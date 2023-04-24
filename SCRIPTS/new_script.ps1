# Set variables for the new user's information
$username = "NewUser"
$password = "P@ssw0rd"
$firstname = "John"
$lastname = "Doe"
$ou = "OU=Utilisateurs,DC=prongf,DC=ca"
$description = "New user created with PowerShell"

# Create the new user object
$newUser = New-Object -TypeName Microsoft.ActiveDirectory.Management.ADUser
$newUser.SamAccountName = $username
$newUser.UserPrincipalName = "$username@example.com"
$newUser.Name = "$firstname $lastname"
$newUser.GivenName = $firstname
$newUser.Surname = $lastname
$newUser.Enabled = $true
$newUser.PasswordNeverExpires = $true
$newUser.CanChangePassword = $true
$newUser.Description = $description

# Set the new user's password
$passwordSecureString = ConvertTo-SecureString -String $password -AsPlainText -Force
$newUser.SetPassword($passwordSecureString)

# Save the new user to Active Directory
New-ADObject -Type User -Path $ou -Name $username -OtherAttributes @{'userAccountControl'='512'} -Credential (Get-Credential) -Instance $newUser
