
Import-Module ActiveDirectory

# Accounts to restore
$users = @(
    "stephanie.brown"
    "john.hall"
    "david.evans"
    "sarah.lee"
    "josh.jones"
    "joseph.smith"
    "chirag.patel"
    "vivek.sharma"
    "steven.johnson"
    "brian.wilson"
    "rick.smith"
    "david.green"
    "harish.kumar"
    "chris.hill"
    "gagandeep.singh"
    "mike.martin"
    "mike.jackson"
    "david.roberts"
    "dave.jones"
    "michael.walker"
    "michael.allen"
    "jeff.williams"
    "rizwan.khan"
    "kim.jones"
    "juan.martinez"
    "muhammad.usman"
    "christopher.jones"
    "adam.brown"
    "jason.thomas"
    "sue.smith"
)

# Word list
$words = @(
    "River", "Mountain", "Silver", "Forest",
    "Ocean", "Thunder", "Winter", "Falcon",
    "Castle", "Sunset", "Rocket", "Meadow",
    "Copper", "Shadow", "Planet", "Garden",
    "Harbor", "Summit", "Crystal", "Valley"
)

# Save results here
$outputPath = "C:\CCDC\restored-credentials.csv"

New-Item -ItemType Directory -Path "C:\CCDC" -Force |
    Out-Null

$results = @()
$usedPasswords = @{}

foreach ($username in $users) {
    try {
        # Verify user exists
        $account = Get-ADUser -Identity $username -ErrorAction Stop

        # Generate a unique password
        do {
            $selected = @(
                $words | Get-Random -Count 3
            )

            $password = ($selected -join "-") + "1"
        } while ($usedPasswords.ContainsKey($password))

        $usedPasswords[$password] = $true

        $securePassword = ConvertTo-SecureString `
            $password -AsPlainText -Force

        # Reset password
        Set-ADAccountPassword `
            -Identity $account `
            -Reset `
            -NewPassword $securePassword `
            -ErrorAction Stop

        # Enable account
        Enable-ADAccount `
            -Identity $account `
            -ErrorAction Stop

        # Record successful changes
        $results += [PSCustomObject]@{
            Username = $username
            Password = $password
        }
    }
    catch {
        Write-Warning "FAILED: $username - $($_.Exception.Message)"
    }
}

# Save successful credentials
$results | Export-Csv `
    -Path $outputPath `
    -NoTypeInformation

# Output exactly username,password
$results | ForEach-Object {
    "$($_.Username),$($_.Password)"
}

Write-Host "`nSuccessfully updated: $($results.Count) of $($users.Count)"
Write-Host "CSV saved to: $outputPath"
