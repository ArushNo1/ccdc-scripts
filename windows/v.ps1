#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$FilePath,

    [string]$OutputPath,

    [switch]$DeleteInsteadOfDisable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $FilePath)) {
    throw "Allowlist file not found at '$FilePath'"
}

# Ingest comma-separated or newline-delimited account names
$rawText = Get-Content -LiteralPath $FilePath -Raw
$allowlist = @($rawText -split '[,\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique)

if (-not $allowlist.Count) {
    throw "Allowlist file is empty! Aborting to prevent locking out all accounts."
}

# Built-in system/service accounts and well-known patterns to NEVER delete or disable
$defaultExclusions = @(
    'Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount', 'krbtgt'
)

$words = @(
    'apple', 'banana', 'cherry', 'lemon', 'mango', 'orange', 'peach', 'pear', 'plum', 'grape',
    'bear', 'bird', 'bunny', 'cat', 'deer', 'dog', 'duck', 'fox', 'horse', 'lion',
    'tiger', 'turtle', 'whale', 'zebra', 'panda', 'mouse', 'sheep', 'goat', 'wolf', 'otter',
    'beach', 'brook', 'cloud', 'forest', 'hill', 'lake', 'moon', 'ocean', 'rain', 'river',
    'rock', 'sand', 'snow', 'star', 'stone', 'sun', 'tree', 'valley', 'wind', 'garden',
    'bread', 'butter', 'cake', 'candy', 'cheese', 'cookie', 'honey', 'muffin', 'pizza', 'waffle',
    'blue', 'green', 'purple', 'silver', 'yellow', 'bright', 'happy', 'kind', 'lucky', 'sunny'
)

$rng = [Security.Cryptography.RandomNumberGenerator]::Create()

function Get-RandomIndex ([int]$Max) {
    $bytes = New-Object byte[] 4
    $limit = [uint64]4294967296 - ([uint64]4294967296 % [uint64]$Max)
    do {
        $rng.GetBytes($bytes)
        $val = [uint64][BitConverter]::ToUInt32($bytes, 0)
    } while ($val -ge $limit)
    [int]($val % $Max)
}

function New-Passphrase {
    $parts = @(1..3 | ForEach-Object { $words[(Get-RandomIndex $words.Count)] })
    $parts[0] = $parts[0].Substring(0, 1).ToUpperInvariant() + $parts[0].Substring(1)
    $parts[(Get-RandomIndex 3)] += (Get-RandomIndex 10000).ToString('D4')
    $parts -join '-'
}

$isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -in 4, 5
$results = New-Object System.Collections.Generic.List[string]

try {
    if ($isDC) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $server = (Get-ADDomain).PDCEmulator
        
        # Enumerate all AD accounts
        $allAccounts = Get-ADUser -Filter * -Server $server -Properties ServicePrincipalNames, SID

        # 1. Identify and nuke non-allowlisted accounts
        foreach ($user in $allAccounts) {
            $name = $user.SamAccountName

            # Skip system/service accounts:
            # - Built-in exclusions
            # - SID ending in -500 (Admin), -501 (Guest), -502 (krbtgt)
            # - Kerberoastable SPN accounts (SQL, IIS, etc.)
            $isService = ($name -in $defaultExclusions) -or 
                         ($user.SID.Value -match '-(500|501|502)$') -or 
                         ($user.ServicePrincipalNames.Count -gt 0)

            if ($isService) { continue }

            if ($name -notin $allowlist) {
                if ($DeleteInsteadOfDisable) {
                    Remove-ADUser -Identity $user -Confirm:$false -Server $server
                    Write-Warning "[NUKED: REMOVED] $name"
                } else {
                    Disable-ADAccount -Identity $user -Server $server
                    Write-Warning "[NUKED: DISABLED] $name"
                }
            }
        }

        # 2. Reset passwords for allowlisted accounts
        foreach ($name in $allowlist) {
            $passphrase = New-Passphrase
            $securePass = ConvertTo-SecureString $passphrase -AsPlainText -Force
            try {
                Set-ADAccountPassword -Identity $name -NewPassword $securePass -Reset -Server $server
                Enable-ADAccount -Identity $name -Server $server
                Set-ADUser -Identity $name -PasswordNeverExpires $false -CannotChangePassword $false -Server $server
                
                $line = "$name,$passphrase"
                $results.Add($line)
                Write-Output $line
            } catch {
                Write-Warning "Could not update allowlisted user ${name}: $($_.Exception.Message)"
            } finally {
                $securePass.Dispose()
            }
        }
    } else {
        Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
        $allUsers = Get-LocalUser

        # 1. Identify and nuke local users
        foreach ($user in $allUsers) {
            $name = $user.Name
            $isService = ($name -in $defaultExclusions) -or ($user.SID.Value -match '-(500|501|503|504)$')

            if ($isService) { continue }

            if ($name -notin $allowlist) {
                if ($DeleteInsteadOfDisable) {
                    Remove-LocalUser -Name $name
                    Write-Warning "[NUKED: REMOVED] $name"
                } else {
                    Disable-LocalUser -Name $name
                    Write-Warning "[NUKED: DISABLED] $name"
                }
            }
        }

        # 2. Reset passwords for allowlisted accounts
        foreach ($name in $allowlist) {
            $passphrase = New-Passphrase
            $securePass = ConvertTo-SecureString $passphrase -AsPlainText -Force
            try {
                Set-LocalUser -Name $name -Password $securePass
                Enable-LocalUser -Name $name
                
                $line = "$name,$passphrase"
                $results.Add($line)
                Write-Output $line
            } catch {
                Write-Warning "Could not update allowlisted user ${name}: $($_.Exception.Message)"
            } finally {
                $securePass.Dispose()
            }
        }
    }
} finally {
    $rng.Dispose()
}

# Write out CSV file if requested
if ($OutputPath) {
    $results | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host "`nCredentials exported to: $OutputPath" -ForegroundColor Green
}