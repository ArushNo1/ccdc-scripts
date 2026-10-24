#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$FilePath,

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $FilePath)) {
    throw "Account file not found at '$FilePath'"
}

# Ingest comma-separated or newline-delimited account names
$rawText = Get-Content -LiteralPath $FilePath -Raw
$targetAccounts = @($rawText -split '[,\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique)

# Built-in accounts to leave disabled if already disabled (e.g., Guest)
$neverEnable = @('Guest', 'DefaultAccount', 'WDAGUtilityAccount', 'krbtgt')

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

        # 1. Re-enable all accounts (except standard disabled system accounts)
        $allADUsers = Get-ADUser -Filter * -Server $server
        foreach ($user in $allADUsers) {
            $name = $user.SamAccountName
            if ($name -in $neverEnable -or $user.SID.Value -match '-(501|502)$') { continue }
            
            if (-not $user.Enabled) {
                Enable-ADAccount -Identity $user -Server $server
                Write-Host "[RE-ENABLED] $name" -ForegroundColor Cyan
            }
        }

        # 2. Reset passwords and verify enable for accounts from the file
        foreach ($name in $targetAccounts) {
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
                Write-Warning "Could not update user ${name}: $($_.Exception.Message)"
            } finally {
                $securePass.Dispose()
            }
        }
    } else {
        Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop

        # 1. Re-enable all local accounts
        $allLocalUsers = Get-LocalUser
        foreach ($user in $allLocalUsers) {
            $name = $user.Name
            if ($name -in $neverEnable -or $user.SID.Value -match '-(501|504)$') { continue }

            if (-not $user.Enabled) {
                Enable-LocalUser -Name $name
                Write-Host "[RE-ENABLED] $name" -ForegroundColor Cyan
            }
        }

        # 2. Reset passwords and verify enable for accounts from the file
        foreach ($name in $targetAccounts) {
            $passphrase = New-Passphrase
            $securePass = ConvertTo-SecureString $passphrase -AsPlainText -Force
            try {
                Set-LocalUser -Name $name -Password $securePass
                Enable-LocalUser -Name $name

                $line = "$name,$passphrase"
                $results.Add($line)
                Write-Output $line
            } catch {
                Write-Warning "Could not update user ${name}: $($_.Exception.Message)"
            } finally {
                $securePass.Dispose()
            }
        }
    }
} finally {
    $rng.Dispose()
}

if ($OutputPath) {
    $results | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host "`nCredentials exported to: $OutputPath" -ForegroundColor Green
}