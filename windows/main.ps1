# are we making nats?
# yolo
# umd on top
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$AuthorizedAdmins,
    [string[]]$AuthorizedUsers = @(),
    [string[]]$PreserveAccount = @(),
    [string[]]$PreservePassword = @(),
    [switch]$NonInteractive,
    [switch]$SkipPasswordReset,
    [string]$CredentialOutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function read-accountlist {
    param([string]$Prompt)
    @( (Read-Host $Prompt) -split ',' | ForEach-Object { $_.Trim() } |
        Where-Object { $_ } | Sort-Object -Unique )
}


function get-randomindex {
    param([int]$Maximum)
    # Rejection sampling avoids modulo bias; RandomNumberGenerator works on PS 5.1.
    $bytes = New-Object byte[] 4
    $limit = [uint64]4294967296 - ([uint64]4294967296 % [uint64]$Maximum)
    do {
        $rng.GetBytes($bytes)
        $value = [uint64][BitConverter]::ToUInt32($bytes, 0)
    } while ($value -ge $limit)
    [int]($value % $Maximum)
}


function new-passphrase {
    $parts = @(1..3 | ForEach-Object { $words[(get-randomindex $words.Count)] })
    $parts[0] = $parts[0].Substring(0, 1).ToUpperInvariant() + $parts[0].Substring(1)
    $parts[(get-randomindex 3)] += (get-randomindex 10000).ToString('D4')
    $parts -join '-'
}

$words = @(
    'apple', 'banana', 'cherry', 'lemon', 'mango', 'orange', 'peach', 'pear', 'plum', 'grape',
    'bear', 'bird', 'bunny', 'cat', 'deer', 'dog', 'duck', 'fox', 'horse', 'lion',
    'tiger', 'turtle', 'whale', 'zebra', 'panda', 'mouse', 'sheep', 'goat', 'wolf', 'otter',
    'beach', 'brook', 'cloud', 'forest', 'hill', 'lake', 'moon', 'ocean', 'rain', 'river',
    'rock', 'sand', 'snow', 'star', 'stone', 'sun', 'tree', 'valley', 'wind', 'garden',
    'bread', 'butter', 'cake', 'candy', 'cheese', 'cookie', 'honey', 'muffin', 'pizza', 'waffle',
    'book', 'chair', 'clock', 'door', 'house', 'lamp', 'paper', 'pencil', 'pillow', 'table',
    'blue', 'green', 'purple', 'silver', 'yellow', 'bright', 'happy', 'kind', 'lucky', 'sunny',
    'boat', 'bridge', 'castle', 'drum', 'feather', 'flower', 'kite', 'lantern', 'maple', 'meadow',
    'music', 'pebble', 'pocket', 'rainbow', 'ribbon', 'rocket', 'shell', 'spoon', 'window', 'winter'
)

$isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -in 4, 5
$privilegedGroups = @()
if ($isDC) {
    Import-Module ActiveDirectory
    $domain = Get-ADDomain
    $server = $domain.PDCEmulator
    $accounts = @(Get-ADUser -Filter * -Server $server -Properties MemberOf, PrimaryGroupID, Enabled |
        Where-Object { $_.SID.Value -notmatch '-502$' })
    # Include operator groups because these can confer control of a DC.
    $groupSids = @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551',
        "$($domain.DomainSID)-512", "$($domain.DomainSID)-520")
    if ($domain.DNSRoot -eq (Get-ADForest -Server $server).RootDomain) {
        $groupSids += "$($domain.DomainSID)-518", "$($domain.DomainSID)-519"
    }
    $privilegedGroups = @($groupSids | ForEach-Object { Get-ADGroup -Identity $_ -Server $server })
    $adminSids = @($privilegedGroups | ForEach-Object {
        Get-ADGroupMember -Identity $_ -Recursive -Server $server
    } | ForEach-Object { $_.SID.Value } | Sort-Object -Unique)
    $inventory = @($accounts | ForEach-Object {
        [pscustomobject]@{ Name = $_.SamAccountName; Enabled = $_.Enabled
            Administrator = ($_.SID.Value -in $adminSids -or $_.PrimaryGroupID -in 512,518,519,520,544,548,549,550,551) }
    })
    Write-Host "Domain controller: auditing domain $($domain.DNSRoot)"
} else {
    Import-Module Microsoft.PowerShell.LocalAccounts
    $accounts = @(Get-LocalUser)
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
    $userGroup = Get-LocalGroup -SID 'S-1-5-32-545'
    $members = @(Get-LocalGroupMember -Group $adminGroup)
    $foreign = @($members | Where-Object { $_.SID.Value -notin @($accounts | ForEach-Object { $_.SID.Value }) })
    if ($foreign.Count) {
        $foreign | Format-Table Name, ObjectClass | Out-Host
        throw 'Administrators includes domain/external principals or groups. Resolve these memberships before running the local account audit.'
    }
    $adminSids = @($members | ForEach-Object { $_.SID.Value })
    $inventory = @($accounts | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Enabled = $_.Enabled; Administrator = $_.SID.Value -in $adminSids }
    })
    Write-Host 'Workstation/member server: auditing local accounts only'
}
$inventory | Sort-Object Administrator, Name -Descending | Format-Table -AutoSize | Out-Host
if ($NonInteractive -and -not $PSBoundParameters.ContainsKey('AuthorizedAdmins')) {
    throw 'NonInteractive requires AuthorizedAdmins; an empty list is not accepted.'
}
$admins = @(if ($PSBoundParameters.ContainsKey('AuthorizedAdmins')) { $AuthorizedAdmins } else { read-accountlist 'Authorized administrators (comma-separated account names)' })
$users = @(if ($NonInteractive -or $PSBoundParameters.ContainsKey('AuthorizedUsers')) { $AuthorizedUsers } else { read-accountlist 'Authorized standard users (comma-separated account names; blank for none)' })
foreach ($name in (@($PreserveAccount) + @($PreservePassword))) {
    if ($name -notin $inventory.Name) { throw "Unknown preserved account: $name" }
}
if ($CredentialOutputPath -and (Test-Path -LiteralPath $CredentialOutputPath)) {
    throw 'CredentialOutputPath already exists; choose a new file.'
}
$credentialRecords = New-Object 'System.Collections.Generic.List[object]'
if (-not $admins.Count) { throw 'At least one authorized administrator is required.' }
$authorized = @($admins + $users | Sort-Object -Unique)
foreach ($name in $authorized) {
    if ($name -notin $inventory.Name) { throw "Unknown account: $name. No changes made." }
}
if (-not @($inventory | Where-Object { $_.Name -in $admins -and $_.Enabled }).Count) {
    throw 'At least one authorized administrator must already be enabled.'
}
# A primary group cannot be removed with Remove-ADGroupMember.
if ($isDC) {
    foreach ($account in $accounts) {
        if ($account.SamAccountName -notin $admins -and $account.SamAccountName -notin $PreserveAccount -and $account.PrimaryGroupID -in 512,518,519,520,544,548,549,550,551) {
            throw "Resolve privileged primary group for $($account.SamAccountName) first. No changes made."
        }
    }
}
if (-not $SkipPasswordReset) {
    $notice = if ($CredentialOutputPath) { 'Credentials are saved using host-local DPAPI encryption.' } else { 'Credential output is plaintext.' }
    Write-Warning "Password resets can break services, scheduled tasks, saved credentials, and EFS access. $notice"
}
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    # Establish authorized administrators before removing privileges from others.
    foreach ($name in $admins) {
        if ($name -in $PreserveAccount) { continue }
        $account = $accounts | Where-Object { if ($isDC) { $_.SamAccountName -eq $name } else { $_.Name -eq $name } }
        if ($PSCmdlet.ShouldProcess($name, 'Ensure administrator membership')) {
            if ($isDC) {
                Add-ADGroupMember -Identity "$($domain.DomainSID)-512" -Members $account -Server $server
            } elseif ($account.SID.Value -notin $adminSids) {
                Add-LocalGroupMember -Group $adminGroup -Member $account
            }
        }
    }
    foreach ($account in $accounts) {
        $name = if ($isDC) { $account.SamAccountName } else { $account.Name }
        if ($name -in $PreserveAccount) { Write-Warning "Preserving all settings and the password for $name; review this exception."; continue }
        $isAdmin = $name -in $admins
        $action = if ($SkipPasswordReset -or $name -in $PreservePassword) { 'Reconcile privileges and harden account; preserve password' } else { 'Reconcile privileges, harden account, and reset password' }
        if ($PSCmdlet.ShouldProcess($name, $action)) {
            if ($isDC) {
                if (-not $isAdmin) {
                    # Remove direct membership edges that lead to any privileged group.
                    foreach ($groupDN in $account.MemberOf) {
                        $group = Get-ADGroup -Identity $groupDN -Server $server
                        $leadsToPrivilege = $group.SID.Value -in $groupSids
                        if (-not $leadsToPrivilege) {
                            foreach ($privileged in $privilegedGroups) {
                                # LDAP transitive membership includes arbitrary nesting depths.
                                $escaped = $groupDN.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29')
                                $ancestors = @(Get-ADGroup -LDAPFilter "(member:1.2.840.113556.1.4.1941:=$escaped)" -Server $server)
                                if ($privileged.DistinguishedName -in @($ancestors | ForEach-Object { $_.DistinguishedName })) { $leadsToPrivilege = $true; break }
                            }
                        }
                        if ($leadsToPrivilege) { Remove-ADGroupMember -Identity $group -Members $account -Confirm:$false -Server $server }
                    }
                }
                $control = @{
                    Identity = $account; Server = $server
                    AllowReversiblePasswordEncryption = $false; DoesNotRequirePreAuth = $false
                    UseDESKeyOnly = $false; PasswordNotRequired = $false; PasswordNeverExpires = $false
                    TrustedForDelegation = $false; TrustedToAuthForDelegation = $false
                }
                if ($isAdmin) { $control.AccountNotDelegated = $true }
                Set-ADAccountControl @control
                Set-ADUser -Identity $account -Server $server -CannotChangePassword $false -Clear 'msDS-AllowedToDelegateTo'
                if ($name -notin $authorized) { Disable-ADAccount -Identity $account -Server $server }
            } else {
                if (-not $isAdmin -and $account.SID.Value -in $adminSids) {
                    if ($account.SID.Value -match '-500$') {
                        Write-Warning "Windows requires the built-in Administrator to remain in Administrators. It will be disabled unless authorized: $name"
                    } else {
                        Remove-LocalGroupMember -Group $adminGroup -Member $account
                    }
                }
                if ($name -in $users) {
                    $ordinaryMembers = @(Get-LocalGroupMember -Group $userGroup)
                    if ($account.SID.Value -notin @($ordinaryMembers | ForEach-Object { $_.SID.Value })) { Add-LocalGroupMember -Group $userGroup -Member $account }
                }
                Set-LocalUser -InputObject $account -PasswordNeverExpires $false -UserMayChangePassword $true
                if ($name -notin $authorized) { Disable-LocalUser -InputObject $account }
            }
            if ($SkipPasswordReset -or $name -in $PreservePassword) { continue }
            $passphrase = new-passphrase
            $password = ConvertTo-SecureString $passphrase -AsPlainText -Force
            try {
                if ($isDC) { Set-ADAccountPassword -Identity $account -Server $server -Reset -NewPassword $password }
                else { Set-LocalUser -InputObject $account -Password $password }
            } finally { $password.Dispose() }
            # Emit immediately so credentials from earlier successful resets survive a later failure.
            if ($CredentialOutputPath) {
                # DPAPI protects this file for the executing identity on this machine.
                $credentialRecords.Add([pscredential]::new($name, (ConvertTo-SecureString $passphrase -AsPlainText -Force)))
                $credentialRecords.ToArray() | Export-Clixml -LiteralPath $CredentialOutputPath
            } else { '{0},{1}' -f $name, $passphrase }
        }
    }
} finally { $rng.Dispose() }


