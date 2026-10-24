#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Audits a writable DC and optionally reduces exposure to the bundled Impacket tools.
.DESCRIPTION
Run elevated on each writable DC. With no switches this only audits and returns
findings; it does not write reports or change the domain. -Apply enables baseline
hardening. -Apply -WhatIf previews changes without creating backups or reports.
The default display summarizes review items and shows HIGH/ERROR findings.
-Detailed shows every finding grouped by area, including remediation steps.
-PassThru returns the original finding objects for filtering or CSV/JSON export.
Domain changes replicate; registry/service changes affect only the current DC.
GPO can overwrite local settings. Review effective policy after its next refresh.

Baseline: SMB signing/SMB1 removal, LDAP signing/channel binding, NTLMv2,
WDigest/anonymous restrictions, Netlogon protection, Spooler/RemoteRegistry
disablement, machine-account quota zero, preauthentication, DES/reversible
encryption flags, password policy, and security auditing. Legacy clients may fail.
Existing passwords do not become strong merely by changing policy or AES flags.

Optional changes require explicit identities: service-account password rotation,
delegation removal, key-credential removal, exposed AD password-field clearing,
and removal of explicit domain replication grants. Legitimate delegation, Hello,
sync/backup systems and services can depend on these settings. Inherited or
GenericAll replication access is reported for manual correction at its source.
No krbtgt reset, mass account disablement, GPO deletion, firewall port blocking,
ticket/hash extraction, password cracking or task deletion is performed.

Reviewed bundled examples (70 tools), grouped by function and control:
  GetNPUsers: AS-REP roasting -> require preauthentication.
  GetUserSPNs: Kerberoasting -> SPN review, random passwords/gMSA, AES.
  ntlmrelayx, CheckLDAPStatus, DumpNTLMInfo: relay/security discovery ->
    SMB signing, LDAP signing/CBT, CA/HTTP/SQL/RPC EPA and patch review.
  addcomputer, badsuccessor: computer/dMSA creation -> quota, OU ACLs, patches.
  findDelegation, rbcd, getST, getPac: delegation/ticket operations ->
    review constrained/unconstrained/RBCD rights and protect privileged users.
  dacledit, owneredit, changepasswd, net: AD control -> owners/ACLs/memberships.
  GetLAPSPassword, Get-GPPPassword: exposed secrets -> reader ACLs, GPP cleanup.
  secretsdump, regsecrets, dpapidump: credential extraction -> replication ACLs,
    privileged identity protection, remote management controls, backup security.
  psexec, smbexec, wmiexec, dcomexec, atexec, services, reg, wmipersist,
    wmiquery, mimikatz: execution/persistence -> admin rights, Defender, service,
    task/WMI inventory. Disabling a service alone cannot stop an administrator.
  ticketer, raiseChild, goldenPac, keylistattack, kintercept: forged tickets,
    trust escalation, RODC keys, protocol CVEs -> patches and key recovery.
  GetADUsers, GetADComputers, lookupsid, samrdump, rpcdump, rpcmap, getArch,
    machine_role, netview: discovery -> anonymous restrictions and least privilege;
    authenticated discovery cannot be generally disabled without breaking AD.
  smbclient, attrib, filetime: authenticated file operations -> share/NTFS rights.
  smbserver, karmaSMB: rogue SMB endpoints -> client signing/name-poisoning controls.
  rdp_check, tstool: RDP/authentication/session operations -> NLA/admin rights.
  mssqlclient, mssqlinstance, checkMSSQLStatus, exchanger, mqtt_check:
    application access/discovery -> application-specific patch/auth/EPA review.
  sambaPipe: Samba CVE-2017-7494 -> patch Samba servers; not a Windows DC setting.
  dpapi, esentutl, ntfs-read, registry-read, samedit: offline data readers/editors ->
    protect stolen hives, volumes, DPAPI keys and backups; host settings cannot
    retroactively protect data already copied by an attacker.
  getTGT, ticketConverter, describeTicket: normal ticket requests/conversion/
    analysis -> credential protection; no separate tool-blocking registry switch.
  ping, ping6, sniff, sniffer, split: connectivity/packet utilities -> network
    segmentation and transport encryption; not direct DC compromises.
Also reviewed ntlmrelayx LDAP, SMB, DCSync, RPC, HTTP/ADCS/SCCM, SQL and WinRM
attack handlers. Remote CA, SCCM, SQL, Exchange and MQTT configuration remains
an explicit application-owner follow-up, not claimed to be fixed by DC settings.

On -Apply, state backups are DPAPI encrypted for this Windows identity on this
machine in a unique SYSTEM/Administrators-only directory. Rotated passwords are
saved BEFORE resetting AD; recover using the same identity/machine:
  $s = Get-Content <credential-file> | ConvertTo-SecureString
  $c = New-Object PSCredential('umd\service-account', $s)
  $c.GetNetworkCredential().Password
Update every dependent service, task, application and secret store immediately.
There is no automatic rollback of password resets or domain changes.

Password checks are indicators, not an offline strength assessment. SYSVOL and
NETLOGON text scanning is heuristic and bounded to 2 MB per file. It does not
cover every disk, share, registry value, application database or backup. Reports
never include matched password text. Findings describe the pre-change state;
rerun without -Apply to check the resulting state.

Impacket is not a complete DC attack catalogue. A valid Domain Admin credential,
SYSTEM access, replication privilege or stolen krbtgt key defeats many of these
controls. Compromise requires incident response and coordinated credential/key
rotation. Patch every DC; this script does not install updates or prove CVE fixes.
.EXAMPLE
.\dc-impacket-hardening.ps1
.EXAMPLE
.\dc-impacket-hardening.ps1 -Detailed
.EXAMPLE
.\dc-impacket-hardening.ps1 -PassThru | Export-Csv .\dc-audit.csv -NoTypeInformation
.EXAMPLE
.\dc-impacket-hardening.ps1 -Apply -WhatIf
.EXAMPLE
.\dc-impacket-hardening.ps1 -Apply
.EXAMPLE
.\dc-impacket-hardening.ps1 -Apply -RotateServiceAccount svc_sql -ServicePasswordLength 40
.EXAMPLE
.\dc-impacket-hardening.ps1 -Apply -ClearDelegationOn old_svc -RemoveReplicationGrantFrom S-1-5-21-111-222-333-1234
.LINK
https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
.LINK
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding
.LINK
https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [switch]$Detailed,
    [switch]$PassThru,
    [switch]$Apply,
    [string[]]$RotateServiceAccount = @(),
    [ValidateRange(30, 128)][int]$ServicePasswordLength = 40,
    [string[]]$ClearDelegationOn = @(),
    [string[]]$ClearKeyCredentialOn = @(),
    [string[]]$ClearPasswordAttributesOn = @(),
    [string[]]$RemoveReplicationGrantFrom = @(),
    [switch]$RemoveGppPasswords,
    [switch]$EnableLsaProtection,
    [switch]$EnableDefenderAsr,
    [switch]$ScanUpdates,
    [ValidateRange(1, 3650)][int]$ServicePasswordMaxAgeDays = 90,
    [string]$BackupRoot = "$env:ProgramData\CCDC\DC-Impacket"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Caller = $PSCmdlet
$script:Findings = New-Object 'System.Collections.Generic.List[object]'
$script:BackupDirectory = $null
$script:Sequence = 0
$script:Failures = 0

function Add-Finding {
    param([string]$Area, [string]$Target, [string]$Risk, [string]$Detail, [string]$NextStep)
    $script:Findings.Add([pscustomobject]@{
        Area = $Area; Target = $Target; Risk = $Risk; Detail = $Detail; NextStep = $NextStep
    })
}
function Get-DisplayTarget {
    param([string]$Target)
    if ($Target.StartsWith('HKLM:\')) { return ($Target -split '\\')[-1] }
    if ($Target -match '^(?:CN|OU)=([^,]+),') { return $Matches[1] }
    return $Target
}
function Show-AuditReport {
    param([object[]]$Findings)
    Write-Host ''
    Write-Host 'DC AUDIT RESULTS' -ForegroundColor Cyan
    Write-Host "$script:Server | $($Findings.Count) observations | $script:Failures failed checks/changes"
    $counts = foreach ($risk in 'ERROR', 'HIGH', 'REVIEW', 'INFO', 'SKIPPED', 'CHANGED') {
        $count = @($Findings | Where-Object Risk -eq $risk).Count
        if ($count) { "$risk`: $count" }
    }
    Write-Host ($counts -join '   |   ')
    Write-Host 'REVIEW items are candidates for investigation, not confirmed vulnerabilities.'
    foreach ($finding in $Findings | Where-Object Area -eq 'Account inventory') {
        Write-Host $finding.Detail
    }
    if ($Detailed) {
        foreach ($group in $Findings | Group-Object Area | Sort-Object Name) {
            Write-Host "`n$($group.Name) ($($group.Count))" -ForegroundColor Cyan
            Write-Host (($group.Group | Select-Object Risk, Target, Detail, NextStep | Format-List | Out-String -Width 120).TrimEnd())
        }
    } else {
        $urgent = @($Findings | Where-Object { $_.Risk -in 'ERROR', 'HIGH' } | Sort-Object @{ Expression = { if ($_.Risk -eq 'ERROR') { 0 } else { 1 } } }, Area, Target)
        if ($urgent.Count) {
            Write-Host "`nHIGH PRIORITY / FAILED CHECKS" -ForegroundColor Yellow
            $rows = $urgent | Select-Object Risk, Area, @{ Name = 'Target'; Expression = { Get-DisplayTarget $_.Target } }, Detail
            Write-Host (($rows | Format-Table -Wrap -AutoSize | Out-String -Width 120).TrimEnd())
        } else { Write-Host "`nNo HIGH or ERROR findings. Review the remaining observations." }
        $review = @($Findings | Where-Object Risk -eq 'REVIEW' | Group-Object Area | Sort-Object Name)
        if ($review.Count) {
            Write-Host "`nCONFIGURATION / MANUAL REVIEW" -ForegroundColor Cyan
            $rows = foreach ($group in $review) {
                $examples = @($group.Group | ForEach-Object { Get-DisplayTarget $_.Target } | Select-Object -Unique -First 2)
                [pscustomobject]@{ Area = $group.Name; Items = $group.Count; Examples = $examples -join ', ' }
            }
            Write-Host (($rows | Format-Table -Wrap -AutoSize | Out-String -Width 120).TrimEnd())
        }
        $other = @($Findings | Where-Object { $_.Risk -in 'INFO', 'SKIPPED', 'CHANGED' } | Group-Object Area | Sort-Object Name)
        if ($other.Count) {
            Write-Host "`nINVENTORY / CHANGE SUMMARY" -ForegroundColor Cyan
            $rows = foreach ($group in $other) {
                [pscustomobject]@{ Area = $group.Name; Items = $group.Count; Status = ($group.Group.Risk | Select-Object -Unique) -join ', ' }
            }
            Write-Host (($rows | Format-Table -AutoSize | Out-String -Width 120).TrimEnd())
        }
        Write-Host "`nUse -Detailed for full targets, evidence and next steps; -PassThru for filtering/export."
    }
    Write-Host 'Findings reflect the pre-change state. Rerun after changes; this is not proof of complete protection.'
}
function Invoke-Check {
    param([string]$Name, [scriptblock]$Action)
    try { & $Action }
    catch {
        $script:Failures++
        Add-Finding $Name $env:COMPUTERNAME 'ERROR' $_.Exception.Message 'Check failed; this area has NOT been verified.'
        Write-Warning "$Name failed: $($_.Exception.Message)"
    }
}
function Save-State {
    param([string]$Name, [object]$Value)
    if (-not $script:BackupDirectory) {
        if (-not [IO.Path]::IsPathRooted($BackupRoot) -or $BackupRoot.StartsWith('\\')) {
            throw 'BackupRoot must be an absolute local path.'
        }
        # Reject reparse-point ancestors before writing sensitive recovery material.
        $ancestor = [IO.DirectoryInfo]$BackupRoot
        while ($null -ne $ancestor) {
            if ($ancestor.Exists -and ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Backup path contains a reparse point: $($ancestor.FullName)"
            }
            $ancestor = $ancestor.Parent
        }
        $path = Join-Path $BackupRoot ((Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $path -Force -WhatIf:$false
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sidText in 'S-1-5-18', 'S-1-5-32-544') {
            $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $path -AclObject $acl -WhatIf:$false
        $script:BackupDirectory = $path
        Write-Host "Encrypted recovery files: $path"
    }
    $script:Sequence++
    $file = Join-Path $script:BackupDirectory (('{0:D4}-{1}.dpapi' -f $script:Sequence, ($Name -replace '[^a-zA-Z0-9_-]', '_')))
    $json = ConvertTo-Json -InputObject $Value -Depth 12 -Compress
    $encrypted = ConvertTo-SecureString -String $json -AsPlainText -Force | ConvertFrom-SecureString
    [IO.File]::WriteAllText($file, $encrypted)
}
function Invoke-Fix {
    param([string]$Target, [string]$Description, [scriptblock]$Action)
    if ($Apply -and $script:Caller.ShouldProcess($Target, $Description)) {
        try {
            & $Action
            Add-Finding 'Change' $Target 'CHANGED' $Description 'Rerun audit and test domain services; some settings require reboot.'
        } catch {
            $script:Failures++
            Add-Finding 'Change' $Target 'ERROR' "$Description failed: $($_.Exception.Message)" 'Partial changes may exist; inspect encrypted backups.'
            Write-Warning "$Description failed for ${Target}: $($_.Exception.Message)"
        }
    }
}
function Test-RegistrySetting {
    param([string]$Path, [string]$Name, [int]$Value, [string]$Area)
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    $current = if ($key) { $key.GetValue($Name, $null) } else { $null }
    if ($null -eq $current -or $current -ne $Value) {
        Add-Finding $Area "$Path\$Name" 'REVIEW' "Current=$current; required=$Value (absent values may have OS defaults)." 'Apply baseline and verify effective policy.'
        Invoke-Fix "$Path\$Name" "Set DWORD to $Value" {
            Save-State 'registry' @{ Path = $Path; Name = $Name; Value = $current; Existed = ($null -ne $current) }
            if (-not (Test-Path -LiteralPath $Path)) { $null = New-Item -Path $Path -Force }
            $null = New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force
            if ((Get-ItemPropertyValue -LiteralPath $Path -Name $Name) -ne $Value) { throw 'Registry readback failed.' }
        }
    }
}
function Get-Attribute {
    param([object]$Object, [string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property -and $null -ne $property.Value) {
        foreach ($value in $property.Value) { if ($null -ne $value) { $value } }
    }
}
function Get-DirectoryEntry {
    param([string]$DN)
    $entry = New-Object DirectoryServices.DirectoryEntry("LDAP://$script:Server/$DN")
    $entry.psbase.AuthenticationType = [DirectoryServices.AuthenticationTypes]::Secure -bor [DirectoryServices.AuthenticationTypes]::Signing -bor [DirectoryServices.AuthenticationTypes]::Sealing
    $entry.psbase.Options.SecurityMasks = [DirectoryServices.SecurityMasks]::Dacl -bor [DirectoryServices.SecurityMasks]::Owner
    return $entry
}
function Resolve-Account {
    param([string]$Identity)
    # Resolve names with AD's identity parser; no interpolation into an LDAP filter.
    try { return Get-ADUser -Identity $Identity -Server $script:Server -Properties ServicePrincipalName }
    catch {
        try { return Get-ADComputer -Identity $Identity -Server $script:Server }
        catch { return Get-ADObject -Identity $Identity -Server $script:Server }
    }
}

$computer = Get-CimInstance Win32_ComputerSystem
if ($computer.DomainRole -notin 4, 5) { throw 'Run this script locally on a domain controller.' }
Import-Module ActiveDirectory
$script:Server = $env:COMPUTERNAME
$dc = Get-ADDomainController -Identity $script:Server -Server $script:Server
if ($dc.IsReadOnly) { throw 'A writable DC is required.' }
$domain = Get-ADDomain -Server $script:Server
$rootDse = Get-ADRootDSE -Server $script:Server
$domainSid = $domain.DomainSID.Value
$forest = Get-ADForest -Server $script:Server
$forestDomain = Get-ADDomain -Identity $forest.RootDomain -Server $script:Server
$trustedSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9', "$domainSid-500", "$domainSid-512", "$domainSid-516", "$domainSid-521", "$($forestDomain.DomainSID.Value)-498", "$($forestDomain.DomainSID.Value)-519")
$replicationGuids = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c')
Write-Host "DC: $script:Server; domain: $($domain.DNSRoot); Apply=$Apply; WhatIf=$WhatIfPreference"
Write-Host 'Audit findings are pre-change observations. Rerun after remediation and after GPO refresh.'
if ($Apply) { Write-Warning 'Signing/channel binding and service changes can break legacy clients. Domain changes replicate. No automatic reboot.' }

Invoke-Check 'Relay and credential baseline' {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $netlogon = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    foreach ($item in @(
        @($ntds, 'LDAPServerIntegrity', 2, 'LDAP relay'),
        @($ntds, 'LdapEnforceChannelBinding', 2, 'LDAPS relay'),
        @($lsa, 'LmCompatibilityLevel', 5, 'NTLMv1'),
        @($lsa, 'NoLMHash', 1, 'LM hashes'),
        @($lsa, 'RestrictAnonymous', 1, 'Anonymous enumeration'),
        @($lsa, 'RestrictAnonymousSAM', 1, 'Anonymous enumeration'),
        @($lsa, 'EveryoneIncludesAnonymous', 0, 'Anonymous enumeration'),
        @($lsa, 'SCENoApplyLegacyAuditPolicy', 1, 'Audit'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential', 0, 'Cleartext credentials'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', 'EnableMulticast', 0, 'Name poisoning'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation', 'AllowInsecureGuestAuth', 0, 'SMB guest'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp', 'UserAuthentication', 1, 'RDP'),
        @($netlogon, 'FullSecureChannelProtection', 1, 'Netlogon'),
        @($netlogon, 'RequireSignOrSeal', 1, 'Netlogon'),
        @($netlogon, 'SealSecureChannel', 1, 'Netlogon'),
        @($netlogon, 'SignSecureChannel', 1, 'Netlogon')
    )) { Test-RegistrySetting $item[0] $item[1] $item[2] $item[3] }
    if ($EnableLsaProtection) {
        Write-Warning 'RunAsPPL=1 needs reboot and can set a UEFI lock. Test LSA plug-in compatibility first.'
        Test-RegistrySetting $lsa 'RunAsPPL' 1 'LSASS protection'
    } else {
        $ppl = Get-ItemProperty -LiteralPath $lsa -Name RunAsPPL -ErrorAction SilentlyContinue
        Add-Finding 'LSASS protection' $script:Server 'REVIEW' "RunAsPPL configured: $($null -ne $ppl). Registry alone does not prove runtime protection." 'Use -EnableLsaProtection after compatibility review; verify WinInit event 12 after reboot.'
    }
    $key = Get-Item -LiteralPath $netlogon
    if ('VulnerableChannelAllowList' -in $key.GetValueNames()) {
        Add-Finding 'Netlogon' $script:Server 'HIGH' 'Vulnerable secure-channel exceptions exist.' 'Remove exceptions and patch incompatible clients.'
        Invoke-Fix $netlogon 'Remove vulnerable secure-channel allowlist' {
            Save-State 'netlogon-exceptions' @{ Path = $netlogon; Value = $key.GetValue('VulnerableChannelAllowList') }
            Remove-ItemProperty -LiteralPath $netlogon -Name VulnerableChannelAllowList
        }
    }
    $smb = Get-SmbServerConfiguration
    if ($smb.EnableSMB1Protocol -or -not $smb.RequireSecuritySignature) {
        Add-Finding 'SMB relay' $script:Server 'HIGH' 'SMB1 enabled or server signing not required.' 'Disable SMB1; require SMB signing.'
        Invoke-Fix 'SMB server' 'Disable SMB1 and require signing; preserve SMB2/3' {
            Save-State 'smb-server' ($smb | Select-Object EnableSMB1Protocol, RequireSecuritySignature)
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Confirm:$false
            $verify = Get-SmbServerConfiguration
            if ($verify.EnableSMB1Protocol -or -not $verify.RequireSecuritySignature) { throw 'SMB server readback failed.' }
        }
    }
    $client = Get-SmbClientConfiguration
    if (-not $client.RequireSecuritySignature) {
        Add-Finding 'SMB relay' $script:Server 'HIGH' 'SMB client signing not required.' 'Require SMB client signing.'
        Invoke-Fix 'SMB client' 'Require signing' {
            Save-State 'smb-client' ($client | Select-Object RequireSecuritySignature)
            Set-SmbClientConfiguration -RequireSecuritySignature $true -Confirm:$false
        }
    }
    foreach ($name in 'Spooler', 'RemoteRegistry') {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$name'"
        if ($svc -and ($svc.StartMode -ne 'Disabled' -or $svc.State -eq 'Running')) {
            Add-Finding 'Remote execution/coercion' $name 'HIGH' "StartMode=$($svc.StartMode); State=$($svc.State)." 'Disable on DC unless explicitly needed. Admins can reenable services.'
            Invoke-Fix $name 'Stop and disable service' {
                Save-State 'service' ($svc | Select-Object Name, StartMode, State)
                Stop-Service -Name $name -Force
                Set-Service -Name $name -StartupType Disabled
            }
        }
    }
}

Invoke-Check 'Password policy' {
    $policy = Get-ADDefaultDomainPasswordPolicy -Server $script:Server
    Add-Finding 'Password policy' $domain.DNSRoot 'INFO' "MinLength=$($policy.MinPasswordLength); Complexity=$($policy.ComplexityEnabled); Reversible=$($policy.ReversibleEncryptionEnabled)." 'Policy cannot validate existing password strength. Check fine-grained policies too.'
    if ($policy.MinPasswordLength -lt 14 -or -not $policy.ComplexityEnabled -or $policy.ReversibleEncryptionEnabled) {
        Invoke-Fix $domain.DNSRoot 'Require minimum 14 characters, complexity and no reversible encryption; preserve stronger length' {
            Save-State 'domain-password-policy' ($policy | Select-Object MinPasswordLength, ComplexityEnabled, ReversibleEncryptionEnabled)
            Set-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName -Server $script:Server -MinPasswordLength ([math]::Max(14, $policy.MinPasswordLength)) -ComplexityEnabled $true -ReversibleEncryptionEnabled $false
        }
    }
    foreach ($pso in Get-ADFineGrainedPasswordPolicy -Filter * -Server $script:Server) {
        if ($pso.MinPasswordLength -lt 14 -or -not $pso.ComplexityEnabled -or $pso.ReversibleEncryptionEnabled) {
            Add-Finding 'Fine-grained password policy' $pso.DistinguishedName 'HIGH' 'Policy overrides the domain default with weak length/complexity or reversible storage.' 'Harden this policy and inspect its resultant users.'
            Invoke-Fix $pso.DistinguishedName 'Harden fine-grained password policy without lowering its minimum length' {
                Save-State 'fine-grained-policy' ($pso | Select-Object DistinguishedName, MinPasswordLength, ComplexityEnabled, ReversibleEncryptionEnabled)
                Set-ADFineGrainedPasswordPolicy -Identity $pso -Server $script:Server -MinPasswordLength ([math]::Max(14, $pso.MinPasswordLength)) -ComplexityEnabled $true -ReversibleEncryptionEnabled $false
            }
        }
    }
    $domainObject = Get-ADObject $domain.DistinguishedName -Server $script:Server -Properties 'ms-DS-MachineAccountQuota'
    if ($domainObject.'ms-DS-MachineAccountQuota' -ne 0) {
        Add-Finding 'Machine creation' $domain.DNSRoot 'HIGH' "MachineAccountQuota=$($domainObject.'ms-DS-MachineAccountQuota')." 'Set to zero; delegated OU creation rights still need review.'
        Invoke-Fix $domain.DNSRoot 'Set machine-account quota to zero' {
            Save-State 'machine-quota' @{ DN = $domain.DistinguishedName; Value = $domainObject.'ms-DS-MachineAccountQuota' }
            Set-ADObject $domain.DistinguishedName -Server $script:Server -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }
        }
    }
}

$schemaNames = @{}
$secretAttributeGuids = @()
foreach ($attribute in Get-ADObject -SearchBase $rootDse.SchemaNamingContext -LDAPFilter '(objectClass=attributeSchema)' -Properties lDAPDisplayName, schemaIDGUID -Server $script:Server) {
    $schemaNames[$attribute.lDAPDisplayName] = $true
    if ($attribute.lDAPDisplayName -in 'ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-EncryptedDSRMPassword', 'msDS-ManagedPassword') {
        $secretAttributeGuids += (New-Object Guid (,[byte[]]$attribute.schemaIDGUID)).ToString()
    }
}
$wanted = @('sAMAccountName', 'userAccountControl', 'pwdLastSet', 'servicePrincipalName', 'adminCount', 'description', 'info', 'msDS-SupportedEncryptionTypes', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'msDS-KeyCredentialLink', 'userPassword', 'unixUserPassword', 'msSFU30Password', 'msDS-GroupMSAMembership', 'msDS-ManagedAccountPrecededByLink', 'msDS-DelegatedMSAState', 'sIDHistory')
$properties = @($wanted | Where-Object { $schemaNames.ContainsKey($_) })
$accounts = @(Get-ADObject -LDAPFilter '(|(objectClass=user)(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-DelegatedManagedServiceAccount))' -Properties $properties -Server $script:Server)
Invoke-Check 'Account exposure' {
    $spnUsers = @($accounts | Where-Object { $_.ObjectClass -eq 'user' -and -not ([int](Get-Attribute $_ 'userAccountControl') -band 2) -and @(Get-Attribute $_ 'servicePrincipalName').Count })
    $asrepUsers = @($accounts | Where-Object { [int](Get-Attribute $_ 'userAccountControl') -band 4194304 })
    Add-Finding 'Account inventory' $domain.DNSRoot 'INFO' "Accounts inspected=$($accounts.Count); enabled user SPN accounts=$($spnUsers.Count); accounts without preauthentication=$($asrepUsers.Count)." 'Every enabled user SPN account is a Kerberoasting candidate. Password strength remains unknown until managed/rotated or separately assessed.'
    foreach ($account in $accounts) {
        $dn = $account.DistinguishedName
        $uac = [int](Get-Attribute $account 'userAccountControl')
        $enabled = -not ($uac -band 2)
        $isUser = $account.ObjectClass -eq 'user'
        $spns = @(Get-Attribute $account 'servicePrincipalName')
        if ($enabled -and $isUser -and $spns.Count) {
            $rawDate = [long](Get-Attribute $account 'pwdLastSet')
            $age = if ($rawDate -gt 0) { [int]((Get-Date) - [DateTime]::FromFileTimeUtc($rawDate)).TotalDays } else { -1 }
            $enc = [int](Get-Attribute $account 'msDS-SupportedEncryptionTypes')
            Add-Finding 'Kerberoasting' $dn 'HIGH' "Enabled user with $($spns.Count) SPN(s); password age=$age days; encryption mask=$enc; neverExpires=$([bool]($uac -band 65536)); adminCount=$(Get-Attribute $account 'adminCount')." 'Prefer gMSA; otherwise rotate to a unique random 30+ character password, update dependencies and test AES. AES alone does not prevent roasting.'
            if ($age -lt 0 -or $age -gt $ServicePasswordMaxAgeDays) {
                Add-Finding 'Service password age' $dn 'HIGH' 'Service password is unset or older than the configured review interval.' 'Use targeted rotation; age does not prove a password is weak.'
            }
        }
        foreach ($flag in @(
            @{ Mask = 4194304; Name = 'AS-REP roasting'; Parameter = 'DoesNotRequirePreAuth' },
            @{ Mask = 128; Name = 'Reversible encryption'; Parameter = 'AllowReversiblePasswordEncryption' },
            @{ Mask = 2097152; Name = 'DES-only Kerberos'; Parameter = 'UseDESKeyOnly' }
        )) {
            if ($uac -band $flag.Mask) {
                Add-Finding $flag.Name $dn 'HIGH' 'Unsafe account flag set.' 'Clear flag; rotate previously exposed passwords and test service compatibility.'
                Invoke-Fix $dn "Clear $($flag.Parameter)" {
                    Save-State 'account-uac' @{ DN = $dn; userAccountControl = $uac }
                    $arguments = @{ Identity = $dn; Server = $script:Server }
                    $arguments[$flag.Parameter] = $false
                    Set-ADAccountControl @arguments
                }
            }
        }
        if ($enabled -and ($uac -band 32)) { Add-Finding 'Password not required' $dn 'HIGH' 'PASSWD_NOTREQD flag set; this does not establish that the password is blank.' 'Investigate provisioning and set a strong password before clearing the flag.' }
        if (($uac -band 524288) -or ($uac -band 16777216) -or @(Get-Attribute $account 'msDS-AllowedToDelegateTo').Count -or @(Get-Attribute $account 'msDS-AllowedToActOnBehalfOfOtherIdentity').Count) {
            $risk = if ($account.ObjectClass -eq 'computer' -and ($uac -band 8192)) { 'REVIEW' } else { 'HIGH' }
            Add-Finding 'Delegation' $dn $risk 'Delegation flags, constrained targets or RBCD descriptor present. DC unconstrained delegation is expected.' 'Review principals/targets; -ClearDelegationOn removes delegation only on explicitly named non-DC accounts.'
        }
        if (@(Get-Attribute $account 'msDS-KeyCredentialLink').Count) { Add-Finding 'Key credentials' $dn 'REVIEW' 'Key credentials present; can be legitimate Windows Hello or shadow credentials.' 'Validate provenance and write ACLs; explicitly remove unauthorized entries only.' }
        if (@(Get-Attribute $account 'sIDHistory').Count) { Add-Finding 'SID history' $dn 'REVIEW' 'SID history exists.' 'Validate migrations and forest trust boundaries; do not blindly erase migration data.' }
        foreach ($field in 'userPassword', 'unixUserPassword', 'msSFU30Password', 'description', 'info') {
            $value = @(Get-Attribute $account $field)
            if (-not $value.Count) { continue }
            if ($field -in 'description', 'info' -and ($value -join ' ') -notmatch '(?i)(password|passwd|pwd|secret|credential)\s*[:=]') { continue }
            Add-Finding 'Exposed password field' "$dn [$field]" 'HIGH' 'Password-bearing attribute or credential-like metadata detected; value suppressed.' 'Rotate the exposed secret, then clear the field with -ClearPasswordAttributesOn after review.'
        }
        if ($account.ObjectClass -match 'ManagedServiceAccount$') {
            Add-Finding 'Managed service account' $dn 'REVIEW' "Class=$($account.ObjectClass); password-reader descriptor present=$(@(Get-Attribute $account 'msDS-GroupMSAMembership').Count -gt 0); predecessor=$(Get-Attribute $account 'msDS-ManagedAccountPrecededByLink')." 'Review password-reader principals and dMSA predecessor/migration state; patch BadSuccessor and restrict OU CreateChild rights.'
            $readerValue = Get-Attribute $account 'msDS-GroupMSAMembership'
            if ($null -ne $readerValue) {
                $bytes = if ($readerValue -is [DirectoryServices.ActiveDirectorySecurity]) { $readerValue.GetSecurityDescriptorBinaryForm() } else { [byte[]]$readerValue }
                $readerAcl = New-Object Security.AccessControl.RawSecurityDescriptor($bytes, 0)
                foreach ($ace in $readerAcl.DiscretionaryAcl) {
                    if ($ace.AceType.ToString() -like 'AccessAllowed*') {
                        Add-Finding 'Managed password reader' $dn 'REVIEW' "Reader SID=$($ace.SecurityIdentifier.Value); access mask=$($ace.AccessMask)." 'Resolve group membership; only authorized service hosts should retrieve this managed password.'
                    }
                }
            }
        }
    }
}

Invoke-Check 'Targeted account remediation' {
    foreach ($identity in $ClearDelegationOn) {
        $account = Resolve-Account $identity
        $current = Get-ADObject $account.DistinguishedName -Server $script:Server -Properties userAccountControl, 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity'
        if ([int]$current.userAccountControl -band 8192) { throw "Refusing to remove expected DC delegation: $identity" }
        Invoke-Fix $account.DistinguishedName 'Remove unconstrained/protocol-transition/constrained/resource-based delegation' {
            Save-State 'delegation' $current
            Set-ADAccountControl -Identity $account.DistinguishedName -Server $script:Server -TrustedForDelegation $false -TrustedToAuthForDelegation $false
            $clear = @('msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity' | Where-Object { @(Get-Attribute $current $_).Count })
            if ($clear.Count) { Set-ADObject $account.DistinguishedName -Server $script:Server -Clear $clear }
        }
    }
    foreach ($identity in $ClearKeyCredentialOn) {
        $account = Resolve-Account $identity
        $current = Get-ADObject $account.DistinguishedName -Server $script:Server -Properties 'msDS-KeyCredentialLink'
        if (@(Get-Attribute $current 'msDS-KeyCredentialLink').Count) {
            Invoke-Fix $account.DistinguishedName 'Clear ALL key credentials on this explicitly selected account (including legitimate Hello keys)' {
                Save-State 'key-credentials' $current
                Set-ADObject $account.DistinguishedName -Server $script:Server -Clear 'msDS-KeyCredentialLink'
            }
        }
    }
    foreach ($identity in $ClearPasswordAttributesOn) {
        $account = Resolve-Account $identity
        $fields = @('userPassword', 'unixUserPassword', 'msSFU30Password', 'description', 'info' | Where-Object { $schemaNames.ContainsKey($_) })
        $current = Get-ADObject $account.DistinguishedName -Server $script:Server -Properties $fields
        $clear = @($fields | Where-Object {
            $value = @(Get-Attribute $current $_)
            $value.Count -and ($_ -notin 'description', 'info' -or ($value -join ' ') -match '(?i)(password|passwd|pwd|secret|credential)\s*[:=]')
        })
        if ($clear.Count) {
            Invoke-Fix $account.DistinguishedName "Clear exposed attributes: $($clear -join ', ')" {
                Save-State 'exposed-attributes' $current
                Set-ADObject $account.DistinguishedName -Server $script:Server -Clear $clear
            }
        }
    }
    foreach ($identity in $RotateServiceAccount) {
        $account = Get-ADUser -Identity $identity -Server $script:Server -Properties ServicePrincipalName, Enabled, 'msDS-SupportedEncryptionTypes'
        if ($account.SamAccountName -eq 'krbtgt' -or -not $account.Enabled -or -not @($account.ServicePrincipalName).Count) { throw "Rotation requires an enabled user service account with an SPN: $identity" }
        Invoke-Fix $account.DistinguishedName 'Generate and save a unique random password, reset service account and enable AES128/AES256 only' {
            Save-State 'service-encryption' ($account | Select-Object DistinguishedName, 'msDS-SupportedEncryptionTypes')
            $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#%+-_'
            $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
            try {
                # Rejection sampling avoids modulo bias. Retry until all categories exist.
                do {
                    $builder = New-Object Text.StringBuilder
                    $byte = New-Object byte[] 1
                    while ($builder.Length -lt $ServicePasswordLength) {
                        $rng.GetBytes($byte)
                        if ($byte[0] -lt ([math]::Floor(256 / $alphabet.Length) * $alphabet.Length)) { $null = $builder.Append($alphabet[$byte[0] % $alphabet.Length]) }
                    }
                    $password = $builder.ToString()
                } until ($password -cmatch '[a-z]' -and $password -cmatch '[A-Z]' -and $password -match '[0-9]' -and $password -match '[!#%+\-_]')
                $secure = ConvertTo-SecureString $password -AsPlainText -Force
                $credentialFile = Join-Path $script:BackupDirectory ("credential-$($account.SamAccountName -replace '[^a-zA-Z0-9_-]', '_')-$([guid]::NewGuid().ToString('N')).dpapi")
                [IO.File]::WriteAllText($credentialFile, ($secure | ConvertFrom-SecureString))
                Set-ADAccountPassword -Identity $account -Server $script:Server -Reset -NewPassword $secure
                Set-ADUser -Identity $account -Server $script:Server -KerberosEncryptionType AES128, AES256
                Write-Warning "Rotated $($account.SamAccountName). Update all dependencies now. Recover password from $credentialFile using this identity and machine."
            } finally { $rng.Dispose(); $password = $null; $secure = $null }
        }
    }
}

Invoke-Check 'AD ACLs and DCSync' {
    $objects = @(Get-ADObject -LDAPFilter '(|(objectClass=domainDNS)(objectClass=organizationalUnit)(objectClass=user)(objectClass=group)(objectClass=computer)(name=AdminSDHolder))' -Server $script:Server)
    foreach ($object in $objects) {
        $entry = Get-DirectoryEntry $object.DistinguishedName
        try {
            $acl = $entry.psbase.ObjectSecurity
            $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            if ($object.DistinguishedName -eq $domain.DistinguishedName -or $object.Name -eq 'AdminSDHolder') {
                Add-Finding 'AD owner' $object.DistinguishedName 'REVIEW' "Owner SID: $owner" 'Verify ownership; WriteOwner can grant DACL control.'
            }
            foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $sid = $ace.IdentityReference.Value
                if ($sid -in $trustedSids -or $sid -eq 'S-1-5-10') { continue }
                $rights = $ace.ActiveDirectoryRights
                $guid = $ace.ObjectType.ToString()
                $inheritOnly = [bool]($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)
                $domainGrant = $object.DistinguishedName -eq $domain.DistinguishedName -and -not $inheritOnly
                $replication = $domainGrant -and (($rights -band [DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [DirectoryServices.ActiveDirectoryRights]::GenericAll -or (($rights -band [DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and ($guid -in $replicationGuids -or $guid -eq [guid]::Empty.ToString())))
                $dangerous = ($rights -band ([DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor [DirectoryServices.ActiveDirectoryRights]::WriteOwner -bor [DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor [DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [DirectoryServices.ActiveDirectoryRights]::ExtendedRight)) -ne 0
                if ($guid -in $secretAttributeGuids -and ($rights -band ([DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [DirectoryServices.ActiveDirectoryRights]::ExtendedRight))) {
                    Add-Finding 'LAPS/managed-password read ACL' $object.DistinguishedName 'REVIEW' "Trustee=$sid; rights=$rights; sensitive attribute GUID=$guid; inherited=$($ace.IsInherited)." 'Resolve group membership and confidential-attribute access rules; restrict readers. Password values were not requested.'
                }
                if ($replication -or $dangerous) {
                    $area = if ($replication) { 'Replication ACL' } else { 'AD write/control ACL' }
                    Add-Finding $area $object.DistinguishedName 'REVIEW' "Trustee=$sid; rights=$rights; objectType=$guid; inherited=$($ace.IsInherited); inheritOnly=$inheritOnly. Candidate grant, not an effective-access verdict." 'Validate group membership and delegation. Inspect SPN/key credential/RBCD writes, reset-password rights, LAPS/gMSA readers and OU creation.'
                }
            }
        } finally { $entry.psbase.Dispose() }
    }
    foreach ($sidText in $RemoveReplicationGrantFrom) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        if ($sid.Value -in $trustedSids) { throw "Refusing to remove core replication/admin SID $sidText" }
        $targetComputer = $null
        try { $targetComputer = Get-ADComputer -Identity $sid.Value -Server $script:Server -Properties userAccountControl }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { }
        if ($targetComputer -and ([int]$targetComputer.userAccountControl -band 8192)) { throw "Refusing to remove a domain controller replication grant: $sidText" }
        Invoke-Fix $domain.DistinguishedName "Remove explicit replication/all-extended-right ACEs for $sidText (preserve GenericAll and inherited ACEs for manual review)" {
            $entry = Get-DirectoryEntry $domain.DistinguishedName
            try {
                $acl = $entry.psbase.ObjectSecurity
                Save-State 'domain-acl' @{ DN = $domain.DistinguishedName; SDDL = $acl.GetSecurityDescriptorSddlForm('All') }
                $removed = 0
                foreach ($ace in $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
                    if ($ace.IdentityReference.Value -eq $sid.Value -and $ace.AccessControlType -eq 'Allow' -and
                        $ace.ActiveDirectoryRights -eq [DirectoryServices.ActiveDirectoryRights]::ExtendedRight -and
                        ($ace.ObjectType.ToString() -in $replicationGuids -or $ace.ObjectType -eq [guid]::Empty)) {
                        $acl.RemoveAccessRuleSpecific($ace); $removed++
                    }
                }
                if ($removed) { $entry.psbase.ObjectSecurity = $acl; $entry.psbase.CommitChanges() }
                Write-Host "Removed $removed explicit extended-right ACE(s) for $sidText. Review GenericAll, ownership, write-DACL and inherited paths separately."
            } finally { $entry.psbase.Dispose() }
        }
    }
}

Invoke-Check 'SYSVOL/NETLOGON exposed credentials' {
    $roots = @(foreach ($name in 'SYSVOL', 'NETLOGON') { (Get-SmbShare -Name $name).Path }) | Select-Object -Unique
    foreach ($root in $roots) {
        foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction Stop) {
            if ($file.Extension -notin '.xml', '.ps1', '.bat', '.cmd', '.vbs', '.ini', '.config', '.txt', '.yml', '.yaml', '.json') { continue }
            if ($file.Length -gt 2MB) {
                Add-Finding 'Credential file scan' $file.FullName 'SKIPPED' 'File exceeds the 2 MB scan limit.' 'Review separately.'
                continue
            }
            $text = [IO.File]::ReadAllText($file.FullName)
            if ($text -match '(?i)cpassword\s*=\s*["''][^"'']+') {
                Add-Finding 'GPP password' $file.FullName 'HIGH' 'Decryptable cpassword found; value suppressed.' 'Rotate the secret; -RemoveGppPasswords removes cpassword attributes and preserves the rest of the XML.'
                if ($RemoveGppPasswords) {
                    Invoke-Fix $file.FullName 'Remove GPP cpassword attributes (password still needs rotation)' {
                        $xml = New-Object Xml.XmlDocument
                        $xml.XmlResolver = $null
                        $settings = New-Object Xml.XmlReaderSettings
                        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
                        $reader = [Xml.XmlReader]::Create($file.FullName, $settings)
                        try { $xml.Load($reader) } finally { $reader.Dispose() }
                        Save-State 'gpp-file' @{ Path = $file.FullName; Content = $text }
                        foreach ($node in @($xml.SelectNodes('//*[@cpassword]'))) { $node.RemoveAttribute('cpassword') }
                        $xml.Save($file.FullName)
                    }
                }
            } elseif ($text -match '(?im)(password|passwd|pwd|secret|credential)\s*[:=]\s*["'']?\S+') {
                Add-Finding 'Possible cleartext credential' $file.FullName 'REVIEW' 'Credential-like assignment detected; content suppressed. Heuristic can produce false positives.' 'Review privately, rotate real secrets and remove them from scripts/configuration.'
            }
        }
    }
    $winlogon = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ('DefaultPassword' -in $winlogon.GetValueNames()) { Add-Finding 'AutoLogon' $script:Server 'HIGH' 'Winlogon DefaultPassword registry value exists.' 'Rotate the secret, remove autologon and investigate why it was configured.' }
}

Invoke-Check 'Persistence and service dependencies' {
    foreach ($svc in Get-CimInstance Win32_Service) {
        if ($svc.StartName -and $svc.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\)' -and $svc.StartName -notmatch '\$$') {
            Add-Finding 'Service identity' $svc.Name 'REVIEW' "Logon identity=$($svc.StartName). Command line suppressed." 'Check least privilege and password ownership; update this dependency during rotation.'
        }
        if ($svc.Name -match 'RemCom|PSEXESVC') { Add-Finding 'Execution artifact' $svc.Name 'HIGH' 'Known remote execution service name found; legitimate tools can create it too.' 'Investigate binary and events before removal.' }
    }
    foreach ($task in Get-ScheduledTask) {
        if ($task.TaskPath -notlike '\Microsoft\*') { Add-Finding 'Scheduled task' ($task.TaskPath + $task.TaskName) 'REVIEW' "Principal=$($task.Principal.UserId); logonType=$($task.Principal.LogonType). Actions suppressed." 'Review author, action, credentials and creation events; preserve authorized tasks.' }
    }
    foreach ($binding in Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding) {
        Add-Finding 'WMI persistence' $script:Server 'REVIEW' "Filter=$($binding.Filter); consumer=$($binding.Consumer)." 'Validate permanent subscription; consumer payload deliberately not logged.'
    }
    foreach ($rid in 512, 518, 519) {
        $sid = if ($rid -eq 512) { "$domainSid-$rid" } else { "$($forestDomain.DomainSID.Value)-$rid" }
        $groupServer = if ($rid -eq 512) { $script:Server } else { $forest.RootDomain }
        foreach ($member in Get-ADGroupMember -Identity $sid -Recursive -Server $groupServer) {
            Add-Finding 'Privileged membership' $member.DistinguishedName 'REVIEW' "Recursive member of privileged group $sid." 'Validate every administrator; compromised authorized admins can use most execution/dumping tools.'
        }
    }
}

Invoke-Check 'AD CS and application relay' {
    $base = "CN=Public Key Services,CN=Services,$($rootDse.ConfigurationNamingContext)"
    foreach ($ca in Get-ADObject -SearchBase $base -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName, certificateTemplates -Server $script:Server) {
        Add-Finding 'AD CS relay' $ca.DistinguishedName 'REVIEW' "Enrollment CA host=$($ca.dNSHostName)." 'On this CA enforce IIS HTTPS/EPA, disable NTLM where feasible, enforce RPC enrollment encryption (IF_ENFORCEENCRYPTICERTREQUEST), review CA/template ACLs and patch. A DC-only script cannot secure a remote CA.'
    }
    foreach ($template in Get-ADObject -SearchBase $base -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', pKIExtendedKeyUsage -Server $script:Server) {
        $nameFlag = [int]$template.'msPKI-Certificate-Name-Flag'
        $approval = ([int]$template.'msPKI-Enrollment-Flag' -band 2) -ne 0
        $eku = @($template.pKIExtendedKeyUsage)
        if (($nameFlag -band 1) -and -not $approval -and [int]$template.'msPKI-RA-Signature' -eq 0 -and (-not $eku.Count -or $eku -contains '2.5.29.37.0' -or $eku -contains '1.3.6.1.5.5.7.3.2' -or $eku -contains '1.3.6.1.4.1.311.20.2.2' -or $eku -contains '1.3.6.1.5.2.3.4')) {
            Add-Finding 'Certificate template candidate' $template.DistinguishedName 'HIGH' 'Requester-supplied subject with authentication-capable EKU and no approval/signatures. Exploitability depends on publication/enrollment rights and CA enforcement.' 'Review published-template ACLs, subject supply and approval. This is a limited ESC1-style check, not a full AD CS assessment.'
        }
    }
    foreach ($svc in Get-Service | Where-Object { $_.Name -match '^(MSSQL|SQLAgent|MSExchange|W3SVC|CertSvc)' }) {
        Add-Finding 'Application attack surface' $svc.Name 'REVIEW' "State=$($svc.Status)." 'SQL: least privilege, TLS/EPA and restrict xp_cmdshell; Exchange/IIS: patch, EPA and authorization; AD CS: secure enrollment. Requires application-specific review.'
    }
    foreach ($rodc in Get-ADDomainController -Filter * -Server $script:Server | Where-Object IsReadOnly) {
        Add-Finding 'RODC key-list exposure' $rodc.HostName 'REVIEW' 'Read-only DC present.' 'Review Password Replication Policy and cached privileged identities; rotate compromised RODC krbtgt keys through a coordinated recovery procedure.'
    }
}

Invoke-Check 'Defender remote execution and credential theft' {
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        Add-Finding 'Defender' $script:Server 'SKIPPED' 'Defender cmdlets unavailable.' 'Verify equivalent endpoint protection and credential theft controls.'
        return
    }
    $status = Get-MpComputerStatus
    Add-Finding 'Defender' $script:Server 'REVIEW' "AntivirusEnabled=$($status.AntivirusEnabled); realTime=$($status.RealTimeProtectionEnabled)." 'Validate effective protection/tamper protection; an administrator may try to disable it.'
    if (-not $status.AntivirusEnabled) { return }
    $rules = @{
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'PSExec/WMI process creation'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'LSASS credential theft'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'WMI permanent-event persistence'
    }
    $preferences = Get-MpPreference
    foreach ($id in $rules.Keys) {
        $index = [array]::IndexOf(@($preferences.AttackSurfaceReductionRules_Ids), $id)
        $action = if ($index -ge 0) { @($preferences.AttackSurfaceReductionRules_Actions)[$index] } else { $null }
        if ($action -ne 1) {
            Add-Finding 'Defender ASR' $rules[$id] 'REVIEW' "Reported rule action=$action; 1 means block." 'Use -EnableDefenderAsr after testing management compatibility. These rules do not cover every Impacket execution method.'
            if ($EnableDefenderAsr) {
                Invoke-Fix $rules[$id] 'Enable ASR rule in block mode' {
                    Save-State 'defender-asr' @{ Id = $id; Action = $action }
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled
                    $verify = Get-MpPreference
                    $position = [array]::IndexOf(@($verify.AttackSurfaceReductionRules_Ids), $id)
                    if ($position -lt 0 -or @($verify.AttackSurfaceReductionRules_Actions)[$position] -ne 1) { throw 'ASR readback failed; inspect tamper protection and management policy.' }
                }
            }
        }
    }
}

Invoke-Check 'Audit policy and patch inventory' {
    $subcategories = @{
        '0CCE9231-69AE-11D9-BED3-505054503030' = 'Kerberos service tickets'
        '0CCE9242-69AE-11D9-BED3-505054503030' = 'Kerberos authentication'
        '0CCE923B-69AE-11D9-BED3-505054503030' = 'Directory service access (SACL also required)'
        '0CCE923C-69AE-11D9-BED3-505054503030' = 'Directory service changes (SACL also required)'
        '0CCE9215-69AE-11D9-BED3-505054503030' = 'Logon'
        '0CCE922B-69AE-11D9-BED3-505054503030' = 'Process creation'
        '0CCE9237-69AE-11D9-BED3-505054503030' = 'User account management'
        '0CCE9211-69AE-11D9-BED3-505054503030' = 'Security system extension'
    }
    foreach ($id in $subcategories.Keys) {
        $guid = '{' + $id + '}'
        $before = & auditpol.exe /get "/subcategory:$guid" /r
        if ($LASTEXITCODE -ne 0) { throw "auditpol query failed: $guid" }
        Add-Finding 'Audit configuration' $subcategories[$id] 'INFO' ($before -join ' ') 'Monitor 4768/4769/4771/4624/4672/4662/5136/4724/4697/7045/4698 and WMI-Activity logs; deploy targeted SACLs for replication and sensitive AD writes.'
        Invoke-Fix $subcategories[$id] 'Enable success/failure auditing' {
            Save-State 'audit-policy' @{ Subcategory = $guid; Before = $before }
            & auditpol.exe /set "/subcategory:$guid" /success:enable /failure:enable | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "auditpol update failed: $guid" }
        }
    }
    $os = Get-CimInstance Win32_OperatingSystem
    $hotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    Add-Finding 'Patching' $script:Server 'REVIEW' "OS=$($os.Caption); build=$($os.BuildNumber); latest listed hotfix=$($hotfix.HotFixID)." 'Verify supported OS and current cumulative updates on ALL DCs: MS14-068, noPac, Netlogon, S4U/PAC, NTLM MIC/reflection and BadSuccessor. A hotfix list is not proof of coverage.'
    if ($ScanUpdates) {
        $session = New-Object -ComObject Microsoft.Update.Session
        $updates = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        foreach ($update in $updates.Updates) { Add-Finding 'Missing update' $script:Server 'HIGH' $update.Title 'Install through your patch process and reboot where required.' }
    }
}

Add-Finding 'Coverage limits' $script:Server 'INFO' 'Offline hive/NTDS/DPAPI/ticket tools act on already-stolen material; normal authenticated AD enumeration remains possible. Disabling RemoteRegistry does not stop an administrator from reenabling it or DCSync.' 'Protect privileged credentials, backups, DSRM, hypervisor and recovery keys. A compromised forest needs recovery, not just hardening.'
if ($PassThru) { $script:Findings }
else { Show-AuditReport -Findings $script:Findings.ToArray() }
if ($script:Failures) { throw "$script:Failures checks or changes failed. Review ERROR findings; the assessment is incomplete." }
