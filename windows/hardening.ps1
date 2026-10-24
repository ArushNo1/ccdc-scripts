#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Block', 'Audit')][string]$ASRMode = 'Block',
    [switch]$SkipASR,
    [switch]$KeepPrinting,
    [switch]$KeepRemoteRegistry,
    [string[]]$SmtpRelayIPv4 = @('127.0.0.1'),
    [string[]]$UpdatePackage = @(),
    [switch]$ScanUpdates
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Set-RegistryValue {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [ValidateSet('DWord', 'String')][string]$Type = 'DWord'
    )

    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set $Type to $Value")) {
        if (-not (Test-Path -LiteralPath $Path)) { $null = New-Item -Path $Path -Force }
        $null = New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force
    }
}

function Remove-AllScheduledTasks {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    $failedTasks = New-Object 'System.Collections.Generic.List[string]'
    $removed = 0
    foreach ($task in $tasks) {
        $name = $task.TaskPath + $task.TaskName
        if ($PSCmdlet.ShouldProcess($name, 'Delete scheduled task')) {
            try {
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                $removed++
            } catch {
                $failedTasks.Add($name)
                Write-Warning "Could not delete ${name}: $($_.Exception.Message)"
            }
        }
    }
    Write-Host "Scheduled tasks deleted: $removed of $($tasks.Count)."
    if ($failedTasks.Count) { Write-Warning "Scheduled tasks still present: $($failedTasks -join ', ')" }
}

function Update-LocalGroupPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Run gpupdate /force and wait for completion')) {
        & "$env:windir\System32\gpupdate.exe" /force /wait:-1
        if ($LASTEXITCODE -ne 0) { throw "gpupdate failed with exit code $LASTEXITCODE. Review the policy processing errors." }
    }
}

function Set-SmtpHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$RelayIPv4 = @('127.0.0.1'))

    if (-not (Get-Service -Name SMTPSVC -ErrorAction SilentlyContinue)) { return }
    foreach ($address in $RelayIPv4) {
        $ip = $null
        if (-not [Net.IPAddress]::TryParse($address, [ref]$ip) -or
            $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
            $address -in '0.0.0.0', '255.255.255.255') {
            throw "SMTP relay entries must be individual IPv4 addresses: $address"
        }
    }
    $root = [ADSI]'IIS://localhost/SMTPSVC'
    $servers = @($root.psbase.Children | Where-Object { $_.SchemaClassName -eq 'IIsSmtpServer' })
    if (-not $servers.Count) { throw 'SMTP is installed but no virtual servers were found in the IIS metabase.' }
    foreach ($server in $servers) {
        if ($PSCmdlet.ShouldProcess($server.Path, "Restrict relay to [$($RelayIPv4 -join ', ')], disable SMTP AUTH and enable logging")) {
            $relay = $server.psbase.InvokeGet('IPSecurity')
            $type = $relay.GetType()
            $set = [Reflection.BindingFlags]::SetProperty
            $null = $type.InvokeMember('GrantByDefault', $set, $null, $relay, @($false))
            # COM expects one argument containing a SAFEARRAY, including when empty.
            $argument = New-Object object[] 1
            $argument[0] = [object[]]@($RelayIPv4 | ForEach-Object { "$_,255.255.255.255" })
            $null = $type.InvokeMember('IPGrant', $set, $null, $relay, $argument)
            $argument[0] = [object[]]@()
            foreach ($name in 'IPDeny', 'DomainGrant', 'DomainDeny') {
                $null = $type.InvokeMember($name, $set, $null, $relay, $argument)
            }
            $server.psbase.InvokeSet('RelayIpList', $relay)
            $server.psbase.InvokeSet('RelayForAuth', 0)
            # Incoming server-to-server mail remains anonymous; relay is controlled by IP.
            $server.psbase.InvokeSet('AuthFlags', 1)
            $server.psbase.InvokeSet('LogType', 1)
            $server.psbase.CommitChanges()
            foreach ($container in $server.psbase.Children) {
                if ($container.Name -ne 'Domain') { continue }
                foreach ($domain in $container.psbase.Children) {
                    $domain.psbase.InvokeSet('RelayIpList', $relay)
                    $domain.psbase.InvokeSet('RelayForAuth', 0)
                    $domain.psbase.CommitChanges()
                }
            }
            Write-Host "SMTP $($server.Name): relay allowed only from $($RelayIPv4 -join ', '); SMTP AUTH disabled; logging enabled."
        }
    }
    if ($PSCmdlet.ShouldProcess('SMTPSVC', 'Set automatic startup and restart SMTP to apply hardening')) {
        Set-Service -Name SMTPSVC -StartupType Automatic
        Restart-Service -Name SMTPSVC -Force
    }
}

function Set-TimeHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if (-not (Get-Service -Name W32Time -ErrorAction SilentlyContinue)) { return }
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config'
    foreach ($name in 'MaxPosPhaseCorrection', 'MaxNegPhaseCorrection') {
        $current = Get-ItemPropertyValue -LiteralPath $path -Name $name
        if ([long]$current -lt 0 -or [long]$current -gt 3600) {
            Set-RegistryValue $path $name 3600
        }
    }
    Set-RegistryValue $path 'EventLogFlags' 3
    Set-RegistryValue $path 'TimeJumpAuditOffset' 300
    if ($PSCmdlet.ShouldProcess('W32Time', 'Set automatic startup, start and reload settings; preserve time sources and domain hierarchy')) {
        Set-Service -Name W32Time -StartupType Automatic
        Start-Service -Name W32Time
        & "$env:windir\System32\w32tm.exe" /config /update
        if ($LASTEXITCODE -ne 0) { throw "Windows Time configuration reload failed: $LASTEXITCODE" }
        $source = & "$env:windir\System32\w32tm.exe" /query /source
        if ($LASTEXITCODE -ne 0) { throw "Windows Time source query failed: $LASTEXITCODE" }
        Write-Host "Windows Time: corrections capped at one hour; source: $source"
        if ($source -match 'Local CMOS Clock|Free-running System Clock') {
            Write-Warning 'Windows Time has no synchronized upstream reference. Configure a trusted source on the forest-root PDC when available.'
        }
    }
}

$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem
$isDC = $computer.DomainRole -in 4, 5
$build = [int]$os.BuildNumber
$dns = Get-Service -Name DNS -ErrorAction SilentlyContinue
foreach ($packagePath in $UpdatePackage) {
    $package = Get-Item -LiteralPath $packagePath
    if ($package.PSIsContainer -or $package.Extension -ne '.msu') { throw 'UpdatePackage must contain applicable Microsoft .msu files.' }
}
Write-Host "OS: $($os.Caption), build $build; domain controller: $isDC"
Write-Warning 'These are exposure reductions, not proof that CVEs are patched. No OS reboot is requested; patch and feature changes can remain pending.'


if ($isDC) {
    Import-Module ActiveDirectory
    Import-Module GroupPolicy
    $policyDomain = Get-ADDomain -Server $env:COMPUTERNAME
    $policyServer = $env:COMPUTERNAME
    $gpos = @(Get-GPO -All -Domain $policyDomain.DNSRoot -Server $policyServer)
    $enabledGpos = @($gpos | Where-Object { $_.GpoStatus -ne 'AllSettingsDisabled' })
    if ($enabledGpos.Count -gt 0) {
        $message = "Disable all $($enabledGpos.Count) active GPOs in $($policyDomain.DNSRoot), including the default policies? This affects the whole domain. No backup will be created."
        # WhatIf previews the domain change without prompting or writing GPOs.
        if ($WhatIfPreference) {
            $null = $PSCmdlet.ShouldProcess($policyDomain.DNSRoot, 'Set all GPOs to AllSettingsDisabled')
        }
        elseif ($PSCmdlet.ShouldContinue($message, 'Disable domain GPOs')) {
            foreach ($gpo in $enabledGpos) {
                if ($PSCmdlet.ShouldProcess("$($policyDomain.DNSRoot): $($gpo.DisplayName)", 'Set GPO status to AllSettingsDisabled')) {
                    $gpo.GpoStatus = 'AllSettingsDisabled'
                    $updated = Get-GPO -Guid $gpo.Id -Domain $policyDomain.DNSRoot -Server $policyServer
                    if ($updated.GpoStatus -ne 'AllSettingsDisabled') { throw "GPO did not report disabled: $($gpo.DisplayName)" }
                    Write-Host "Disabled GPO: $($gpo.DisplayName)"
                }
            }
            Write-Host 'GPO changes replicate between DCs. This script refreshes only this computer; other machines refresh separately.'
        }
        else { Write-Host 'Domain GPOs retained. Conflicting policies can overwrite local hardening during refresh.' }
    }
    else { Write-Host 'All GPOs in this domain are already disabled.' }
}
Update-LocalGroupPolicy

Write-Warning 'Deleting all scheduled tasks, including Microsoft and scored application tasks. Already running task processes are not stopped.'
Remove-AllScheduledTasks

$settings = @(
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'NoLMHash'; Value = 1 },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Value = 1 },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Value = 1 },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'EveryoneIncludesAnonymous'; Value = 0 },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Value = 1 },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; Value = 1 },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'PromptOnSecureDesktop'; Value = 1 },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorAdmin'; Value = 2 },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorUser'; Value = 0 },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableInstallerDetection'; Value = 1 },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Value = 0 },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'DisableSmartNameResolution'; Value = 1 },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Value = 0 },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoDriveTypeAutoRun'; Value = 255 },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoAutorun'; Value = 1 },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; Name = 'SafeDllSearchMode'; Value = 1 },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Value = 1 },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name = 'EnableModuleLogging'; Value = 1 },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; Name = '*'; Value = '*'; Type = 'String' },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Value = 1 }
)
foreach ($setting in $settings) { set-registryvalue @setting }
Write-Warning 'NTLMv2-only enforcement rejects LM/NTLMv1 clients. Retest application authentication.'
set-registryvalue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5
set-registryvalue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy' 0
$remoteRegistry = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
if ($remoteRegistry -and -not $KeepRemoteRegistry -and $PSCmdlet.ShouldProcess('RemoteRegistry', 'Stop and disable remote registry access')) {
    Stop-Service -Name RemoteRegistry -Force
    Set-Service -Name RemoteRegistry -StartupType Disabled
}
Write-Warning 'Disabling NetBIOS can break legacy name resolution and applications.'
foreach ($adapter in Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True') {
    if ($PSCmdlet.ShouldProcess($adapter.Description, 'Disable NetBIOS over TCP/IP')) {
        $result = Invoke-CimMethod -InputObject $adapter -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 }
        if ($result.ReturnValue -notin 0, 1) { throw "NetBIOS change failed for $($adapter.Description): $($result.ReturnValue)" }
        if ($result.ReturnValue -eq 1) { Write-Warning "NetBIOS change requires restart: $($adapter.Description)" }
    }
}
# Subcategory GUIDs avoid depending on the Windows display language.
$auditCategories = @(
    @{ Id = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'Process creation'; Failure = $false },
    @{ Id = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon'; Failure = $true },
    @{ Id = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Name = 'Special logon'; Failure = $false },
    @{ Id = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'Audit policy change'; Failure = $true },
    @{ Id = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'User account management'; Failure = $true },
    @{ Id = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'Security group management'; Failure = $true },
    @{ Id = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Name = 'Credential validation'; Failure = $true },
    @{ Id = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos authentication service'; Failure = $true }
)
foreach ($category in $auditCategories) {
    if ($PSCmdlet.ShouldProcess($category.Name, 'Enable audit events')) {
        $arguments = @('/set', "/subcategory:$($category.Id)", '/success:enable')
        if ($category.Failure) { $arguments += '/failure:enable' }
        & "$env:windir\System32\auditpol.exe" @arguments
        if ($LASTEXITCODE -ne 0) { throw "Audit policy change failed for $($category.Name): $LASTEXITCODE" }
    }
}

if ($PSCmdlet.ShouldProcess('SMB', 'Disable SMBv1 server, require client/server signing, disable insecure guest logons')) {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
}
set-registryvalue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' 0
if ($PSCmdlet.ShouldProcess('SMB1 feature', 'Remove SMBv1 client/server components without automatic reboot')) {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $feature = Get-WindowsFeature -Name FS-SMB1
        if ($feature.Installed) { Uninstall-WindowsFeature -Name FS-SMB1 }
    }
    else {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
        if ($feature.State -eq 'Enabled') { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart }
    }
}

$printKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
set-registryvalue $printKey 'RestrictDriverInstallationToAdministrators' 1
set-registryvalue $printKey 'NoWarningNoElevationOnInstall' 0
set-registryvalue $printKey 'UpdatePromptSettings' 0
$spooler = Get-CimInstance Win32_Service -Filter "Name='Spooler'"
if ($spooler -and -not $KeepPrinting -and $PSCmdlet.ShouldProcess('Spooler', 'Stop and disable printing to remove print-service attack surface')) {
    Stop-Service -Name Spooler -Force
    Set-Service -Name Spooler -StartupType Disabled
}
set-registryvalue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
set-registryvalue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1

if ($isDC) {
    Import-Module ActiveDirectory
    $domain = Get-ADDomain
    $server = $env:COMPUTERNAME
    if ($PSCmdlet.ShouldProcess($domain.DNSRoot, 'Set machine-account quota to zero')) {
        Set-ADObject -Identity $domain.DistinguishedName -Server $server -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }
    }
    Write-Host 'Machine-account quota restricts ordinary users creating computer accounts; delegated joins remain possible. Install DC updates for both noPac CVEs.'
    $netlogon = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    set-registryvalue $netlogon 'FullSecureChannelProtection' 1
    $netlogonKey = Get-Item -LiteralPath $netlogon -ErrorAction SilentlyContinue
    if ($null -ne $netlogonKey -and 'vulnerablechannelallowlist' -in $netlogonKey.GetValueNames()) {
        if ($PSCmdlet.ShouldProcess($netlogon, 'Remove vulnerablechannelallowlist')) {
            Remove-ItemProperty -LiteralPath $netlogon -Name 'vulnerablechannelallowlist' -Force -ErrorAction Stop
        }
    }
    $ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    Write-Warning 'LDAP signing rejects unsigned SASL and cleartext simple binds. Retest scored LDAP applications.'
    set-registryvalue $ntds 'LDAPServerIntegrity' 2

    Write-Warning 'LDAP channel binding can reject incompatible LDAPS clients; requires applicable DC updates.'
    set-registryvalue $ntds 'LdapEnforceChannelBinding' 2

}
if ($dns -and $os.ProductType -ne 1 -and $build -lt 20348) {
    set-registryvalue 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' 'TcpReceivePacketSize' 65280
    if ($PSCmdlet.ShouldProcess('DNS', 'Restart to activate temporary SIGRed workaround')) { Restart-Service -Name DNS }
    Write-Host 'SIGRed workaround does not replace the security update.'
}
if ($os.ProductType -ne 1 -and $build -in 18362, 18363) {
    set-registryvalue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'DisableCompression' 1
    Write-Host 'Applied SMBGhost server-side workaround for SAC 1903/1909; clients still need updates.'
}

foreach ($packagePath in $UpdatePackage) {
    $package = Get-Item -LiteralPath $packagePath
    if ($package.PSIsContainer -or $package.Extension -ne '.msu') { throw 'UpdatePackage must contain applicable Microsoft .msu files.' }
    if ($PSCmdlet.ShouldProcess($package.FullName, 'Install update package without automatic reboot')) {
        $hash = (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash
        $process = Start-Process -FilePath "$env:windir\System32\wusa.exe" -ArgumentList @(('"{0}"' -f $package.FullName), '/quiet', '/norestart') -Wait -PassThru
        [pscustomobject]@{ Path = $package.FullName; SHA256 = $hash; ExitCode = $process.ExitCode }
        if ($process.ExitCode -notin 0, 3010, 2359302) { throw "Update installer failed: $($process.ExitCode). Review servicing logs." }
        Write-Host "Update result: $($process.ExitCode); 3010 means reboot required, 2359302 means already installed."
    }
}
if ($ScanUpdates -and $PSCmdlet.ShouldProcess('Configured Windows Update/WSUS source', 'Search available software updates')) {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    $result.Updates | Select-Object Title, KBArticleIDs
}
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
    $defenderStatus = Get-MpComputerStatus
    if ($defenderStatus.AntivirusEnabled -and $PSCmdlet.ShouldProcess('Microsoft Defender', 'Enable real-time, behavior, archive, download and script scanning, and PUA protection')) {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableArchiveScanning $false -DisableIOAVProtection $false -DisableScriptScanning $false -PUAProtection Enabled
        Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -DisableBlockAtFirstSeen $false

        for ($attempt = 0; $attempt -lt 15 -and -not (Get-MpComputerStatus).RealTimeProtectionEnabled; $attempt++) {
            Start-Sleep -Seconds 2
        }
        if (-not (Get-MpComputerStatus).RealTimeProtectionEnabled) {
            throw 'Defender real-time protection did not enable; review effective policy and tamper protection.'
        }
    }
    elseif (-not $defenderStatus.AntivirusEnabled) {
        Write-Warning 'Defender Antivirus is inactive; Defender hardening was skipped.'
    }
}
else { Write-Warning 'Defender cmdlets are unavailable; Defender hardening was skipped.' }
$asrConfigured = $false
$asrCommand = Get-Command Add-MpPreference -ErrorAction SilentlyContinue
$asrReady = $false
if (-not $SkipASR -and $asrCommand -and $asrCommand.Parameters.ContainsKey('AttackSurfaceReductionRules_Ids')) {
    $status = Get-MpComputerStatus
    $asrReady = $status.AntivirusEnabled -and ($status.RealTimeProtectionEnabled -or $WhatIfPreference)
}
if (-not $SkipASR -and -not $asrReady) {
    Write-Warning 'ASR skipped: active Defender with ASR support is required. Server 2016 requires the modern unified solution; check platform support.'
}
if ($asrReady) {
    $asrConfigured = $true
    $rules = [ordered]@{
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'PSExec and WMI process creation'
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Vulnerable signed driver abuse'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'LSASS credential theft'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'WMI event subscription persistence'
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Office child processes'
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Office executable content'
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Office process injection'
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Office macro Win32 API calls'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Executable email content'
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'JS/VBS downloaded executables'
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Adobe Reader child processes'
    }
    $preferences = Get-MpPreference
    if ($os.ProductType -ne 1) {
        $rules.Remove('92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b')
    }
    $asrKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
    $desired = if ($ASRMode -eq 'Block') { 1 } else { 2 }
    foreach ($id in $rules.Keys) {
        $action = $desired
        $ids = @($preferences.AttackSurfaceReductionRules_Ids)
        $actions = @($preferences.AttackSurfaceReductionRules_Actions)
        $index = [array]::IndexOf($ids, $id)
        $policyKey = Get-Item -LiteralPath $asrKey -ErrorAction SilentlyContinue
        $policyValue = if ($null -ne $policyKey) { $policyKey.GetValue($id, $null) } else { $null }
        # An audit run must not weaken a preexisting block, including registry-only policy.
        if ($desired -eq 2 -and (($index -ge 0 -and $index -lt $actions.Count -and $actions[$index] -eq 1) -or $policyValue -eq '1')) { $action = 1 }
        set-registryvalue $asrKey $id $action.ToString() -Type String
        if ($PSCmdlet.ShouldProcess($rules[$id], "Set ASR action $action (1 block, 2 audit)")) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $action
        }
    }
}

Set-SmtpHardening -RelayIPv4 $SmtpRelayIPv4
Set-TimeHardening

Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature



# Refresh after the local changes as requested; domain/local policy can replace registry values.
Update-LocalGroupPolicy
if (-not $WhatIfPreference) { Write-Host 'Final policy refresh completed. Retest effective settings and scored services; some changes require sign-out or restart.' }

if ($asrConfigured) {
    $effective = Get-MpPreference
    $effectiveIds = @($effective.AttackSurfaceReductionRules_Ids)
    $effectiveActions = @($effective.AttackSurfaceReductionRules_Actions)
    foreach ($id in $rules.Keys) {
        $index = [array]::IndexOf($effectiveIds, $id)
        $action = if ($index -ge 0 -and $index -lt $effectiveActions.Count) { $effectiveActions[$index] } else { $null }
        [pscustomobject]@{ Rule = $rules[$id]; Id = $id; ReportedAction = $action }
        if (-not $WhatIfPreference -and ($null -eq $action -or ($desired -eq 1 -and $action -ne 1) -or ($desired -eq 2 -and $action -notin 1, 2))) {
            Write-Warning "ASR $id does not report the requested action. Check platform support, tamper protection and management policy."
        }
    }
}
