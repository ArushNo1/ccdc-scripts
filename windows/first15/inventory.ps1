#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Collects a one-time Windows inventory without changing system configuration.
.EXAMPLE
.\inventory.ps1
.EXAMPLE
.\inventory.ps1 -OutputDirectory C:\CCDC\Inventory -ShowDetails
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot ('inventory-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))),
    [switch]$ShowDetails,
    [switch]$NetworkOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$FormatEnumerationLimit = -1
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    throw 'Run this script in 64-bit Windows PowerShell to inventory both registry views and local accounts.'
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a new output directory so an earlier inventory is preserved.' }
$directory = New-Item -Path $OutputDirectory -ItemType Directory
$OutputDirectory = $directory.FullName
$started = Get-Date
$sections = [ordered]@{}
$failures = New-Object 'System.Collections.Generic.List[object]'
$summary = New-Object 'System.Collections.Generic.List[object]'
$report = New-Object System.Text.StringBuilder
$null = $report.AppendLine("Windows inventory: $env:COMPUTERNAME | $($started.ToString('o'))")
$null = $report.AppendLine('Competition summary. Full inventory, including processes, connections and DNS records: inventory.json')

function Add-InventoryError {
    param([string]$Section, [string]$Target, [System.Management.Automation.ErrorRecord]$Failure)
    $failures.Add([pscustomobject]@{ Section = $Section; Target = $Target; Error = $Failure.Exception.Message })
    Write-Warning "${Section} (${Target}): $($Failure.Exception.Message)"
}

function Get-InventorySection {
    param([string]$Name, [scriptblock]$Action)
    Write-Host "Collecting $Name..."
    $errorCount = $failures.Count
    $items = New-Object 'System.Collections.Generic.List[object]'
    try { & $Action | ForEach-Object { $items.Add($_) } }
    catch { Add-InventoryError $Name $env:COMPUTERNAME $_ }
    $sections[$Name] = $items.ToArray()
    $state = if ($failures.Count -gt $errorCount) { 'Incomplete' } else { 'Collected' }
    $summary.Add([pscustomobject]@{ Section = $Name; Count = $items.Count; Status = $state })

}

Get-InventorySection 'host' {
    $computer = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{
        Computer = $computer.Name; Domain = $computer.Domain; DomainJoined = $computer.PartOfDomain
        DomainRole = $computer.DomainRole; DomainController = $computer.DomainRole -in 4, 5
        CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        OS = $os.Caption; Version = $os.Version; Build = $os.BuildNumber
        Architecture = $os.OSArchitecture; LastBoot = $os.LastBootUpTime
        MemoryGB = [math]::Round($computer.TotalPhysicalMemory / 1GB, 2)
    }
}
Get-InventorySection 'network' {
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
        Select-Object Description, InterfaceIndex, MACAddress, IPAddress, IPSubnet, DefaultIPGateway,
            DNSServerSearchOrder, DNSDomain, DNSDomainSuffixSearchOrder, DHCPEnabled, DHCPServer, TcpipNetbiosOptions
}
Get-InventorySection 'routes' {
    Get-NetRoute | Select-Object AddressFamily, InterfaceIndex, DestinationPrefix, NextHop, RouteMetric, Protocol
}
Get-InventorySection 'disks' {
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' |
        Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace
}
Get-InventorySection 'services' {
    Get-CimInstance Win32_Service | Sort-Object Name |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ProcessId
}
Get-InventorySection 'nssm-services' {
    foreach ($service in $sections['services'] | Where-Object { $_.PathName -match '(?i)nssm' }) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)\Parameters"
        try {
            $key = Get-Item -LiteralPath $path
            [pscustomobject]@{
                Service = $service.Name; Application = $key.GetValue('Application')
                Directory = $key.GetValue('AppDirectory'); Arguments = $key.GetValue('AppParameters')
            }
        }
        catch { Add-InventoryError 'nssm-services' $service.Name $_ }
    }
}
Get-InventorySection 'processes' {
    Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
}
$processById = @{}
foreach ($process in $sections['processes']) { $processById[[int]$process.ProcessId] = $process }
$servicesById = @{}
foreach ($service in $sections['services']) {
    if ($service.ProcessId -gt 0) { $servicesById[[int]$service.ProcessId] = @($servicesById[[int]$service.ProcessId]) + $service.Name }
}
Get-InventorySection 'tcp' {
    $connections = if ($NetworkOnly) { @(Get-NetTCPConnection -State Listen) } else { @(Get-NetTCPConnection) }
    $connections | Sort-Object LocalPort, State | ForEach-Object {
        $process = $processById[[int]$_.OwningProcess]
        [pscustomobject]@{
            LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress; RemotePort = $_.RemotePort; State = $_.State.ToString()
            ProcessId = $_.OwningProcess; ProcessName = if ($process) { $process.Name } else { $null }
            Executable = if ($process) { $process.ExecutablePath } else { $null }
            Services = @($servicesById[[int]$_.OwningProcess] | Where-Object { $null -ne $_ })
        }
    }
}
Get-InventorySection 'udp' {
    Get-NetUDPEndpoint | Sort-Object LocalPort | ForEach-Object {
        $process = $processById[[int]$_.OwningProcess]
        [pscustomobject]@{
            LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort; ProcessId = $_.OwningProcess
            ProcessName = if ($process) { $process.Name } else { $null }
            Executable = if ($process) { $process.ExecutablePath } else { $null }
            Services = @($servicesById[[int]$_.OwningProcess] | Where-Object { $null -ne $_ })
        }
    }
}
Get-InventorySection 'shares' {
    foreach ($share in Get-SmbShare) {
        $access = @()
        if (-not $NetworkOnly) {
            try { $access = @(Get-SmbShareAccess -Name $share.Name -ScopeName $share.ScopeName | Select-Object AccountName, AccessControlType, AccessRight) }
            catch { Add-InventoryError 'shares' $share.Name $_ }
        }
        [pscustomobject]@{
            Name = $share.Name; ScopeName = $share.ScopeName; Path = $share.Path
            Description = $share.Description; Special = $share.Special; EncryptData = $share.EncryptData; ShareAccess = $access
        }
    }
}
# Export the firewall handoff before slower account, task and DNS-record collection.
$firewallErrors = @($failures | Where-Object { $_.Section -in 'host', 'services', 'tcp', 'udp', 'shares' })
$firewallInputPath = Join-Path $OutputDirectory 'firewall-input.json'
$firewallInput = [ordered]@{
    SchemaVersion = 1
    Computer = $env:COMPUTERNAME
    Collected = (Get-Date).ToString('o')
    CollectionComplete = $firewallErrors.Count -eq 0 -and $sections['host'].Count -eq 1
    DomainRole = if ($sections['host'].Count) { $sections['host'][0].DomainRole } else { $null }
    RunningServices = @($sections['services'] | Where-Object State -eq 'Running' | ForEach-Object Name)
    ListeningTcpPorts = @($sections['tcp'] | Where-Object {
        $_.State -eq 'Listen' -and -not [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($_.LocalAddress))
    } | ForEach-Object LocalPort | Sort-Object -Unique)
    HasFileShares = @($sections['shares'] | Where-Object { -not $_.Special }).Count -gt 0
    TrustedSubnets = @()
    ManagementSubnets = @()
    ManagementTcpPorts = @(22, 3389, 5985, 5986)
    AdditionalServiceTcpPorts = @()
    AdditionalServiceUdpPorts = @()
    Errors = @($firewallErrors | ForEach-Object { "$($_.Section): $($_.Error)" })
}
$firewallInput | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $firewallInputPath -Encoding UTF8
$listenerRows = @(
    foreach ($protocol in 'TCP', 'UDP') {
        $endpoints = if ($protocol -eq 'TCP') { @($sections['tcp'] | Where-Object State -eq 'Listen') } else { @($sections['udp']) }
        foreach ($endpoint in $endpoints) {
            [pscustomobject]@{
                Protocol = $protocol; Port = $endpoint.LocalPort; ProcessId = $endpoint.ProcessId
                Process = $endpoint.ProcessName; Executable = $endpoint.Executable
                Services = @($endpoint.Services) -join '; '; BindAddress = $endpoint.LocalAddress
                LocalOnly = [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($endpoint.LocalAddress))
            }
        }
    }
)
$endpointPath = Join-Path $OutputDirectory 'listener-endpoints.csv'
if ($listenerRows.Count) { $listenerRows | Export-Csv -LiteralPath $endpointPath -NoTypeInformation -Encoding UTF8 }
else { '"Protocol","Port","ProcessId","Process","Executable","Services","BindAddress","LocalOnly"' | Set-Content -LiteralPath $endpointPath -Encoding UTF8 }
$listenerGroups = @(
    foreach ($group in @($listenerRows | Group-Object Protocol, ProcessId, LocalOnly)) {
        $first = $group.Group[0]
        $ports = @($group.Group.Port | Sort-Object -Unique)
        $shownPorts = ($ports | Select-Object -First 12) -join ', '
        if ($ports.Count -gt 12) { $shownPorts += " (+$($ports.Count - 12) more; see listener-endpoints.csv)" }
        [pscustomobject]@{
            Protocol = $first.Protocol; Ports = $shownPorts; PortCount = $ports.Count
            ProcessId = $first.ProcessId; Process = $first.Process; Executable = $first.Executable
            Services = @($group.Group | ForEach-Object { $_.Services } | Where-Object { $_ } | Sort-Object -Unique) -join '; '
            BindAddresses = @($group.Group.BindAddress | Sort-Object -Unique) -join '; '
            LocalOnly = $first.LocalOnly
        }
    }
)
$listenerPath = Join-Path $OutputDirectory 'listeners.csv'
if ($listenerGroups.Count) { $listenerGroups | Export-Csv -LiteralPath $listenerPath -NoTypeInformation -Encoding UTF8 }
else { '"Protocol","Ports","PortCount","ProcessId","Process","Executable","Services","BindAddresses","LocalOnly"' | Set-Content -LiteralPath $listenerPath -Encoding UTF8 }
$networkReview = @(
    "Host: $env:COMPUTERNAME | DC: $($firewallInput.DomainRole -in 4, 5) | collected: $($firewallInput.Collected)"
    foreach ($adapter in $sections['network']) { "IPs: $($adapter.IPAddress -join ', ') | DNS: $($adapter.DNSServerSearchOrder -join ', ')" }
    ''
    'Network listeners by process (observed, not automatically approved):'
    foreach ($listener in $listenerGroups | Where-Object { -not $_.LocalOnly }) {
        "$($listener.Protocol) $($listener.Ports) | $($listener.Process) PID $($listener.ProcessId) | services: $($listener.Services)"
    }
    ''
    'Review listeners.csv for paths and bind addresses. A listener is not proof a service should be allowed.'
    'Set source subnets and add required custom/scored ports in firewall-input.json. Empty source arrays mean Any.'
    'DHCP client UDP endpoints and high UDP ports are not automatically treated as application services.'
    "Firewall input complete: $($firewallInput.CollectionComplete)"
    $firewallInput.Errors
)
$networkReview | Set-Content -LiteralPath (Join-Path $OutputDirectory 'network-review.txt') -Encoding UTF8
Write-Host "Firewall input ready: $firewallInputPath"
Write-Host "Quick network review: $(Join-Path $OutputDirectory 'network-review.txt')"
if ($NetworkOnly) {
    if ($ShowDetails) { Write-Host ($networkReview -join [Environment]::NewLine) }
    [pscustomobject]@{
        Computer = $env:COMPUTERNAME; Scope = 'Network'; OutputDirectory = $OutputDirectory
        FirewallInputPath = $firewallInputPath; Errors = $failures.Count; Complete = $firewallInput.CollectionComplete
    }
    return
}

Get-InventorySection 'share-ntfs-access' {
    foreach ($share in $sections['shares'] | Where-Object { $_.Path }) {
        try {
            $acl = Get-Acl -LiteralPath $share.Path
            [pscustomobject]@{
                Share = $share.Name; Path = $share.Path; Owner = $acl.Owner; Sddl = $acl.Sddl
                Access = @($acl.Access | Select-Object IdentityReference, FileSystemRights, AccessControlType, IsInherited)
            }
        }
        catch { Add-InventoryError 'share-ntfs-access' $share.Name $_ }
    }
}
Get-InventorySection 'scheduled-tasks' {
    Get-ScheduledTask | Select-Object TaskPath, TaskName, State, Author,
        @{ Name = 'Principal'; Expression = { $_.Principal | Select-Object UserId, GroupId, LogonType, RunLevel } },
        @{ Name = 'Actions'; Expression = { @($_.Actions | Select-Object Execute, Arguments, WorkingDirectory, ClassId) } },
        @{ Name = 'Triggers'; Expression = { @($_.Triggers | Select-Object * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties) } }
}
Get-InventorySection 'startup-registry' {
    foreach ($hive in 'HKLM:', 'HKCU:') {
        foreach ($view in 'SOFTWARE', 'SOFTWARE\WOW6432Node') {
            foreach ($keyName in 'Run', 'RunOnce', 'RunOnceEx', 'RunServices', 'RunServicesOnce') {
                $path = "$hive\$view\Microsoft\Windows\CurrentVersion\$keyName"
                if (-not (Test-Path -LiteralPath $path)) { continue }
                $keys = @(Get-Item -LiteralPath $path) + @(Get-ChildItem -LiteralPath $path -Recurse)
                foreach ($key in $keys) {
                    foreach ($name in $key.GetValueNames()) {
                        [pscustomobject]@{ Key = $key.Name; Name = $name; Value = $key.GetValue($name) }
                    }
                }
            }
        }
        $path = "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        if (Test-Path -LiteralPath $path) {
            $key = Get-Item -LiteralPath $path
            foreach ($name in 'Shell', 'Userinit') {
                if ($name -in $key.GetValueNames()) { [pscustomobject]@{ Key = $key.Name; Name = $name; Value = $key.GetValue($name) } }
            }
        }
    }
}
Get-InventorySection 'active-setup' {
    foreach ($view in 'SOFTWARE', 'SOFTWARE\WOW6432Node') {
        $path = "HKLM:\$view\Microsoft\Active Setup\Installed Components"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        foreach ($key in Get-ChildItem -LiteralPath $path) {
            [pscustomobject]@{ Key = $key.Name; StubPath = $key.GetValue('StubPath'); Version = $key.GetValue('Version') }
        }
    }
}
Get-InventorySection 'startup-folders' {
    foreach ($folderName in 'Startup', 'CommonStartup') {
        $path = [Environment]::GetFolderPath([Environment+SpecialFolder]$folderName)
        if ($path -and (Test-Path -LiteralPath $path)) {
            Get-ChildItem -LiteralPath $path -Force | Select-Object FullName, Length, LastWriteTime, Attributes
        }
    }
}
Get-InventorySection 'startup-commands' {
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
}
Get-InventorySection 'wmi-subscriptions' {
    foreach ($class in '__EventFilter', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__FilterToConsumerBinding') {
        Get-CimInstance -Namespace root/subscription -ClassName $class |
            Select-Object @{ Name = 'Class'; Expression = { $class } }, * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties
    }
}
Get-InventorySection 'software' {
    foreach ($hive in 'HKLM:', 'HKCU:') {
        foreach ($view in 'SOFTWARE', 'SOFTWARE\WOW6432Node') {
            $path = "$hive\$view\Microsoft\Windows\CurrentVersion\Uninstall"
            if (-not (Test-Path -LiteralPath $path)) { continue }
            foreach ($key in Get-ChildItem -LiteralPath $path) {
                $name = $key.GetValue('DisplayName')
                if (-not $name) { continue }
                [pscustomobject]@{
                    Name = $name; Version = $key.GetValue('DisplayVersion'); Publisher = $key.GetValue('Publisher')
                    InstallLocation = $key.GetValue('InstallLocation'); InstallDate = $key.GetValue('InstallDate')
                    RegistryKey = $key.Name; SystemComponent = $key.GetValue('SystemComponent')
                }
            }
        }
    }
}
Get-InventorySection 'features' {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Get-WindowsFeature | Where-Object Installed | Select-Object Name, DisplayName, InstallState
    }
    else { Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled' | Select-Object FeatureName, State }
}
Get-InventorySection 'hotfixes' { Get-HotFix | Select-Object HotFixID, Description, InstalledOn }
Get-InventorySection 'firewall-profiles' {
    Get-NetFirewallProfile -PolicyStore ActiveStore |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowLocalFirewallRules, LogFileName, LogBlocked
}
Get-InventorySection 'defender' {
    Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled,
        BehaviorMonitorEnabled, IsTamperProtected, AntivirusSignatureVersion, AntivirusSignatureLastUpdated
}
Get-InventorySection 'asr' {
    $preferences = Get-MpPreference
    $ids = @($preferences.AttackSurfaceReductionRules_Ids)
    $actions = @($preferences.AttackSurfaceReductionRules_Actions)
    for ($index = 0; $index -lt $ids.Count; $index++) {
        if ($null -ne $ids[$index]) {
            [pscustomobject]@{ RuleId = $ids[$index]; Action = if ($index -lt $actions.Count) { $actions[$index] } else { $null } }
        }
    }
}
$isDC = $sections['host'].Count -gt 0 -and $sections['host'][0].DomainController
if ($sections['host'].Count -gt 0) {
    Get-InventorySection 'users' {
        if ($isDC) {
            Import-Module ActiveDirectory
            Get-ADUser -Filter * -Properties Enabled, PasswordLastSet, PasswordNeverExpires, LastLogonDate, ServicePrincipalName |
                Select-Object SamAccountName, SID, Enabled, DistinguishedName, PasswordLastSet, PasswordNeverExpires, LastLogonDate, ServicePrincipalName
        }
        else { Get-LocalUser | Select-Object Name, SID, Enabled, Description, LastLogon, PasswordLastSet, PasswordExpires }
    }
    Get-InventorySection 'groups' {
        if ($isDC) { Get-ADGroup -Filter * | Select-Object Name, SamAccountName, SID, DistinguishedName, GroupCategory, GroupScope }
        else { Get-LocalGroup | Select-Object Name, SID, Description }
    }
    Get-InventorySection 'group-members' {
        foreach ($group in $sections['groups']) {
            try {
                $members = if ($isDC) { @(Get-ADGroupMember -Identity $group.DistinguishedName) } else { @(Get-LocalGroupMember -SID $group.SID) }
                foreach ($member in $members) {
                    [pscustomobject]@{ Group = $group.Name; GroupSID = $group.SID.ToString(); Member = $member.Name; MemberSID = $member.SID.ToString(); ObjectClass = $member.ObjectClass }
                }
            }
            catch { Add-InventoryError 'group-members' $group.Name $_ }
        }
    }
}
if ($isDC) {
    Get-InventorySection 'domain' {
        Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode, PDCEmulator, RIDMaster, InfrastructureMaster, ReplicaDirectoryServers
        Get-ADForest | Select-Object Name, ForestMode, Domains, GlobalCatalogs, SchemaMaster, DomainNamingMaster
    }
    Get-InventorySection 'domain-password-policy' { Get-ADDefaultDomainPasswordPolicy | Select-Object * -ExcludeProperty PropertyNames, AddedProperties, RemovedProperties, ModifiedProperties, PropertyCount }
    Get-InventorySection 'gpos' {
        Import-Module GroupPolicy
        Get-GPO -All | Select-Object Id, DisplayName, GpoStatus, Owner, CreationTime, ModificationTime
    }
}
if ('DNS' -in @($sections['services'] | ForEach-Object Name)) {
    Get-InventorySection 'dns-zones' {
        Import-Module DnsServer
        Get-DnsServerZone | Select-Object ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, IsAutoCreated, DynamicUpdate
    }
    Get-InventorySection 'dns-records' {
        foreach ($zone in $sections['dns-zones']) {
            try {
                Get-DnsServerResourceRecord -ZoneName $zone.ZoneName | ForEach-Object {
                    [pscustomobject]@{
                        Zone = $zone.ZoneName; HostName = $_.HostName; RecordType = $_.RecordType
                        TTLSeconds = $_.TimeToLive.TotalSeconds; Timestamp = $_.Timestamp
                        Data = $_.RecordData | Select-Object * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties
                    }
                }
            }
            catch { Add-InventoryError 'dns-records' $zone.ZoneName $_ }
        }
    }
    Get-InventorySection 'dns-forwarders' { Get-DnsServerForwarder | Select-Object IPAddress, UseRootHint, Timeout, EnableReordering }
}
if ('W3SVC' -in @($sections['services'] | ForEach-Object Name)) {
    Get-InventorySection 'iis-sites' {
        Import-Module WebAdministration
        Get-Website | Select-Object Name, State, PhysicalPath, ApplicationPool,
            @{ Name = 'Bindings'; Expression = { @($_.Bindings.Collection | Select-Object protocol, bindingInformation, sslFlags) } }
    }
}
foreach ($name in 'users', 'group-members', 'iis-sites', 'dns-zones', 'dns-records', 'dns-forwarders') {
    if (-not $sections.Contains($name)) { $sections[$name] = @() }
}
$windowsServicePath = '(?i)^("?%SystemRoot%|"?\\SystemRoot|"?' + [regex]::Escape($env:windir) + '[\\/])'

$inventory = [pscustomobject]@{
    Computer = $env:COMPUTERNAME; Started = $started.ToString('o'); Finished = (Get-Date).ToString('o')
    Scope = 'One host. DC account inventory covers its current domain; other hosts use local accounts. Group membership is direct. Software/startup registry covers machine and current user. Hotfixes are not a complete patch assessment.'
    Sections = $sections; Summary = $summary.ToArray(); Errors = $failures.ToArray()
}
$inventory | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'inventory.json') -Encoding UTF8

function Add-ReportSection {
    param([string]$Title, [string[]]$Rows = @(), [int]$Limit = 20)
    $null = $report.AppendLine("`r`n[$Title]")
    $lines = @($Rows | Where-Object { $_ })
    if (-not $lines.Count) { $null = $report.AppendLine('No entries collected. Check collection errors below.'); return }
    foreach ($line in $lines | Select-Object -First $Limit) {
        $text = $line -replace '[\r\n]+', ' '
        if ($text.Length -gt 240) { $text = $text.Substring(0, 237) + '...' }
        $null = $report.AppendLine($text)
    }
    if ($lines.Count -gt $Limit) { $null = $report.AppendLine("... $($lines.Count - $Limit) more entries in inventory.json") }
}

Add-ReportSection 'Collection errors' @(
    if (-not $failures.Count) { 'None reported.' }
    $failures.ToArray() | ForEach-Object { "$($_.Section) / $($_.Target): $($_.Error)" }
)
Add-ReportSection 'Host' @(
    $sections['host'] | ForEach-Object {
        "$($_.Computer) | $($_.OS) build $($_.Build) | domain: $($_.Domain) | DC: $($_.DomainController)"
        "Current user: $($_.CurrentUser) | last boot: $($_.LastBoot)"
    }
    $sections['network'] | ForEach-Object {
        "$($_.Description): $($_.IPAddress -join ', ') | gateway: $($_.DefaultIPGateway -join ', ') | DNS: $($_.DNSServerSearchOrder -join ', ')"
    }
    $sections['disks'] | ForEach-Object { "$($_.DeviceID) free: $([math]::Round($_.FreeSpace / 1GB, 1)) GB / $([math]::Round($_.Size / 1GB, 1)) GB" }
)
# Group dual-stack listeners and dynamic RPC ports by their owning process.
$listening = @($sections['tcp'] | Where-Object State -eq 'Listen')
Add-ReportSection 'TCP listeners by process' @(
    $listening | Group-Object ProcessId | ForEach-Object {
        $first = $_.Group[0]
        $ports = @($_.Group.LocalPort | Sort-Object -Unique)
        $shownPorts = ($ports | Select-Object -First 12) -join ', '
        if ($ports.Count -gt 12) { $shownPorts += " (+$($ports.Count - 12) more)" }
        $addresses = @($_.Group.LocalAddress | Sort-Object -Unique) -join ', '
        $services = @($_.Group | ForEach-Object { $_.Services } | Sort-Object -Unique) -join ', '
        "PID $($first.ProcessId) $($first.ProcessName): TCP $shownPorts | binds: $addresses | services: $services"
    }
)
Add-ReportSection 'UDP endpoints by process' @(
    $sections['udp'] | Group-Object ProcessId | ForEach-Object {
        $first = $_.Group[0]
        $ports = @($_.Group.LocalPort | Sort-Object -Unique)
        $shownPorts = ($ports | Select-Object -First 12) -join ', '
        if ($ports.Count -gt 12) { $shownPorts += " (+$($ports.Count - 12) more)" }
        "PID $($first.ProcessId) $($first.ProcessName): UDP $shownPorts"
    }
)
Add-ReportSection 'Application and role services' @(
    $sections['services'] | Where-Object {
        $_.Name -match '(?i)mssql|sqlagent|mysql|mariadb|postgres|pgsql|apache|httpd|nginx|tomcat|mongo|ftp|filezilla|ssh|vnc|W3SVC|DNS|DHCPServer|NTDS|ADWS|SMTPSVC' -or
        ($_.PathName -and $_.PathName -notmatch $windowsServicePath)
    } | Sort-Object Name | ForEach-Object { "$($_.Name): $($_.State) / $($_.StartMode) | account: $($_.StartName) | $($_.PathName)" }
)
Add-ReportSection 'NSSM applications' @(
    $sections['nssm-services'] | ForEach-Object { "$($_.Service): $($_.Application) $($_.Arguments) | directory: $($_.Directory)" }
)
Add-ReportSection 'IIS sites' @(
    $sections['iis-sites'] | ForEach-Object {
        $bindings = @($_.Bindings | ForEach-Object { "$($_.protocol) $($_.bindingInformation)" }) -join ', '
        "$($_.Name): $($_.State) | $bindings | path: $($_.PhysicalPath)"
    }
)
Add-ReportSection 'Accounts and privileged memberships' @(
    $users = @($sections['users'])
    $enabled = @($users | Where-Object Enabled)
    "Users collected: $($users.Count); enabled: $($enabled.Count). Direct memberships only."
    $sections['group-members'] | Where-Object {
        $_.GroupSID -match '^S-1-5-32-(544|548|549|550|551|552|555|580)$|^S-1-5-21-.*-(512|518|519|520|526|527)$' -or $_.Group -eq 'DnsAdmins'
    } | ForEach-Object { "$($_.Group): $($_.Member)" }
)
Add-ReportSection 'Non-administrative shares' @(
    $sections['shares'] | Where-Object { -not $_.Special } | ForEach-Object {
        $access = @($_.ShareAccess | ForEach-Object { "$($_.AccountName) $($_.AccessControlType) $($_.AccessRight)" }) -join '; '
        "$($_.Name): $($_.Path) | $access"
    }
)
Add-ReportSection 'DNS zones and forwarders' @(
    $sections['dns-zones'] | ForEach-Object { "$($_.ZoneName): $($_.ZoneType) | AD integrated: $($_.IsDsIntegrated) | dynamic update: $($_.DynamicUpdate)" }
    $sections['dns-forwarders'] | ForEach-Object { "Forwarders: $($_.IPAddress -join ', ') | root hints: $($_.UseRootHint)" }
)
Add-ReportSection 'Custom scheduled tasks' @(
    $sections['scheduled-tasks'] | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
        $actions = @($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
        "$($_.TaskPath)$($_.TaskName): $($_.State) | user: $($_.Principal.UserId) | $actions"
    }
)
Add-ReportSection 'Startup entries' @(
    $sections['startup-registry'] | ForEach-Object { "$($_.Key) / $($_.Name): $($_.Value)" }
    $sections['startup-folders'] | ForEach-Object { $_.FullName }
)
Add-ReportSection 'Security status' @(
    $sections['firewall-profiles'] | ForEach-Object { "Firewall $($_.Name): enabled=$($_.Enabled), inbound=$($_.DefaultInboundAction), outbound=$($_.DefaultOutboundAction)" }
    $sections['defender'] | ForEach-Object { "Defender: antivirus=$($_.AntivirusEnabled), realtime=$($_.RealTimeProtectionEnabled), signatures=$($_.AntivirusSignatureLastUpdated)" }
    "ASR entries collected: $(@($sections['asr']).Count). Actions and GUIDs are in inventory.json."
)
$null = $report.AppendLine("`r`nOther collected details in inventory.json:")
$null = $report.AppendLine("Processes: $(@($sections['processes']).Count); TCP connections: $(@($sections['tcp']).Count); software: $(@($sections['software']).Count); DNS records: $(@($sections['dns-records']).Count)")
$null = $report.AppendLine('Filtering is for quick review. Custom tasks, service paths and privileged group selections are heuristics, not a complete threat assessment. Missing sections or failed collectors mean unknown status.')
$report.ToString() | Set-Content -LiteralPath (Join-Path $OutputDirectory 'inventory.txt') -Encoding UTF8
if ($ShowDetails) { Write-Host $report.ToString() }
Write-Host "Collected $($summary.Count) sections; errors: $($failures.Count)."
Write-Host "Reports: $OutputDirectory"
Write-Host "Firewall preview: .\firewall.ps1 -InventoryPath `"$firewallInputPath`" -WhatIf"
Write-Host 'Reports include account information and process/task arguments. Keep them with your team.'
[pscustomobject]@{ Computer = $env:COMPUTERNAME; OutputDirectory = $OutputDirectory; FirewallInputPath = $firewallInputPath; Errors = $failures.Count; Complete = $failures.Count -eq 0 }
