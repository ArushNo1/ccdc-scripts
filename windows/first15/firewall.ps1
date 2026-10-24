#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$InventoryPath,
    [switch]$Edit,
    [string[]]$TrustedSubnets = @(),
    [string[]]$ManagementSubnets = @(),
    [ValidateRange(1, 65535)][int[]]$ManagementTcpPorts = @(22, 3389, 5985, 5986),
    [ValidateRange(1, 65535)][int[]]$ServiceTcpPorts = @(),
    [ValidateRange(1, 65535)][int[]]$ServiceUdpPorts = @(),
    [switch]$AllowFileSharing,
    [switch]$BlockFileSharing,
    [switch]$AllowLegacyNetbios,
    [switch]$BlockInboundRpc,
    [switch]$NonInteractive,
    [string]$BackupDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module NetSecurity


function Test-FirewallAddress {
    param([string[]]$Addresses)
    foreach ($address in $Addresses) {
        $parts = $address.Split('/')
        $ip = $null
        if ($parts.Count -gt 2 -or -not [Net.IPAddress]::TryParse($parts[0], [ref]$ip)) {
            throw "Use explicit IP addresses or CIDR subnets: $address"
        }
        if ($parts.Count -eq 2) {
            $prefix = 0
            $maximum = if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
            if (-not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 1 -or $prefix -gt $maximum) {
                throw "Invalid or unrestricted CIDR: $address"
            }
        }
    }
}


function Test-RunningService {
    param([string]$Name)
    if ($null -ne $inventoryInput) { return $Name -in @($inventoryInput.RunningServices) }
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    $null -ne $service -and $service.Status -eq 'Running'
}


function Add-InboundRule {
    param([string]$Name, [string]$Protocol, [string[]]$Ports, [string[]]$RemoteAddress,
        [string]$Service)
    $parameters = @{
        Name = "CCDC-$Name"; DisplayName = "CCDC $Name"; Group = 'CCDC managed firewall'
        Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'
        Protocol = $Protocol; LocalPort = $Ports; RemoteAddress = $RemoteAddress
        PolicyStore = 'PersistentStore'
    }
    if ($Service) { $parameters.Service = $Service }
    $null = New-NetFirewallRule @parameters
}


function ConvertTo-FirewallPort {
    param([string]$Text)
    foreach ($entry in ($Text -split ',')) {
        $entry = $entry.Trim()
        if ($entry -notmatch '^(\d{1,5})(?:-(\d{1,5}))?$') { throw "Invalid port or range: $entry" }
        $first = [int]$Matches[1]
        $last = if ($Matches[2]) { [int]$Matches[2] } else { $first }
        if ($first -lt 1 -or $last -gt 65535 -or $last -lt $first) { throw "Invalid port or range: $entry" }
        if ($first -eq $last) { $first.ToString() } else { "$first-$last" }
    }
}

function Read-FirewallPort {
    param([string]$Label, [string[]]$Current)
    while ($true) {
        $value = Read-Host "$Label [$($Current -join ', ')]: Enter keeps; list replaces; +list adds; -list removes; none clears"
        if ([string]::IsNullOrWhiteSpace($value)) { return $Current }
        $value = $value.Trim()
        if ($value -eq 'none') { return }
        try {
            $operation = $value.Substring(0, 1)
            $portText = if ($operation -in '+', '-') { $value.Substring(1) } else { $value }
            $ports = @(ConvertTo-FirewallPort $portText)
            if ($operation -eq '+') { return @($Current + $ports | Sort-Object -Unique) }
            if ($operation -eq '-') {
                # Remove exact entries; replace a range to change only part of it.
                return @($Current | Where-Object { $_ -notin $ports })
            }
            return @($ports | Sort-Object -Unique)
        }
        catch { Write-Warning $_.Exception.Message }
    }
}

function Read-FirewallSource {
    param([string]$Label, [string[]]$Current)
    while ($true) {
        $value = Read-Host "$Label [$($Current -join ', ')]: Enter keeps; comma-separated IPs/CIDRs or Any replaces"
        if ([string]::IsNullOrWhiteSpace($value)) { return $Current }
        $addresses = @($value -split ',' | ForEach-Object { $_.Trim() })
        if ($addresses.Count -eq 1 -and $addresses[0] -eq 'Any') { return 'Any' }
        try { Test-FirewallAddress $addresses; return $addresses }
        catch { Write-Warning $_.Exception.Message }
    }
}

function Add-PortSuggestion {
    param([string]$Protocol, [string[]]$Ports, [string]$Purpose, [string]$Scope = 'Service')
    $suggestions.Add([pscustomobject]@{ Protocol = $Protocol; Ports = $Ports; Purpose = $Purpose; Scope = $Scope })
}

$inventoryInput = $null
$importedTcpPorts = @()
$importedUdpPorts = @()
if ($Edit -and $NonInteractive) { throw 'Choose Edit or NonInteractive, not both.' }
if ($InventoryPath) {
    $inventoryInput = Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json
    foreach ($property in 'SchemaVersion', 'Computer', 'Collected', 'CollectionComplete', 'DomainRole', 'RunningServices', 'ListeningTcpPorts', 'HasFileShares', 'TrustedSubnets', 'ManagementSubnets', 'ManagementTcpPorts', 'AdditionalServiceTcpPorts', 'AdditionalServiceUdpPorts', 'Errors') {
        if ($property -notin $inventoryInput.PSObject.Properties.Name) { throw "Inventory input is missing $property. Use inventory.ps1's firewall-input.json." }
    }
    if ($inventoryInput.SchemaVersion -ne 1) { throw 'Unsupported firewall inventory schema.' }
    if ($inventoryInput.Computer -ne $env:COMPUTERNAME) { throw "Inventory is for $($inventoryInput.Computer), not $env:COMPUTERNAME. Run inventory on this host." }
    if ($inventoryInput.CollectionComplete -isnot [bool] -or -not $inventoryInput.CollectionComplete -or @($inventoryInput.Errors).Count) { throw 'Firewall inventory is incomplete. Check collection errors and rerun inventory.' }
    if ($inventoryInput.DomainRole -notin 0, 1, 2, 3, 4, 5) { throw 'Invalid inventory domain role.' }
    if ($inventoryInput.HasFileShares -isnot [bool]) { throw 'Invalid inventory share status.' }
    $collected = [DateTimeOffset]::Parse($inventoryInput.Collected)
    if (([DateTimeOffset]::Now - $collected).TotalHours -gt 1) { Write-Warning 'Inventory is over an hour old. Newly started or reconfigured services may be missing.' }
    foreach ($port in @($inventoryInput.ListeningTcpPorts) + @($inventoryInput.ManagementTcpPorts)) {
        if ([string]$port -notmatch '^\d{1,5}$' -or [int]$port -lt 1 -or [int]$port -gt 65535) { throw "Invalid inventory TCP port: $port" }
    }
    if (-not $PSBoundParameters.ContainsKey('TrustedSubnets')) { $TrustedSubnets = @($inventoryInput.TrustedSubnets) }
    if (-not $PSBoundParameters.ContainsKey('ManagementSubnets')) { $ManagementSubnets = @($inventoryInput.ManagementSubnets) }
    if (-not $PSBoundParameters.ContainsKey('ManagementTcpPorts')) { $ManagementTcpPorts = @($inventoryInput.ManagementTcpPorts) }
    foreach ($entry in $inventoryInput.AdditionalServiceTcpPorts) { $importedTcpPorts += @(ConvertTo-FirewallPort ([string]$entry)) }
    foreach ($entry in $inventoryInput.AdditionalServiceUdpPorts) { $importedUdpPorts += @(ConvertTo-FirewallPort ([string]$entry)) }
    Write-Host "Imported inventory: $($inventoryInput.Computer), collected $($inventoryInput.Collected)"
}
Test-FirewallAddress $TrustedSubnets
Test-FirewallAddress $ManagementSubnets
if ($AllowFileSharing -and $BlockFileSharing) { throw 'Choose AllowFileSharing or BlockFileSharing, not both.' }
$serviceSources = if ($TrustedSubnets.Count) { $TrustedSubnets } else { @('Any') }
$managementSources = if ($ManagementSubnets.Count) { $ManagementSubnets } else { $serviceSources }
$computer = Get-CimInstance Win32_ComputerSystem
if ($null -ne $inventoryInput -and $inventoryInput.DomainRole -ne $computer.DomainRole) { throw 'Host role changed since inventory. Rerun inventory before importing.' }
$isDC = $computer.DomainRole -in 4, 5
$dns = Test-RunningService 'DNS'
$dhcp = Test-RunningService 'DHCPServer'
$dhcpClient = Test-RunningService 'Dhcp'
$smb = Test-RunningService 'LanmanServer'
$time = Test-RunningService 'W32Time'
$shares = @()
if ($smb -and -not $isDC) {
    if ($null -ne $inventoryInput) { if ($inventoryInput.HasFileShares) { $shares = @('Inventory file share') } }
    else { $shares = @(Get-SmbShare | Where-Object { -not $_.Special }) }
}
$allowSMB = $isDC -or ($smb -and -not $BlockFileSharing -and ($AllowFileSharing -or $shares.Count -gt 0))
if ($isDC -and $BlockFileSharing) { throw 'Use the interactive port selection to remove DC SMB; doing so breaks SYSVOL/NETLOGON access.' }
if (-not $isDC -and $AllowFileSharing -and -not $smb) { throw 'File sharing requested but LanmanServer is not running.' }
$listeners = if ($null -ne $inventoryInput) { @($inventoryInput.ListeningTcpPorts) } else { @(Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique) }
$suggestions = New-Object 'System.Collections.Generic.List[object]'
if ($isDC) {
    Add-PortSuggestion 'TCP/UDP' @('88') 'Kerberos authentication'
    Add-PortSuggestion 'TCP/UDP' @('389') 'LDAP and DC discovery'
    Add-PortSuggestion 'TCP/UDP' @('464') 'Kerberos password changes'
    if (-not $BlockInboundRpc) {
        Add-PortSuggestion 'TCP' @('135', '49152-65535') 'RPC endpoint mapper and dynamic RPC; domain operations and DC replication'
    }
    if (636 -in $listeners) { Add-PortSuggestion 'TCP' @('636') 'LDAPS; keep if applications use it' }
    if (3268 -in $listeners) { Add-PortSuggestion 'TCP' @('3268') 'Global Catalog queries' }
    if (3269 -in $listeners) { Add-PortSuggestion 'TCP' @('3269') 'Global Catalog over TLS; keep if used' }
    if ($time) { Add-PortSuggestion 'UDP' @('123') 'Windows time synchronization' }
}
if ($dns) { Add-PortSuggestion 'TCP/UDP' @('53') 'DNS queries; both TCP and UDP are needed' }
if ($allowSMB) { Add-PortSuggestion 'TCP' @('445') 'SMB shares; on DCs this includes SYSVOL and NETLOGON' }
if (Test-RunningService 'W3SVC') { Add-PortSuggestion 'TCP' @('80', '443') 'IIS web services; check actual bindings' }
if (Test-RunningService 'MSSQLSERVER') { Add-PortSuggestion 'TCP' @('1433') 'Default SQL Server; check its configured port' }
if (Test-RunningService 'SMTPSVC') { Add-PortSuggestion 'TCP' @('25') 'SMTP' }
if ($AllowLegacyNetbios) {
    Add-PortSuggestion 'TCP' @('139') 'Legacy NetBIOS session service'
    Add-PortSuggestion 'UDP' @('137', '138') 'Legacy NetBIOS name/datagram services'
}
if ($ServiceTcpPorts.Count) { Add-PortSuggestion 'TCP' @($ServiceTcpPorts | ForEach-Object { $_.ToString() }) 'Extra service ports supplied as arguments' }
if ($ServiceUdpPorts.Count) { Add-PortSuggestion 'UDP' @($ServiceUdpPorts | ForEach-Object { $_.ToString() }) 'Extra service ports supplied as arguments' }
if ($importedTcpPorts.Count) { Add-PortSuggestion 'TCP' $importedTcpPorts 'Custom/scored ports selected in inventory input' }
if ($importedUdpPorts.Count) { Add-PortSuggestion 'UDP' $importedUdpPorts 'Custom/scored ports selected in inventory input' }
if ($dhcp) { Add-PortSuggestion 'UDP' @('67', '547') 'DHCP server; these selected ports accept any source' }
if ($dhcpClient) { Add-PortSuggestion 'UDP' @('68', '546') 'DHCP client; these selected ports accept any source' }
$managementPorts = @($ManagementTcpPorts | Where-Object { $_ -in $listeners } | ForEach-Object { $_.ToString() })
foreach ($port in $managementPorts) {
    $purpose = switch ($port) { '22' { 'SSH' } '3389' { 'RDP' } '5985' { 'WinRM HTTP' } '5986' { 'WinRM HTTPS' } default { 'Configured management service' } }
    Add-PortSuggestion 'TCP' @($port) $purpose 'Management'
}
if ($isDC -and (Test-RunningService 'ADWS') -and 9389 -in $listeners) {
    $managementPorts += '9389'
    Add-PortSuggestion 'TCP' @('9389') 'AD Web Services for AD PowerShell and Administrative Center' 'Management'
}
$tcpPorts = @($suggestions | Where-Object { $_.Scope -eq 'Service' -and $_.Protocol -in 'TCP', 'TCP/UDP' } | ForEach-Object { $_.Ports } | Sort-Object -Unique)
$udpPorts = @($suggestions | Where-Object { $_.Scope -eq 'Service' -and $_.Protocol -in 'UDP', 'TCP/UDP' } | ForEach-Object { $_.Ports } | Sort-Object -Unique)
Write-Host "Domain controller: $isDC; DNS running: $dns; DHCP server running: $dhcp"
Write-Host 'Recommended inbound allowances:'
foreach ($suggestion in $suggestions) {
    Write-Host "  $($suggestion.Scope) $($suggestion.Protocol) $($suggestion.Ports -join ', '): $($suggestion.Purpose)"
}
Write-Host 'Check scored services and custom ports; detection does not cover every application.'
$interactive = -not $NonInteractive -and -not $WhatIfPreference
$editPorts = $interactive -and (-not $InventoryPath -or $Edit)
if ($editPorts) {
    $tcpPorts = @(Read-FirewallPort 'Service TCP ports' $tcpPorts)
    $udpPorts = @(Read-FirewallPort 'Service UDP ports' $udpPorts)
    $managementPorts = @(Read-FirewallPort 'Management TCP ports' $managementPorts)
    $serviceSources = @(Read-FirewallSource 'Service sources' $serviceSources)
    $managementSources = @(Read-FirewallSource 'Management sources' $managementSources)
}
$dhcpPorts = @()
if ($dhcp) { $dhcpPorts += '67', '547' }
if ($dhcpClient) { $dhcpPorts += '68', '546' }
# Selected DHCP ports also receive service-bound exceptions from any source.
$selectedDhcpPorts = @()
foreach ($port in $dhcpPorts) {
    foreach ($entry in $udpPorts) {
        $bounds = $entry -split '-'
        $last = if ($bounds.Count -eq 2) { [int]$bounds[1] } else { [int]$bounds[0] }
        if ([int]$port -ge [int]$bounds[0] -and [int]$port -le $last) { $selectedDhcpPorts += $port; break }
    }
}
Write-Host 'Final inbound rules:'
Write-Host "  Service TCP: $($tcpPorts -join ', '); UDP: $($udpPorts -join ', ')"
Write-Host "  Service sources: $($serviceSources -join ', ')"
Write-Host "  Management TCP: $($managementPorts -join ', '); sources: $($managementSources -join ', ')"
Write-Host "  DHCP UDP exceptions from any IP: $($selectedDhcpPorts -join ', ')"
Write-Host '  Essential ICMP error and IPv6 discovery messages remain allowed.'
Write-Host '  Default inbound: Block; default outbound: Allow. Existing outbound rules remain in place.'
Write-Host '  Existing local inbound rules will be replaced. Ports omitted from all allowances are blocked by default.'
if ('Any' -in $serviceSources -or 'Any' -in $managementSources) { Write-Warning 'At least one source scope is Any: those allowed ports accept connections from every IP.' }
if ($isDC) { Write-Warning 'Removing AD/RPC/SMB ports can break domain operations, Group Policy and DC replication.' }
if ($BlockInboundRpc) {
    Write-Warning 'CONTAINMENT: inbound TCP 135 and 49152-65535 will be blocked from every IP. These explicit blocks override ordinary port allowances and disrupt DC replication and RPC-based domain operations.'
    Write-Warning 'RPC port blocking is not a ZeroLogon fix. SMB named-pipe access may still expose Netlogon when SMB is allowed.'
}

# Domain policy is not editable through PersistentStore; refuse to imply an allowlist
# when inherited rules or disabled local-rule merging would defeat it.
$managedRules = @(Get-NetFirewallRule -PolicyStore ActiveStore |
    Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.PolicyStoreSourceType -eq 'GroupPolicy' })
$managedProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore |
    Where-Object { $_.AllowLocalFirewallRules -eq 'False' })
if ($managedRules.Count -or $managedProfiles.Count) {
    throw 'Domain policy controls inbound rules or disables local rule merging. Update that GPO first; local changes cannot guarantee this allowlist.'
}
if ($interactive -and (Read-Host 'Apply these rules? [y/N]') -notin 'y', 'yes') { Write-Host 'Cancelled. No firewall changes made.'; return }
if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Enable firewall and replace local inbound rules with the scoped role allowlist')) { return }
if (-not $BackupDirectory) {
    $BackupDirectory = Join-Path $env:ProgramData ('CCDC\firewall-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
}
$null = New-Item -Path $BackupDirectory -ItemType Directory -Force
$backup = Join-Path (Get-Item -LiteralPath $BackupDirectory).FullName 'before.wfw'
& netsh.exe advfirewall export $backup
if ($LASTEXITCODE -ne 0) { throw 'Firewall export failed. No rules changed.' }

try {
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
    # Stage the new allowances before disabling existing remote-access rules.
    $oldRules = @(Get-NetFirewallRule -PolicyStore PersistentStore |
        Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' -and $_.Group -ne 'CCDC managed firewall' })
    $previous = @(Get-NetFirewallRule -PolicyStore PersistentStore |
        Where-Object { $_.Group -eq 'CCDC managed firewall' })
    if ($previous.Count) { $previous | Remove-NetFirewallRule }
    if ($tcpPorts.Count) { Add-InboundRule 'Role TCP' 'TCP' $tcpPorts $serviceSources }
    $scopedUdpPorts = @($udpPorts | Where-Object { $_ -notin $dhcpPorts })
    if ($scopedUdpPorts.Count) { Add-InboundRule 'Role UDP' 'UDP' $scopedUdpPorts $serviceSources }
    if ($managementPorts.Count) {
        Add-InboundRule 'Management' 'TCP' $managementPorts $managementSources
    }
    if ($BlockInboundRpc) {
        $null = New-NetFirewallRule -Name 'CCDC-Block-Inbound-RPC' -DisplayName 'CCDC block inbound RPC' -Group 'CCDC managed firewall' -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol TCP -LocalPort @('135', '49152-65535') -RemoteAddress Any -PolicyStore PersistentStore
    }
    # DHCP discovery may use source 0.0.0.0; keep these selected allowances unscoped.
    foreach ($port in $selectedDhcpPorts) {
        $service = if ($port -in '67', '547') { 'DHCPServer' } else { 'Dhcp' }
        Add-InboundRule "DHCP $port" 'UDP' @($port) @('Any') $service
    }
    # Keep essential IPv6 neighbor discovery and IPv4/IPv6 packet-too-big messages.
    foreach ($type in '1', '2', '3', '4', '133', '134', '135', '136') {
        $null = New-NetFirewallRule -Name "CCDC-ICMPv6-$type" -DisplayName "CCDC ICMPv6 $type" -Group 'CCDC managed firewall' -Direction Inbound -Action Allow -Profile Any -Protocol ICMPv6 -IcmpType $type -PolicyStore PersistentStore
    }
    $null = New-NetFirewallRule -Name 'CCDC-ICMPv4-errors' -DisplayName 'CCDC ICMPv4 errors' -Group 'CCDC managed firewall' -Direction Inbound -Action Allow -Profile Any -Protocol ICMPv4 -IcmpType 3 -PolicyStore PersistentStore
    Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 32767
    if ($oldRules.Count) { $oldRules | Disable-NetFirewallRule }
    Write-Host "Applied. Console rollback: netsh advfirewall import `"$backup`""
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
}
catch {
    $failure = $_
    & netsh.exe advfirewall import $backup
    if ($LASTEXITCODE -ne 0) { Write-Warning "Automatic rollback failed. Backup: $backup" }
    throw $failure
}
