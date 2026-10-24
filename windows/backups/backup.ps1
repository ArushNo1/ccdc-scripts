#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Exports Windows and installed role configurations to a local ZIP for off-host storage.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot ('backup-' + $env:COMPUTERNAME + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))),
    [string[]]$ContentPath = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    throw 'Run in 64-bit Windows PowerShell.'
}
$OutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$archivePath = $OutputDirectory + '.zip'
if ((Test-Path -LiteralPath $OutputDirectory) -or (Test-Path -LiteralPath $archivePath)) {
    throw 'Choose a new output directory so an earlier backup is preserved.'
}
foreach ($path in $ContentPath) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSProvider.Name -ne 'FileSystem') { throw "Content must be a filesystem path: $path" }
    $sourcePath = $item.FullName.TrimEnd('\')
    if ($OutputDirectory -eq $sourcePath -or $OutputDirectory.StartsWith($sourcePath + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "The backup destination cannot be inside content being copied: $path"
    }
}
if (-not $PSCmdlet.ShouldProcess($OutputDirectory, 'Export configurations and content, then create a local ZIP')) { return }
$null = New-Item -Path $OutputDirectory -ItemType Directory
# Exports can contain application secrets; restrict the folder before writing them.
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $OutputDirectory -AclObject $acl
$results = New-Object 'System.Collections.Generic.List[object]'
function Save-BackupSection {
    param([string]$Name, [scriptblock]$Action)
    try {
        & $Action | Out-Null
        $results.Add([pscustomobject]@{ Section = $Name; Status = 'Saved'; Error = $null })
        Write-Host "Saved: $Name"
    } catch {
        $results.Add([pscustomobject]@{ Section = $Name; Status = 'Failed'; Error = $_.Exception.Message })
        Write-Warning "$Name failed: $($_.Exception.Message)"
    }
}
Save-BackupSection 'Firewall' {
    & netsh.exe advfirewall export (Join-Path $OutputDirectory 'firewall.wfw')
    if ($LASTEXITCODE -ne 0) { throw "netsh exit code $LASTEXITCODE" }
}
Save-BackupSection 'Security policy' {
    & secedit.exe /export /cfg (Join-Path $OutputDirectory 'security.inf') /quiet
    if ($LASTEXITCODE -ne 0) { throw "secedit exit code $LASTEXITCODE" }
    & auditpol.exe /backup ('/file:' + (Join-Path $OutputDirectory 'audit-policy.csv'))
    if ($LASTEXITCODE -ne 0) { throw "auditpol exit code $LASTEXITCODE" }
}
Save-BackupSection 'Network and shares' {
    Get-NetIPConfiguration -Detailed | Export-Clixml -LiteralPath (Join-Path $OutputDirectory 'network.xml')
    Get-SmbShare | Export-Clixml -LiteralPath (Join-Path $OutputDirectory 'shares.xml')
}
$services = @(Get-Service)
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -in 4, 5) {
    Save-BackupSection 'GPOs' {
        Import-Module GroupPolicy
        $folder = New-Item -Path (Join-Path $OutputDirectory 'gpo') -ItemType Directory
        Backup-GPO -All -Path $folder.FullName
        Get-GPOReport -All -ReportType Xml -Path (Join-Path $OutputDirectory 'gpo-report.xml')
    }
    Save-BackupSection 'AD reference exports' {
        Import-Module ActiveDirectory
        Get-ADDomain | Export-Clixml -LiteralPath (Join-Path $OutputDirectory 'ad-domain.xml')
        Get-ADUser -Filter * -Properties Enabled, MemberOf, PasswordLastSet |
            Select-Object DistinguishedName, SamAccountName, SID, Enabled, MemberOf, PasswordLastSet |
            Export-Clixml -LiteralPath (Join-Path $OutputDirectory 'ad-users.xml')
        Get-ADGroup -Filter * -Properties Members | Select-Object DistinguishedName, Name, SID, GroupScope, GroupCategory, Members |
            Export-Clixml -LiteralPath (Join-Path $OutputDirectory 'ad-groups.xml')
    }
}
if ($services.Name -contains 'DNS') {
    Save-BackupSection 'DNS settings' {
        Import-Module DnsServer
        Get-DnsServerZone | Export-Clixml -LiteralPath (Join-Path $OutputDirectory 'dns-zones.xml')
        Get-DnsServerForwarder | Export-Clixml -LiteralPath (Join-Path $OutputDirectory 'dns-forwarders.xml')
    }
    Save-BackupSection 'DNS zone exports' {
        foreach ($zone in Get-DnsServerZone | Where-Object { $_.ZoneType -eq 'Primary' -and -not $_.IsAutoCreated }) {
            Save-BackupSection ("DNS zone " + $zone.ZoneName) {
                $fileName = 'ccdc-' + [guid]::NewGuid().ToString('N') + '.dns'
                $temporaryPath = Join-Path "$env:windir\System32\dns" $fileName
                try {
                    Export-DnsServerZone -Name $zone.ZoneName -FileName $fileName
                    Copy-Item -LiteralPath $temporaryPath -Destination (Join-Path $OutputDirectory $fileName)
                    [pscustomobject]@{ Zone = $zone.ZoneName; File = $fileName } | ConvertTo-Json -Compress |
                        Add-Content -LiteralPath (Join-Path $OutputDirectory 'dns-zone-map.jsonl') -Encoding UTF8
                } finally {
                    if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath }
                }
            }
        }
    }
}
if ($services.Name -contains 'DHCPServer') {
    Save-BackupSection 'DHCP' {
        Import-Module DhcpServer
        Export-DhcpServer -ComputerName $env:COMPUTERNAME -File (Join-Path $OutputDirectory 'dhcp.xml') -Leases
    }
}
if (Test-Path -LiteralPath "$env:windir\System32\inetsrv\config") {
    Save-BackupSection 'IIS configuration' {
        Copy-Item -LiteralPath "$env:windir\System32\inetsrv\config" -Destination (Join-Path $OutputDirectory 'iis-config') -Recurse -Force
    }
}
foreach ($path in $ContentPath) {
    Save-BackupSection ("Content " + $path) {
        $name = 'content-' + [guid]::NewGuid().ToString('N')
        Copy-Item -LiteralPath $path -Destination (Join-Path $OutputDirectory $name) -Recurse -Force
        [pscustomobject]@{ Source = (Get-Item -LiteralPath $path -Force).FullName; Backup = $name } | ConvertTo-Json -Compress |
            Add-Content -LiteralPath (Join-Path $OutputDirectory 'content-map.jsonl') -Encoding UTF8
    }
}
$failed = @($results | Where-Object Status -eq 'Failed')
[pscustomobject]@{
    Computer = $env:COMPUTERNAME
    Collected = (Get-Date).ToString('o')
    Complete = $failed.Count -eq 0
    Sections = $results.ToArray()
    Limitations = 'Configuration exports only. No AD system state, passwords, database consistency, NTFS ACL preservation or automatic restoration. ZIP is not encrypted.'
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'report.json') -Encoding UTF8
Add-Type -AssemblyName System.IO.Compression.FileSystem
# Unlike Compress-Archive, this includes hidden files in selected content.
[IO.Compression.ZipFile]::CreateFromDirectory($OutputDirectory, $archivePath)
$fileAcl = New-Object System.Security.AccessControl.FileSecurity
$fileAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $fileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')))
}
Set-Acl -LiteralPath $archivePath -AclObject $fileAcl
if ($failed.Count) { Write-Warning "$($failed.Count) sections failed. See report.json; this backup is incomplete." }
Write-Host "Copy to your host: $archivePath"
[pscustomobject]@{ Directory = $OutputDirectory; ArchivePath = $archivePath; Complete = $failed.Count -eq 0; FailedSections = $failed.Count }
