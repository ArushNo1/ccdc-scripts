#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Watches Security events for account changes, privileged memberships and failed-logon bursts.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 60)][int]$IntervalSeconds = 3,
    [ValidateRange(0, 1440)][int]$LookbackMinutes = 5,
    [ValidateRange(2, 1000)][int]$FailureThreshold = 5,
    [ValidateRange(10, 3600)][int]$FailureWindowSeconds = 60,
    [string]$LogPath = (Join-Path $env:ProgramData 'CCDC\Monitoring\security.log'),
    [switch]$Once,
    [switch]$PassThru
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Enable-SecurityAuditing {
    # Prefer advanced subcategories over legacy category-level audit policy.
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $override = Get-ItemPropertyValue -LiteralPath $lsaPath -Name SCENoApplyLegacyAuditPolicy -ErrorAction Ignore
    if ($override -ne 1) {
        $null = New-ItemProperty -LiteralPath $lsaPath -Name SCENoApplyLegacyAuditPolicy -PropertyType DWord -Value 1 -Force
    }
    $categories = @(
        @{ Id = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon'; Success = $false },
        @{ Id = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Name = 'Credential Validation'; Success = $false },
        @{ Id = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Authentication Service'; Success = $false },
        @{ Id = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'User Account Management'; Success = $true },
        @{ Id = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'Security Group Management'; Success = $true },
        @{ Id = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'Audit Policy Change'; Success = $true }
    )
    foreach ($category in $categories) {
        # GUIDs work on localized Windows. Omitted success settings remain unchanged.
        $arguments = @('/set', "/subcategory:$($category.Id)", '/failure:enable')
        if ($category.Success) { $arguments += '/success:enable' }
        $result = & "$env:windir\System32\auditpol.exe" @arguments
        if ($LASTEXITCODE -ne 0) { throw "Cannot enable $($category.Name) auditing: $($result -join ' ')" }
    }
    Write-Host 'Required Security audit categories enabled on this computer. Existing auditing remains enabled.'
}

function ConvertTo-SecurityAlert {
    param([Parameter(Mandatory)][xml]$EventXml)
    $id = [int]$EventXml.SelectSingleNode("//*[local-name()='System']/*[local-name()='EventID']").InnerText
    $data = @{}
    foreach ($item in $EventXml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) { $data[[string]$item.GetAttribute('Name')] = $item.InnerText }
    # Log clearing (1102) uses UserData instead of EventData.
    foreach ($item in $EventXml.SelectNodes("//*[local-name()='UserData']/*/*[not(*)]")) { $data[$item.LocalName] = $item.InnerText }
    $actor = "$($data['SubjectDomainName'])\$($data['SubjectUserName'])".Trim('\')
    $target = "$($data['TargetDomainName'])\$($data['TargetUserName'])".Trim('\')
    $severity = 'SUSPICIOUS'
    $summary = switch ($id) {
        1102 { $severity = 'CRITICAL'; 'Security audit log cleared' }
        4719 { 'Audit policy changed' }
        4720 { 'User created' }
        4722 { 'User enabled' }
        4723 { 'Password change attempted' }
        4724 { 'Password reset attempted' }
        4725 { 'User disabled' }
        4726 { 'User deleted' }
        4738 { 'User account changed' }
        4740 { 'Account locked out' }
        4767 { 'Account unlocked' }
        4781 { 'Account renamed' }
        { $_ -in 4728, 4732, 4756 } { 'Group member added' }
        { $_ -in 4729, 4733, 4757 } { 'Group member removed' }
        { $_ -in 4625, 4771, 4776 } { 'Authentication failed' }
        default { return }
    }
    if ($id -eq 4776 -and $data['Status'] -eq '0x0') { return }
    $privileged = [string]$data['TargetSid'] -match '^S-1-5-32-(544|548|549|550|551|552)$|^S-1-5-21-\d+-\d+-\d+-(512|518|519|520|526|527)$'
    if ($id -in 4728, 4732, 4756 -and $privileged) { $severity = 'CRITICAL'; $summary = 'Privileged group member added' }
    $details = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in 'MemberName', 'MemberSid', 'IpAddress', 'IpPort', 'WorkstationName', 'Workstation', 'LogonType', 'Status', 'SubStatus', 'FailureReason', 'CallerComputerName', 'OldTargetUserName', 'NewTargetUserName', 'SamAccountName', 'OldUacValue', 'NewUacValue', 'UserAccountControl', 'PrivilegeList', 'SubcategoryGuid', 'AuditPolicyChanges') {
        if ($data.ContainsKey($name) -and $data[$name] -notin '', '-') { $details.Add("${name}=$($data[$name])") }
    }
    $keywords = [string]$EventXml.Event.System.Keywords
    $outcome = if ($keywords -eq '0x8010000000000000') { 'Failure' } elseif ($keywords -eq '0x8020000000000000') { 'Success' } else { 'Unknown' }
    [pscustomobject]@{
        Time = [datetime]::Parse([string]$EventXml.Event.System.TimeCreated.SystemTime).ToUniversalTime()
        RecordId = [long][string]$EventXml.Event.System.EventRecordID
        EventId = $id; Severity = $severity; Summary = $summary; Actor = $actor; Target = $target
        Source = $(if ($data['IpAddress'] -and $data['IpAddress'] -ne '-') { $data['IpAddress'] } elseif ($data['Workstation']) { $data['Workstation'] } else { $data['WorkstationName'] })
        Outcome = $outcome; Details = $details -join '; '
    }
}

function Write-SecurityAlert {
    param([object]$Alert)
    $line = '[{0}] {1} E{2} #{3} | {4} | actor={5} | target={6} | {7}' -f $Alert.Time.ToLocalTime().ToString('HH:mm:ss'), $Alert.Severity, $Alert.EventId, $Alert.RecordId, $Alert.Summary, $Alert.Actor, $Alert.Target, $Alert.Outcome
    Write-Host $line -ForegroundColor $(if ($Alert.Severity -eq 'CRITICAL') { 'Red' } else { 'Yellow' })
    if ($Alert.Details) { Write-Host "  $($Alert.Details)" }
    Add-Content -LiteralPath $LogPath -Value ($Alert | ConvertTo-Json -Compress) -Encoding UTF8
    if ($PassThru) { $Alert }
}

Enable-SecurityAuditing

$parent = Split-Path -Parent $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
$null = New-Item -Path $parent -ItemType Directory -Force
$ids = '1102', '4719', '4720', '4722', '4723', '4724', '4725', '4726', '4738', '4740', '4767', '4781', '4728', '4732', '4756', '4729', '4733', '4757', '4625', '4771', '4776'
$eventFilter = ($ids | ForEach-Object { "EventID=$_" }) -join ' or '
$latest = Get-WinEvent -LogName Security -MaxEvents 1
$cursor = if ($LookbackMinutes -eq 0) { [long]$latest.RecordId } else { 0L }
$lastTime = $latest.TimeCreated
$initial = $true
$failures = @{}
Write-Host "Watching Security. Failed-logon threshold: $FailureThreshold in $FailureWindowSeconds seconds per event type/source or account. Log: $LogPath"
do {
    $newest = Get-WinEvent -LogName Security -MaxEvents 1
    if ($newest.RecordId -lt $cursor -or ($newest.RecordId -eq $cursor -and $newest.TimeCreated -gt $lastTime)) {
        Write-Warning 'Security log record numbering reset; restarting the reader. Previously overwritten events cannot be recovered.'
        $cursor = 0L; $failures.Clear()
    }
    if (-not $initial) {
        $oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1
        if ($oldest.RecordId -gt ($cursor + 1)) { Write-Warning 'Security log overwrote unread records. Some activity may have been missed.' }
    }
    $timeFilter = if ($initial -and $LookbackMinutes -gt 0) { ' and TimeCreated[timediff(@SystemTime) <= ' + ($LookbackMinutes * 60000) + ']' } else { '' }
    $xpath = "*[System[($eventFilter) and EventRecordID > $cursor and EventRecordID <= $($newest.RecordId)$timeFilter]]"
    $query = New-Object Diagnostics.Eventing.Reader.EventLogQuery('Security', [Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
    $reader = New-Object Diagnostics.Eventing.Reader.EventLogReader($query)
    $read = 0
    try {
        while ($read -lt 1000) {
            $event = $reader.ReadEvent()
            if ($null -eq $event) { break }
            try {
                $alert = ConvertTo-SecurityAlert -EventXml ([xml]$event.ToXml())
                $cursor = [long]$event.RecordId
                $read++
                if ($null -eq $alert) { continue }
                if ($alert.EventId -in 4625, 4771, 4776) {
                    $keys = @("$($alert.EventId)|account|$($alert.Target)")
                    if ($alert.Source -and $alert.Source -notin '-', '::', '0.0.0.0') { $keys += "$($alert.EventId)|source|$($alert.Source)" }
                    $triggered = New-Object 'System.Collections.Generic.List[string]'
                    foreach ($key in $keys) {
                        if (-not $failures.ContainsKey($key)) { $failures[$key] = New-Object 'System.Collections.Generic.Queue[datetime]' }
                        $queue = $failures[$key]
                        while ($queue.Count -and $queue.Peek() -lt $alert.Time.AddSeconds(-$FailureWindowSeconds)) { $null = $queue.Dequeue() }
                        $queue.Enqueue($alert.Time)
                        if ($queue.Count % $FailureThreshold -eq 0) { $triggered.Add("$key ($($queue.Count) failures)") }
                    }
                    if ($triggered.Count -eq 0) { continue }
                    $alert.Summary = 'Failed authentication burst'
                    $alert.Details = ($triggered -join '; ') + '; ' + $alert.Details
                }
                Write-SecurityAlert $alert
            } finally { $event.Dispose() }
        }
    } finally { $reader.Dispose() }
    if ($read -lt 1000) { $cursor = [long]$newest.RecordId }
    $lastTime = $newest.TimeCreated
    $initial = $false
    foreach ($key in @($failures.Keys)) {
        $queue = $failures[$key]
        while ($queue.Count -and $queue.Peek() -lt [datetime]::UtcNow.AddSeconds(-$FailureWindowSeconds)) { $null = $queue.Dequeue() }
        if (-not $queue.Count) { $failures.Remove($key) }
    }
    if ($Once -and $read -lt 1000) { break }
    if ($read -lt 1000) { Start-Sleep -Seconds $IntervalSeconds }
} while ($true)
