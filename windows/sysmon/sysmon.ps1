#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Monitor,
    [switch]$MonitorOnly,
    [switch]$Once,
    [switch]$NoTui,
    [switch]$ProfileCheck,
    [ValidateRange(100, 50000)][int]$BufferSize = 5000,
    [string]$SysmonPath,
    [string[]]$ApprovedDnsServer = @(),
    [ValidateRange(16, 63)][int]$MinimumLabelLength = 24,
    [ValidateRange(2, 1000)][int]$DnsThreshold = 5,
    [ValidateRange(1, 60)][int]$WindowMinutes = 5,
    [ValidateRange(0, 1440)][int]$LookBackMinutes = 5,
    [ValidateRange(1, 60)][int]$PollSeconds = 3,
    [string]$AlertPath = "$env:ProgramData\CCDC\Sysmon\alerts.log"
)

$ErrorActionPreference = 'Stop'
$logName = 'Microsoft-Windows-Sysmon/Operational'

function Get-SysmonEvent {
    param([string]$XPath, [int]$Limit = 1000, [switch]$Oldest)
    try {
        Get-WinEvent -LogName $logName -FilterXPath $XPath -MaxEvents $Limit -Oldest:$Oldest -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
    }
}

function ConvertFrom-SysmonEvent {
    param($Event)
    $data = @{}
    foreach ($item in ([xml]$Event.ToXml()).Event.EventData.Data) {
        $data[[string]$item.Name] = [string]$item.'#text'
    }
    return $data
}

function Get-RiskyExecutable {
    param([string]$Path)
    if ($Path -notmatch '(?i)\\Users\\|\\Windows\\Temp\\|\\ProgramData\\|\\\$Recycle\.Bin\\|\\PerfLogs\\') { return }
    if (-not $signatureCache.ContainsKey($Path)) {
        if ($signatureCache.Count -ge 2048) { $signatureCache.Clear() }
        try {
            $signatureCache[$Path] = [string](Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop).Status
        }
        catch {
            # The file may have been deleted since the event was recorded.
            $signatureCache[$Path] = 'Unavailable'
            Write-Verbose "Could not check signature for ${Path}: $_"
        }
    }
    if ($signatureCache[$Path] -ne 'Valid') { return $signatureCache[$Path] }
}

function New-SysmonFinding {
    param([string]$Severity, [string]$Reason)
    [pscustomobject]@{ Severity = $Severity; Reason = $Reason }
}

function Get-ProcessContext {
    param($Event, [hashtable]$Data)
    if ($Event.Id -eq 1) {
        if ($processes.Count -ge 2048) { $processes.Clear() }
        if ($Data.ProcessGuid) { $processes[$Data.ProcessGuid] = $Data }
        return $Data
    }
    $guid = $Data.ProcessGuid
    if (-not $guid) { $guid = $Data.SourceProcessGUID }
    if ($guid -notmatch '^\{[0-9a-fA-F-]{36}\}$') { return }
    if (-not $processes.ContainsKey($guid)) {
        $creation = Get-SysmonEvent -XPath "*[System[EventID=1] and EventData[Data[@Name='ProcessGuid']='$guid']]" -Limit 1
        if ($processes.Count -ge 2048) { $processes.Clear() }
        $processes[$guid] = if ($null -ne $creation) { ConvertFrom-SysmonEvent $creation } else { $null }
    }
    return $processes[$guid]
}

function Get-EventSummary {
    param($Event, [hashtable]$Data)
    $image = $Data.Image
    if (-not $image) { $image = $Data.SourceImage }
    $ownerId = $Data.ProcessId
    if (-not $ownerId) { $ownerId = $Data.SourceProcessId }
    $processLabel = if ($image) { ($image -split '\\')[-1] } else { 'Sysmon' }
    if ($ownerId) { $processLabel += " ($ownerId)" }
    $detail = switch ($Event.Id) {
        1 { "START $($Data.Image) | parent $(([string]$Data.ParentImage -split '\\')[-1])" }
        3 {
            $direction = if ($Data.Initiated -eq 'true') { 'OUT' } else { 'IN' }
            "$direction $($Data.Protocol) $($Data.SourceIp):$($Data.SourcePort) -> $($Data.DestinationIp):$($Data.DestinationPort)"
        }
        4 { "Service $($Data.State)" }
        5 { 'EXIT' }
        8 { "Remote thread -> $($Data.TargetImage) ($($Data.TargetProcessId))" }
        16 { 'Configuration changed' }
        22 { "DNS $($Data.QueryName) | status $($Data.QueryStatus)" }
        25 { "Tampering: $($Data.Type)" }
        255 { "ERROR $($Data.ID): $($Data.Description)" }
        default {
            $fields = foreach ($key in 'EventType', 'TargetFilename', 'TargetObject', 'Details', 'Name', 'Destination', 'PipeName', 'ImageLoaded', 'Query', 'Consumer', 'Filter', 'RuleName') {
                if ($Data[$key]) { "${key}=$($Data[$key])" }
            }
            if ($fields) { $fields -join ' | ' }
            else {
                ($Data.GetEnumerator() | Where-Object { $_.Key -notin 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User' } |
                    Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' | '
            }
        }
    }
    return "$processLabel | $detail"
}

function Get-EventDetails {
    param($Event, [hashtable]$Data, [hashtable]$Context)
    $details = [ordered]@{ Time = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff'); Event = "E$($Event.Id) #$($Event.RecordId)" }
    if ($Data.ProcessId) { $details['PID'] = $Data.ProcessId }
    elseif ($Data.SourceProcessId) { $details['Source PID'] = $Data.SourceProcessId }
    $image = if ($Data.Image) { $Data.Image } else { $Data.SourceImage }
    if ($image) { $details['Path'] = $image }
    $command = if ($Data.CommandLine) { $Data.CommandLine } else { $Context.CommandLine }
    if ($command) { $details['Command'] = $command }
    $parent = if ($Data.ParentImage) { $Data } else { $Context }
    if ($parent.ParentImage) {
        $details['Parent'] = $parent.ParentImage
        if ($parent.ParentProcessId) { $details['Parent'] += " ($($parent.ParentProcessId))" }
    }
    if ($parent.ParentCommandLine) { $details['Parent command'] = $parent.ParentCommandLine }
    if ($parent.ParentUser) { $details['Parent user'] = $parent.ParentUser }
    $user = if ($Data.User) { $Data.User } elseif ($Data.SourceUser) { $Data.SourceUser } else { $Context.User }
    $integrity = if ($Data.IntegrityLevel) { $Data.IntegrityLevel } else { $Context.IntegrityLevel }
    if ($user) { $details['User'] = $user }
    if ($integrity) { $details['Integrity'] = $integrity }
    if ($Data.TargetImage) {
        $details['Target process'] = $Data.TargetImage
        if ($Data.TargetProcessId) { $details['Target process'] += " ($($Data.TargetProcessId))" }
    }
    if ($Data.TargetUser) { $details['Target user'] = $Data.TargetUser }
    if ($Event.Id -eq 3) {
        foreach ($side in 'Source', 'Destination') {
            $address = $Data["${side}Ip"]
            if ($address -like '*:*') { $address = "[$address]" }
            $endpoint = "$($address):$($Data["${side}Port"])"
            if ($Data["${side}Hostname"]) { $endpoint += " ($($Data["${side}Hostname"]))" }
            $label = if ($side -eq 'Source') { 'Source endpoint' } else { 'Dest endpoint' }
            $details[$label] = $endpoint
        }
    }
    $fieldsById = @{
        1 = @('CurrentDirectory', 'Product', 'Description', 'OriginalFileName', 'Company', 'FileVersion', 'LogonId', 'TerminalSessionId', 'Hashes')
        2 = @('TargetFilename', 'CreationUtcTime', 'PreviousCreationUtcTime')
        3 = @('Protocol', 'Initiated')
        4 = @('State', 'Version', 'SchemaVersion')
        5 = @()
        6 = @('ImageLoaded', 'Signed', 'Signature', 'SignatureStatus', 'Company', 'Description', 'OriginalFileName', 'Hashes')
        7 = @('ImageLoaded', 'Signed', 'Signature', 'SignatureStatus', 'Product', 'Description', 'OriginalFileName', 'FileVersion', 'Hashes')
        8 = @('NewThreadId', 'StartAddress', 'StartModule', 'StartFunction')
        9 = @('Device')
        10 = @('GrantedAccess', 'SourceThreadId', 'CallTrace')
        11 = @('TargetFilename', 'CreationUtcTime')
        12 = @('EventType', 'TargetObject')
        13 = @('EventType', 'TargetObject', 'Details')
        14 = @('EventType', 'TargetObject', 'NewName')
        15 = @('TargetFilename', 'Contents', 'CreationUtcTime', 'Hash')
        16 = @('Configuration', 'ConfigurationFileHash')
        17 = @('EventType', 'PipeName')
        18 = @('EventType', 'PipeName')
        19 = @('EventType', 'Operation', 'EventNamespace', 'Name', 'Query')
        20 = @('EventType', 'Operation', 'Name', 'Type', 'Destination')
        21 = @('EventType', 'Operation', 'Consumer', 'Filter')
        22 = @('QueryName', 'QueryType', 'QueryStatus', 'QueryResults')
        23 = @('TargetFilename', 'IsExecutable', 'Archived', 'Hashes')
        24 = @('Session', 'ClientInfo', 'Archived')
        25 = @('Type')
        26 = @('TargetFilename', 'IsExecutable', 'Hashes')
        27 = @('TargetFilename')
        28 = @('TargetFilename')
        29 = @('TargetFilename', 'Hashes')
        255 = @('ID', 'Description')
    }
    $labels = @{
        CurrentDirectory = 'Working dir'; OriginalFileName = 'Original name'; FileVersion = 'Version'
        TargetFilename = 'File'; CreationUtcTime = 'Created UTC'; PreviousCreationUtcTime = 'Previous UTC'
        ImageLoaded = 'Loaded image'; SignatureStatus = 'Signature status'; NewThreadId = 'New thread'
        StartAddress = 'Start address'; StartModule = 'Start module'; StartFunction = 'Start function'
        GrantedAccess = 'Access mask'; SourceThreadId = 'Source thread'; CallTrace = 'Call trace'
        EventType = 'Operation type'; TargetObject = 'Registry path'; NewName = 'New name'
        ConfigurationFileHash = 'Config hash'; PipeName = 'Pipe'; EventNamespace = 'Namespace'
        QueryName = 'DNS name'; QueryType = 'Query type'; QueryStatus = 'DNS status'; QueryResults = 'DNS results'
        IsExecutable = 'Executable'; ClientInfo = 'Clipboard client'; SchemaVersion = 'Schema'; ID = 'Error ID'
    }
    $keys = if ($fieldsById.ContainsKey([int]$Event.Id)) { $fieldsById[[int]$Event.Id] } else {
        # Future event IDs still expose their useful fields instead of disappearing.
        $Data.Keys | Where-Object { $_ -notmatch 'Guid$|^Hashes?$|^UtcTime$|^ProcessId$|^Image$|^User$' } | Sort-Object
    }
    foreach ($key in $keys) {
        $value = $Data[$key]
        if ($null -eq $value -or $value -eq '' -or $value -eq '-') { continue }
        $label = if ($labels.ContainsKey($key)) { $labels[$key] } else { $key }
        $details[$label] = $value
    }
    foreach ($item in $details.GetEnumerator()) {
        [pscustomobject]@{ Label = $item.Key; Value = $item.Value }
    }
}

function Get-TerminalFieldLine {
    param([string]$Label, [string]$Value, [int]$Width)
    $prefix = '      {0,-17} ' -f ($Label + ':')
    $continuation = ' ' * $prefix.Length
    $remaining = $Value -replace '[\x00-\x1f\x7f]', ' '
    $available = [Math]::Max(1, $Width - $prefix.Length)
    while ($remaining.Length -gt $available) {
        $prefix + $remaining.Substring(0, $available)
        $remaining = $remaining.Substring($available)
        $prefix = $continuation
    }
    $prefix + $remaining
}

function Write-SysmonBatch {
    param([object[]]$Records)
    if ($Records.Count -eq 0) { return }
    $suspicious = @($Records | Where-Object Severity -eq 'SUSPICIOUS').Count
    $critical = @($Records | Where-Object Severity -eq 'CRITICAL').Count
    $lineLimit = 120
    try {
        $width = $Host.UI.RawUI.WindowSize.Width
        if ($width -ge 60) { $lineLimit = [Math]::Min($width - 1, 180) }
    }
    catch { Write-Verbose 'Terminal width unavailable; using 120 columns.' }
    if (-not $useTui) {
        Write-Host ("`n[{0:HH:mm:ss}] {1} events | {2} suspicious | {3} critical" -f (Get-Date), $Records.Count, $suspicious, $critical) -ForegroundColor Cyan
    }
    $logLines = foreach ($record in $Records) {
        $fields = $record.Data.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }
        $reasons = ($record.Findings | ForEach-Object Reason) -join '; '
        $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] Event {2} Record {3} | {4}' -f
            $record.Event.TimeCreated, $record.Severity, $record.Event.Id, $record.Event.RecordId, ($fields -join ' | ')
        if ($reasons) { $line += " | Findings=$reasons" }
        if ($record.Context -and $record.Event.Id -ne 1) {
            $line += " | Parent=$($record.Context.ParentImage) | Command=$($record.Context.CommandLine)"
        }
        $line -replace '[\r\n\t]', ' '
    }
    Add-Content -LiteralPath $AlertPath -Value $logLines -Encoding UTF8
    if ($useTui) { return }
    $groups = $Records | Group-Object Category | Sort-Object @{ Expression = { ($_.Group | Measure-Object Priority -Maximum).Maximum }; Descending = $true }, Name
    foreach ($group in $groups) {
        Write-Host ("  {0} ({1})" -f $group.Name.ToUpperInvariant(), $group.Count) -ForegroundColor Cyan
        foreach ($record in $group.Group) {
            $color = switch ($record.Severity) { 'CRITICAL' { 'Red' } 'SUSPICIOUS' { 'Yellow' } default { 'Gray' } }
            $summary = Get-EventSummary $record.Event $record.Data
            $line = '    {0:HH:mm:ss} {1,-10} E{2,-3} #{3} {4}' -f $record.Event.TimeCreated, $record.Severity, $record.Event.Id, $record.Event.RecordId, $summary
            $line = $line -replace '[\r\n\t]', ' '
            if ($line.Length -gt $lineLimit) { $line = $line.Substring(0, $lineLimit - 3) + '...' }
            Write-Host $line -ForegroundColor $color
            foreach ($detail in @(Get-EventDetails $record.Event $record.Data $record.Context)) {
                foreach ($detailLine in @(Get-TerminalFieldLine -Label $detail.Label -Value $detail.Value -Width $lineLimit)) {
                    Write-Host $detailLine -ForegroundColor Gray
                }
            }
            foreach ($finding in $record.Findings) {
                foreach ($reasonLine in @(Get-TerminalFieldLine -Label '!' -Value $finding.Reason -Width $lineLimit)) {
                    Write-Host $reasonLine -ForegroundColor $color
                }
            }
        }
    }
}

function Get-VisibleEvent {
    param([hashtable]$View)
    foreach ($record in $View.Buffer) {
        if ($View.Severity -eq 1 -and $record.Priority -lt 1) { continue }
        if ($View.Severity -eq 2 -and $record.Priority -lt 2) { continue }
        if ($View.EventId -and $record.Event.Id -ne $View.EventId) { continue }
        if ($View.Search -and $record.SearchText.IndexOf($View.Search, [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $record
    }
}

function Copy-SysmonEvent {
    param([hashtable]$View)
    $visible = @(Get-VisibleEvent $View)
    if (-not $visible.Count) { $View.Message = 'Nothing to copy.'; return }
    $record = $null
    foreach ($candidate in $visible) {
        if ($candidate.Event.RecordId -eq $View.Selected) { $record = $candidate; break }
    }
    if ($null -eq $record) { $record = $visible[$visible.Count - 1] }
    $View.Selected = $record.Event.RecordId
    $View.Follow = $false
    $text = @(
        "$($record.Severity) | $(Get-EventSummary $record.Event $record.Data)"
        foreach ($finding in $record.Findings) { "$($finding.Severity): $($finding.Reason)" }
        foreach ($detail in @(Get-EventDetails $record.Event $record.Data $record.Context)) {
            "$($detail.Label): $($detail.Value)"
        }
    ) -join [Environment]::NewLine
    try {
        Set-Clipboard -Value $text -ErrorAction Stop
        $View.Message = "Copied E$($record.Event.Id) #$($record.Event.RecordId). F resumes following."
    }
    catch { $View.Message = "Copy failed: $($_.Exception.Message)" }
}

function Resume-SysmonView {
    param([hashtable]$View)
    $View.Follow = $true
    $View.Focus = 'Events'
    $View.DetailsOffset = 0
    $View.Search = ''; $View.EventId = 0; $View.Severity = 0
    $View.Editing = ''; $View.Input = ''; $View.Message = ''
    if ($View.Buffer.Count) { $View.Selected = $View.Buffer[$View.Buffer.Count - 1].Event.RecordId }
}

function Update-SysmonPointer {
    param([hashtable]$View, [int]$X, [int]$Y, [int]$Wheel = 0)
    if ($Y -eq 0 -and $X -ge 0 -and $X -lt 18 -and $Wheel -eq 0) {
        Resume-SysmonView $View
        return
    }
    if ($View.Editing) { return }
    $View.Message = ''
    if ($Y -eq 3 + $View.PageSize -and $X -ge 0 -and $X -lt 17 -and $Wheel -eq 0) {
        Copy-SysmonEvent $View
        return
    }
    if ($Wheel) {
        $View.Focus = if ($Y -ge 3 -and $Y -lt 3 + $View.PageSize) { 'Events' } else { 'Details' }
        $keyName = if ($Wheel -gt 0) { 'UpArrow' } else { 'DownArrow' }
        Update-SysmonView $View ([pscustomobject]@{ Key = $keyName; KeyChar = [char]0 })
    }
    elseif ($Y -ge 3 -and $Y -lt 3 + $View.PageSize) {
        $visible = @(Get-VisibleEvent $View)
        $position = $View.FirstVisible + $Y - 3
        if ($position -lt $visible.Count) {
            $View.Selected = $visible[$position].Event.RecordId
            $View.Follow = $false; $View.Focus = 'Events'; $View.DetailsOffset = 0
        }
    }
    elseif ($Y -ge 3 + $View.PageSize) { $View.Focus = 'Details'; $View.Follow = $false }
}

function Initialize-SysmonInput {
    if ('CcdcSysmon.ConsoleInput' -as [type]) { return }
    # ReadConsoleInput preserves key events and exposes mouse clicks without a module dependency.
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace CcdcSysmon {
    public static class ConsoleInput {
        [StructLayout(LayoutKind.Explicit, Size = 20)]
        public struct Record {
            [FieldOffset(0)] public ushort Type;
            [FieldOffset(4)] public int KeyDown;
            [FieldOffset(8)] public ushort Repeat;
            [FieldOffset(10)] public ushort VirtualKey;
            [FieldOffset(14)] public ushort Character;
            [FieldOffset(16)] public uint Control;
            [FieldOffset(4)] public short MouseX;
            [FieldOffset(6)] public short MouseY;
            [FieldOffset(8)] public uint Buttons;
            [FieldOffset(16)] public uint MouseFlags;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetStdHandle(int id);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetConsoleMode(IntPtr handle, out uint mode);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetConsoleMode(IntPtr handle, uint mode);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetNumberOfConsoleInputEvents(IntPtr handle, out uint count);
        [DllImport("kernel32.dll", EntryPoint = "ReadConsoleInputW", SetLastError = true)]
        static extern bool ReadConsoleInput(IntPtr handle, [Out] Record[] records, uint length, out uint read);
        static IntPtr input;
        static uint savedMode;
        static bool enabled;
        public static void Enable() {
            input = GetStdHandle(-10);
            if (!GetConsoleMode(input, out savedMode)) throw new Win32Exception(Marshal.GetLastWin32Error());
            uint mode = (savedMode | 0x0098u) & ~0x0240u;
            if (!SetConsoleMode(input, mode)) throw new Win32Exception(Marshal.GetLastWin32Error());
            enabled = true;
        }
        public static void Restore() {
            if (enabled && !SetConsoleMode(input, savedMode)) throw new Win32Exception(Marshal.GetLastWin32Error());
            enabled = false;
        }
        public static Record[] ReadPending() {
            uint count, read;
            if (!GetNumberOfConsoleInputEvents(input, out count)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (count == 0) return new Record[0];
            count = Math.Min(count, 64u);
            Record[] records = new Record[count];
            if (!ReadConsoleInput(input, records, count, out read)) throw new Win32Exception(Marshal.GetLastWin32Error());
            Array.Resize(ref records, (int)read);
            return records;
        }
    }
}
'@
}

function Update-SysmonView {
    param([hashtable]$View, $Key)
    $View.Message = ''
    if ($Key.Key -eq 'End' -and ($Key.Modifiers -band [ConsoleModifiers]::Control)) { Resume-SysmonView $View; return }
    if ($View.Editing) {
        switch ($Key.Key) {
            'Escape' { $View.Editing = ''; $View.Input = ''; return }
            'Backspace' {
                if ($View.Input.Length -gt 0) { $View.Input = $View.Input.Substring(0, $View.Input.Length - 1) }
                return
            }
            'Enter' {
                if ($View.Editing -eq 'Search') { $View.Search = $View.Input }
                else {
                    $number = 0
                    if ($View.Input -eq '') { $View.EventId = 0 }
                    elseif ([int]::TryParse($View.Input, [ref]$number) -and $number -gt 0) { $View.EventId = $number }
                    else { $View.Message = 'Enter a positive event ID, or leave blank for all.'; return }
                }
                $View.Editing = ''
                $View.DetailsOffset = 0
                return
            }
            default {
                if (-not [char]::IsControl($Key.KeyChar)) { $View.Input += [string]$Key.KeyChar }
                return
            }
        }
    }
    $visible = @(Get-VisibleEvent $View)
    $index = -1
    for ($item = 0; $item -lt $visible.Count; $item++) {
        if ($visible[$item].Event.RecordId -eq $View.Selected) { $index = $item; break }
    }
    if ($index -lt 0 -and $visible.Count -gt 0) { $index = $visible.Count - 1 }
    $step = switch ($Key.Key) { 'UpArrow' { -1 } 'DownArrow' { 1 } 'PageUp' { -$View.PageSize } 'PageDown' { $View.PageSize } default { 0 } }
    if ($step -ne 0) {
        if ($View.Focus -eq 'Details') { $View.Follow = $false; $View.DetailsOffset = [Math]::Max(0L, [long]$View.DetailsOffset + $step) }
        elseif ($visible.Count -gt 0) {
            $View.Follow = $false
            $index = [Math]::Max(0, [Math]::Min($visible.Count - 1, $index + $step))
            $View.Selected = $visible[$index].Event.RecordId
            $View.DetailsOffset = 0
        }
        return
    }
    switch ($Key.Key) {
        'Tab' {
            $View.Focus = if ($View.Focus -eq 'Events') { 'Details' } else { 'Events' }
            if ($View.Focus -eq 'Details') { $View.Follow = $false }
            return
        }
        'Home' {
            if ($View.Focus -eq 'Details') { $View.DetailsOffset = 0 }
            elseif ($visible.Count -gt 0) { $View.Selected = $visible[0].Event.RecordId; $View.Follow = $false }
            return
        }
        'End' {
            if ($View.Focus -eq 'Details') { $View.DetailsOffset = [int]::MaxValue }
            else { Resume-SysmonView $View }
            return
        }
    }
    switch (([string]$Key.KeyChar).ToLowerInvariant()) {
        'q' { $View.Quit = $true }
        'f' { Resume-SysmonView $View }
        'p' { if ($View.Follow) { $View.Follow = $false } else { Resume-SysmonView $View } }
        's' { $View.Follow = $false; $View.Severity = ($View.Severity + 1) % 3; $View.DetailsOffset = 0 }
        'i' { $View.Follow = $false; $View.Editing = 'Event ID'; $View.Input = ''; $View.Message = '' }
        '/' { $View.Follow = $false; $View.Editing = 'Search'; $View.Input = $View.Search; $View.Message = '' }
        'c' { $View.Search = ''; $View.EventId = 0; $View.Severity = 0; $View.DetailsOffset = 0 }
        'y' { Copy-SysmonEvent $View }
    }
}

function Get-SysmonFrame {
    param([hashtable]$View, [int]$Width, [int]$Height)
    $lines = New-Object 'System.Collections.Generic.List[object]'
    if ($Width -lt 60 -or $Height -lt 16) {
        $lines.Add([pscustomobject]@{ Text = 'Enlarge the terminal to at least 60 columns and 17 rows. Q exits.'; Color = 'Yellow'; Selected = $false })
    }
    else {
        $visible = @(Get-VisibleEvent $View)
        $index = -1
        for ($item = 0; $item -lt $visible.Count; $item++) {
            if ($visible[$item].Event.RecordId -eq $View.Selected) { $index = $item; break }
        }
        if ($visible.Count -gt 0 -and ($View.Follow -or $index -lt 0)) {
            $index = $visible.Count - 1
            if ($View.Selected -ne $visible[$index].Event.RecordId) { $View.DetailsOffset = 0 }
            $View.Selected = $visible[$index].Event.RecordId
        }
        $mode = if ($View.Follow) { 'LIVE' } else { 'HOLD' }
        $filter = @('ALL', 'SUSPICIOUS+CRITICAL', 'CRITICAL')[$View.Severity]
        $lines.Add([pscustomobject]@{ Text = "[F: FOLLOW LATEST] $mode | collected $($View.Collected) | buffer $($View.Buffer.Count)/$BufferSize | visible $($visible.Count)"; Color = 'Cyan'; Selected = $false })
        $lines.Add([pscustomobject]@{ Text = "Filter: $filter | ID: $(if ($View.EventId) {$View.EventId} else {'ALL'}) | Search: $($View.Search) | Focus: $($View.Focus) | ProfileCheck: $(if ($ProfileCheck) {'ON'} else {'OFF'})"; Color = 'Gray'; Selected = $false })
        $listRows = [Math]::Max(4, [int][Math]::Floor(($Height - 7) * 0.45))
        $View.PageSize = $listRows
        $lines.Add([pscustomobject]@{ Text = 'EVENTS  Time     Severity   ID   Record  Process / activity'; Color = 'Cyan'; Selected = $false })
        $first = [Math]::Max(0, $index - $listRows + 1)
        $View.FirstVisible = $first
        for ($row = 0; $row -lt $listRows; $row++) {
            $position = $first + $row
            $text = ''
            $color = 'Gray'
            $selected = $false
            if ($position -lt $visible.Count) {
                $record = $visible[$position]
                $selected = $position -eq $index
                $marker = if ($selected) { '>' } else { ' ' }
                $color = switch ($record.Severity) { 'CRITICAL' { 'Red' } 'SUSPICIOUS' { 'Yellow' } default { 'Gray' } }
                $text = '{0} {1:HH:mm:ss} {2,-10} {3,-4} #{4,-6} {5}' -f $marker, $record.Event.TimeCreated, $record.Severity, $record.Event.Id, $record.Event.RecordId, (Get-EventSummary $record.Event $record.Data)
            }
            $lines.Add([pscustomobject]@{ Text = $text; Color = $color; Selected = $selected })
        }
        $details = New-Object 'System.Collections.Generic.List[object]'
        if ($index -ge 0) {
            $record = $visible[$index]
            foreach ($finding in $record.Findings) {
                $color = if ($finding.Severity -eq 'CRITICAL') { 'Red' } else { 'Yellow' }
                foreach ($line in @(Get-TerminalFieldLine '!' $finding.Reason $Width)) {
                    $details.Add([pscustomobject]@{ Text = $line; Color = $color; Selected = $false })
                }
            }
            foreach ($detail in @(Get-EventDetails $record.Event $record.Data $record.Context)) {
                foreach ($line in @(Get-TerminalFieldLine $detail.Label $detail.Value $Width)) {
                    $details.Add([pscustomobject]@{ Text = $line; Color = 'Gray'; Selected = $false })
                }
            }
        }
        $detailRows = $Height - $lines.Count - 4
        $View.DetailsOffset = [Math]::Min($View.DetailsOffset, [Math]::Max(0, $details.Count - $detailRows))
        $lines.Add([pscustomobject]@{ Text = "[Y: COPY DETAILS] $(if ($index -ge 0) {"E$($visible[$index].Event.Id) #$($View.Selected)"} else {'No matching events'}) | lines $(if ($details.Count) { $View.DetailsOffset + 1 } else { 0 })-$([Math]::Min($details.Count, $View.DetailsOffset + $detailRows))/$($details.Count)"; Color = 'Cyan'; Selected = $false })
        for ($row = 0; $row -lt $detailRows; $row++) {
            $position = $View.DetailsOffset + $row
            if ($position -lt $details.Count) { $lines.Add($details[$position]) }
            else { $lines.Add([pscustomobject]@{ Text = ''; Color = 'Gray'; Selected = $false }) }
        }
        $lines.Add([pscustomobject]@{ Text = "Arrows/PgUp/PgDn: scroll | Tab: pane | Home/End | Y copy"; Color = 'Cyan'; Selected = $false })
        $lines.Add([pscustomobject]@{ Text = "F latest P pause | / search I ID S severity C clear Q quit"; Color = 'Cyan'; Selected = $false })
        $prompt = if ($View.Editing) { "$($View.Editing): $($View.Input)_  [Enter apply, Esc cancel] $($View.Message)" } elseif ($View.Message) { $View.Message } else { "Full log: $AlertPath | HOLD stops following; collection continues." }
        $lines.Add([pscustomobject]@{ Text = $prompt; Color = 'Gray'; Selected = $false })
    }
    while ($lines.Count -lt $Height) { $lines.Add([pscustomobject]@{ Text = ''; Color = 'Gray'; Selected = $false }) }
    $lines
}

function Write-SysmonFrame {
    param([object[]]$Frame, [int]$Width, [ConsoleColor]$Background)
    for ($row = 0; $row -lt $Frame.Count; $row++) {
        $text = $Frame[$row].Text -replace '[\x00-\x1f\x7f]', ' '
        if ($text.Length -gt $Width) { $text = $text.Substring(0, $Width) }
        [Console]::SetCursorPosition(0, $row)
        [Console]::ForegroundColor = [ConsoleColor]$Frame[$row].Color
        [Console]::BackgroundColor = if ($Frame[$row].Selected) { [ConsoleColor]::DarkBlue } else { $Background }
        [Console]::Write($text.PadRight($Width))
    }
}

function Get-C2Service {
    param([string]$Name)
    $hostName = $Name.TrimEnd('.').ToLowerInvariant()
    foreach ($domain in $c2ServiceDomains) {
        if ($hostName -eq $domain -or $hostName.EndsWith('.' + $domain)) { return $domain }
    }
}

function New-C2ProfileFinding {
    param([string]$Key, [datetime]$Time, [string]$Severity, [string]$Reason)
    if ($profileAlerts.ContainsKey($Key) -and $profileAlerts[$Key] -ge $Time.AddMinutes(-$WindowMinutes)) { return }
    if ($profileAlerts.Count -ge 4096) { $profileAlerts.Clear() }
    $profileAlerts[$Key] = $Time
    New-SysmonFinding $Severity $Reason
}

function Get-C2ProfileFinding {
    param($Event, [hashtable]$Data)
    if (-not $ProfileCheck) { return }
    $owner = $Data.ProcessGuid
    if (-not $owner) { $owner = "$($Data.Image)|$($Data.ProcessId)" }
    $now = $Event.TimeCreated
    switch ($Event.Id) {
        3 {
            if ($Data.Protocol -notin 'tcp', 'udp') { return }
            $outbound = $Data.Initiated -eq 'true'
            $remoteIp = if ($outbound) { $Data.DestinationIp } else { $Data.SourceIp }
            $port = if ($outbound) { $Data.DestinationPort } else { $Data.SourcePort }
            $localPort = $Data.DestinationPort
            $risky = Get-RiskyExecutable $Data.Image
            $service = Get-C2Service $Data.DestinationHostname
            $key = "$owner|$remoteIp|$port|$($Data.Protocol)|$outbound"
            if ($service) {
                New-C2ProfileFinding "service|$owner|$service" $now 'SUSPICIOUS' "Possible C2 activity: connection to $service; legitimate service use can look the same"
            }
            if ($risky) {
                $direction = if ($outbound) { 'outbound' } else { 'inbound/P2P' }
                New-C2ProfileFinding "socket|$key" $now 'SUSPICIOUS' "Possible C2 activity: $direction $($Data.Protocol) connection involving an executable in a writable location; signature=$risky"
            }
            if ($outbound -and $port -in '1883', '8883') {
                New-C2ProfileFinding "mqtt|$key" $now 'SUSPICIOUS' 'Possible C2 activity: connection to a common MQTT port; broker traffic can be legitimate and the protocol is not verified'
            }
            if ($risky -and ($port -eq '445' -or (-not $outbound -and $localPort -eq '445'))) {
                New-C2ProfileFinding "smb|$key" $now 'SUSPICIOUS' 'Possible C2 activity: SMB connection involving an executable in a writable location; inspect peer and pipe activity'
            }
            if (-not $outbound) { return }
            foreach ($oldKey in @($networkGroups.Keys)) {
                if ($networkGroups[$oldKey].LastSeen -lt $now.AddMinutes(-$WindowMinutes)) { $networkGroups.Remove($oldKey) }
            }
            if (-not $networkGroups.ContainsKey($key)) {
                if ($networkGroups.Count -ge 4096) { $networkGroups.Clear() }
                $networkGroups[$key] = @{ Times = @(); LastSeen = $now }
            }
            $group = $networkGroups[$key]
            $group.Times = @($group.Times | Where-Object { $_ -ge $now.AddMinutes(-$WindowMinutes) })
            $group.LastSeen = $now
            # Parallel sockets at the same instant are not evidence of periodic beaconing.
            if ($group.Times.Count -and ($now - $group.Times[-1]).TotalSeconds -lt 2) { return }
            $group.Times = @($group.Times) + @($now)
            if ($group.Times.Count -gt 5) { $group.Times = $group.Times[-5..-1] }
            if ($group.Times.Count -lt 5) { return }
            $intervals = @(for ($index = 1; $index -lt 5; $index++) { ($group.Times[$index] - $group.Times[$index - 1]).TotalSeconds })
            $mean = ($intervals | Measure-Object -Average).Average
            $maxDeviation = ($intervals | ForEach-Object { [Math]::Abs($_ - $mean) } | Measure-Object -Maximum).Maximum
            if ($maxDeviation -le $mean * 0.25) {
                $severity = if ($risky) { 'CRITICAL' } else { 'SUSPICIOUS' }
                New-C2ProfileFinding "beacon|$key" $now $severity "Possible C2 activity: 5 approximately periodic connections to ${remoteIp}:$port within $WindowMinutes minutes; investigate polling/beaconing (also used by legitimate software)"
            }
        }
        { $_ -in 17, 18 } {
            $risky = Get-RiskyExecutable $Data.Image
            $knownName = $Data.PipeName -match '(?i)^\\(?:postex_|msagent_|status_)|(?:paexec|remcom|csexec|gruntsvc)'
            if ($risky -or $knownName) {
                New-C2ProfileFinding "pipe|$owner|$($Data.PipeName)" $now 'SUSPICIOUS' 'Possible C2 activity: named pipe with a suspicious name or an executable in a writable location; inspect both endpoints'
            }
        }
        7 {
            if ($Data.ImageLoaded -match '(?i)\\(?:wpcap|packet)\.dll$' -and (Get-RiskyExecutable $Data.Image)) {
                New-C2ProfileFinding "capture|$owner" $now 'SUSPICIOUS' 'Possible C2 activity: packet capture library loaded by an executable in a writable location; raw network protocols are not visible in Sysmon network events'
            }
        }
        22 {
            if (-not $Data.QueryName) { return }
            $service = Get-C2Service $Data.QueryName
            if ($service) {
                New-C2ProfileFinding "service|$owner|$service" $now 'SUSPICIOUS' "Possible C2 activity: DNS lookup for $service; legitimate service use can look the same"
            }
            $name = $Data.QueryName.TrimEnd('.').ToLowerInvariant()
            $labels = $name.Split('.')
            $lastEncoded = -1
            for ($index = 0; $index -lt $labels.Length - 2; $index++) {
                if ($labels[$index] -match "^[a-z2-7]{$MinimumLabelLength,63}$") { $lastEncoded = $index }
            }
            if ($lastEncoded -lt 0) { return }
            # This suffix follows the encoded labels; it is not a public-suffix lookup.
            $suffix = $labels[($lastEncoded + 1)..($labels.Length - 1)] -join '.'
            $key = "$owner|$suffix"
            $cutoff = $now.AddMinutes(-$WindowMinutes)
            foreach ($oldKey in @($dnsGroups.Keys)) {
                if ($dnsGroups[$oldKey].LastSeen -lt $cutoff) { $dnsGroups.Remove($oldKey) }
            }
            if (-not $dnsGroups.ContainsKey($key)) {
                if ($dnsGroups.Count -ge 4096) { $dnsGroups.Clear() }
                $dnsGroups[$key] = @{ Names = @{}; LastSeen = $now; Escalated = $false }
                New-SysmonFinding 'SUSPICIOUS' 'Possible C2 activity: long Base32-compatible DNS label; investigate DNS tunneling'
            }
            $group = $dnsGroups[$key]
            foreach ($oldName in @($group.Names.Keys)) {
                if ($group.Names[$oldName] -lt $cutoff) { $group.Names.Remove($oldName) }
            }
            if ($group.Names.Count -lt $DnsThreshold) { $group.Escalated = $false }
            if ($group.Names.Count -ge $DnsThreshold -and -not $group.Names.ContainsKey($name)) {
                $oldestName = $group.Names.Keys | Sort-Object { $group.Names[$_] } | Select-Object -First 1
                $group.Names.Remove($oldestName)
            }
            $group.Names[$name] = $now
            $group.LastSeen = $now
            if ($group.Names.Count -ge $DnsThreshold -and -not $group.Escalated) {
                New-SysmonFinding 'CRITICAL' "Possible C2 activity: $DnsThreshold distinct Base32-looking DNS queries within $WindowMinutes minutes to $suffix; investigate DNS tunneling"
                $group.Escalated = $true
            }
        }
    }
}

function Get-SysmonFinding {
    param($Event, [hashtable]$Data)
    switch ($Event.Id) {
        1 {
            if ($Data.ParentImage -match '\\(w3wp|httpd|apache|php-cgi|nginx|tomcat\d*)\.exe$' -and
                $Data.Image -match '\\(cmd|powershell|pwsh|wscript|cscript|mshta|bash|sh)\.exe$') {
                New-SysmonFinding 'CRITICAL' 'Possible webshell activity: web server spawned a shell or script host; review parent, command line and user'
            }
            $signatureStatus = Get-RiskyExecutable $data.Image
            if ($signatureStatus) {
                New-SysmonFinding 'SUSPICIOUS' "Executable started from a commonly writable location; signature=$signatureStatus"
            }
            if ($data.Image -match '\\(powershell|pwsh)\.exe$' -and
                $data.CommandLine -match '(?i)(?:\s-(?:e|en|enc|enco|encodedcommand)\s|FromBase64String|DownloadString\s*\()') {
                New-SysmonFinding 'SUSPICIOUS' 'Encoded PowerShell or download command; review intent'
            }
        }
        3 {
            if ($data.Initiated -eq 'true') {
                $signatureStatus = Get-RiskyExecutable $data.Image
                $connectionKey = "$($data.ProcessGuid)|$($data.Image)|$($data.DestinationIp)|$($data.DestinationPort)|$($data.Protocol)"
                if ($signatureStatus -and -not $networkAlerts.ContainsKey($connectionKey)) {
                    if ($networkAlerts.Count -ge 4096) { $networkAlerts.Clear() }
                    $networkAlerts[$connectionKey] = $true
                    New-SysmonFinding 'SUSPICIOUS' "Outbound connection from an executable in a commonly writable location; signature=$signatureStatus; investigate unexpected outbound traffic"
                }
            }
            if ($data.DestinationPort -eq '53' -and $data.Initiated -eq 'true' -and
                $ApprovedDnsServer.Count -gt 0 -and $data.DestinationIp -notin $ApprovedDnsServer) {
                New-SysmonFinding 'SUSPICIOUS' 'DNS traffic to a server outside ApprovedDnsServer'
            }
        }
        8 { New-SysmonFinding 'SUSPICIOUS' 'Remote thread creation; possible injection, also used by legitimate software' }
        { $_ -in 19, 20, 21 } {
            New-SysmonFinding 'SUSPICIOUS' 'WMI subscription activity; inspect filter/consumer'
        }
        25 { New-SysmonFinding 'CRITICAL' "Process tampering detected: $($data.Type)" }
        255 { New-SysmonFinding 'CRITICAL' "Sysmon error; telemetry may be missing: $($data.Description)" }
    }
    if ($ProfileCheck) { Get-C2ProfileFinding $Event $Data }
}

if (-not $MonitorOnly) {
    $configPath = Join-Path $PSScriptRoot 'umd.xml'
    $null = [xml](Get-Content -LiteralPath $configPath -Raw)
    if (-not $SysmonPath) {
        $SysmonPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\Sysmon64.exe'
    }
    $SysmonPath = (Resolve-Path -LiteralPath $SysmonPath).Path
    $signature = Get-AuthenticodeSignature -LiteralPath $SysmonPath
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw 'The Sysmon executable does not have a valid Microsoft signature.'
    }
    $service = Get-Service -Name Sysmon, Sysmon64 -ErrorAction SilentlyContinue
    # Sysmon writes normal status messages to stderr; check its exit code directly.
    $operation = if ($service) { '-c' } else { '-i' }
    $installer = Start-Process -FilePath $SysmonPath -ArgumentList @('-accepteula', $operation, ('"' + $configPath + '"')) -NoNewWindow -Wait -PassThru
    try {
        if ($installer.ExitCode -ne 0) { throw "Sysmon configuration failed (exit $($installer.ExitCode))." }
    }
    finally { $installer.Dispose() }
    foreach ($item in @(Get-Service -Name Sysmon, Sysmon64 -ErrorAction SilentlyContinue)) {
        if ($item.Status -ne 'Running') { Start-Service -Name $item.Name }
    }
    & wevtutil.exe sl $logName /e:true /ms:268435456
    if ($LASTEXITCODE -ne 0) { throw 'Could not enable/resize the Sysmon event log.' }
    Write-Host 'Sysmon is running with umd.xml. Logging continues when this script exits.'
}
if (-not ($Monitor -or $MonitorOnly)) { return }

$null = Get-WinEvent -ListLog $logName -ErrorAction Stop
$alertDirectory = Split-Path -Parent $AlertPath
if ($alertDirectory) { $null = New-Item -Path $alertDirectory -ItemType Directory -Force }
$processes = @{}
$dnsGroups = @{}
$signatureCache = @{}
$networkAlerts = @{}
$profileAlerts = @{}
$networkGroups = @{}
$c2ServiceDomains = @(
    'discord.com', 'discordapp.com', 'discord.gg', 'slack.com', 'slack-edge.com'
    'api.github.com', 'raw.githubusercontent.com', 'gitee.com', 'blob.core.windows.net'
    'graph.microsoft.com', 'teams.microsoft.com', 'tailscale.com'
)
$cursor = 0L
$startTime = (Get-Date).ToUniversalTime().AddMinutes(-$LookBackMinutes).ToString('o')
$categories = @{
    1 = 'Processes'; 2 = 'Files'; 3 = 'Network'; 4 = 'Sysmon'; 5 = 'Processes'
    6 = 'Drivers'; 7 = 'Modules'; 8 = 'Injection'; 9 = 'Disk access'; 10 = 'Process access'
    11 = 'Files'; 12 = 'Registry'; 13 = 'Registry'; 14 = 'Registry'; 15 = 'Files'
    16 = 'Sysmon'; 17 = 'Pipes'; 18 = 'Pipes'; 19 = 'WMI'; 20 = 'WMI'; 21 = 'WMI'
    22 = 'DNS'; 23 = 'Files'; 24 = 'Clipboard'; 25 = 'Injection'; 26 = 'Files'
    27 = 'Files'; 28 = 'Files'; 29 = 'Files'; 255 = 'Sysmon'
}
$useTui = $false
if (-not ($NoTui -or $Once) -and $Host.Name -eq 'ConsoleHost') {
    try {
        $useTui = -not ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected)
        if ($useTui) { $null = [Console]::KeyAvailable }
    }
    catch { Write-Verbose "Interactive console unavailable: $_"; $useTui = $false }
}
$view = @{
    Buffer = New-Object 'System.Collections.Generic.List[object]'
    Selected = 0L; Follow = $true; Focus = 'Events'; DetailsOffset = 0
    Severity = 0; EventId = 0; Search = ''; Editing = ''; Input = ''; Message = ''
    PageSize = 10; FirstVisible = 0; Quit = $false; Collected = 0
}
$nextPoll = [datetime]::MinValue
$dirty = $true
$lastWidth = 0
$lastHeight = 0
$consoleReady = $false
$mouseInput = $false
try {
    if ($useTui) {
        $originalForeground = [Console]::ForegroundColor
        $originalBackground = [Console]::BackgroundColor
        $originalCursor = [Console]::CursorVisible
        $consoleReady = $true
        [Console]::Clear()
        [Console]::CursorVisible = $false
        try {
            Initialize-SysmonInput
            [CcdcSysmon.ConsoleInput]::Enable()
            $mouseInput = $true
        }
        catch { Write-Verbose "Mouse input unavailable; use F or Ctrl+End to follow latest: $_" }
    }
    else {
        Write-Host "Showing all collected Sysmon events. Full details: $AlertPath. Ctrl+C stops this monitor; Sysmon keeps logging."
    }
    do {
        if ((Get-Date) -ge $nextPoll) {
            $latest = Get-SysmonEvent -XPath '*' -Limit 1
            if ($null -ne $latest -and $latest.RecordId -lt $cursor) {
                if (-not $useTui) { Write-Warning 'Sysmon log was cleared or replaced; resetting the monitor cursor.' }
                $cursor = 0L
                $startTime = (Get-Date).ToUniversalTime().ToString('o')
                $dnsGroups.Clear()
                $processes.Clear()
                $signatureCache.Clear()
                $networkAlerts.Clear()
                $profileAlerts.Clear()
                $networkGroups.Clear()
                $view.Buffer.Clear()
                $view.Selected = 0L
                $dirty = $true
            }
            $position = if ($cursor -eq 0) { "TimeCreated[@SystemTime >= '$startTime']" } else { "EventRecordID > $cursor" }
            $events = @(Get-SysmonEvent -XPath "*[System[$position]]" -Oldest)
            $records = @(foreach ($event in $events) {
                $data = ConvertFrom-SysmonEvent $event
                $findings = @(Get-SysmonFinding $event $data)
                $priority = if ($findings.Severity -contains 'CRITICAL') { 2 } elseif ($findings.Severity -contains 'SUSPICIOUS') { 1 } else { 0 }
                $severity = @('INFO', 'SUSPICIOUS', 'CRITICAL')[$priority]
                $category = $categories[[int]$event.Id]
                if (-not $category) { $category = 'Other' }
                $context = Get-ProcessContext $event $data
                $searchText = @($event.Id; $severity; $category; $data.Values; $context.Values; $findings.Reason) -join ' '
                [pscustomobject]@{
                    Event = $event; Data = $data; Findings = $findings; Priority = $priority
                    Severity = $severity; Category = $category; Context = $context; SearchText = $searchText
                }
            })
            Write-SysmonBatch -Records $records
            if ($events.Count -gt 0) {
                $cursor = $events[-1].RecordId
                $view.Collected += $records.Count
                if ($useTui) {
                    foreach ($record in $records) { $view.Buffer.Add($record) }
                    if ($view.Buffer.Count -gt $BufferSize) { $view.Buffer.RemoveRange(0, $view.Buffer.Count - $BufferSize) }
                    $dirty = $true
                }
            }
            if ($Once) { break }
            # Drain queued batches immediately; otherwise wait for new events.
            $nextPoll = if ($events.Count -ge 1000) { Get-Date } else { (Get-Date).AddSeconds($PollSeconds) }
        }
        if ($useTui) {
            if ($mouseInput) {
                foreach ($inputEvent in @([CcdcSysmon.ConsoleInput]::ReadPending())) {
                    if ($inputEvent.Type -eq 1 -and $inputEvent.KeyDown) {
                        $key = [ConsoleKeyInfo]::new([char]$inputEvent.Character, [ConsoleKey]$inputEvent.VirtualKey,
                            [bool]($inputEvent.Control -band 16), [bool]($inputEvent.Control -band 3), [bool]($inputEvent.Control -band 12))
                        for ($repeat = 0; $repeat -lt [Math]::Max(1, $inputEvent.Repeat); $repeat++) { Update-SysmonView $view $key }
                        $dirty = $true
                    }
                    elseif ($inputEvent.Type -eq 2) {
                        $wheel = if ($inputEvent.MouseFlags -eq 4) { [int]($inputEvent.Buttons -shr 16); } else { 0 }
                        if ($wheel -gt 32767) { $wheel -= 65536 }
                        if ($wheel -or ($inputEvent.MouseFlags -eq 0 -and ($inputEvent.Buttons -band 1))) {
                            Update-SysmonPointer $view $inputEvent.MouseX ($inputEvent.MouseY - [Console]::WindowTop) $wheel
                            $dirty = $true
                        }
                    }
                    elseif ($inputEvent.Type -eq 4) { $dirty = $true }
                }
            }
            else {
                while ([Console]::KeyAvailable) {
                    Update-SysmonView $view ([Console]::ReadKey($true))
                    $dirty = $true
                }
            }
            if ($view.Quit) { break }
            $width = [Math]::Max(1, [Console]::WindowWidth - 1)
            $height = [Math]::Max(1, [Console]::WindowHeight - 1)
            if ($dirty -or $width -ne $lastWidth -or $height -ne $lastHeight) {
                $frame = @(Get-SysmonFrame $view $width $height)
                try {
                    Write-SysmonFrame $frame $width $originalBackground
                    $lastWidth = $width; $lastHeight = $height; $dirty = $false
                }
                catch [ArgumentOutOfRangeException] {
                    # Resizing can invalidate a frame between measuring and drawing it.
                    $dirty = $true
                }
            }
            Start-Sleep -Milliseconds 100
        }
        elseif ($events.Count -lt 1000) { Start-Sleep -Seconds $PollSeconds }
    } while ($true)
}
finally {
    if ($mouseInput) {
        try { [CcdcSysmon.ConsoleInput]::Restore() }
        catch { Write-Warning "Could not restore the console input mode: $_" }
    }
    if ($consoleReady) {
        [Console]::ForegroundColor = $originalForeground
        [Console]::BackgroundColor = $originalBackground
        [Console]::CursorVisible = $originalCursor
        [Console]::Clear()
    }
    Write-Host "Monitor stopped. Sysmon continues logging. Full details: $AlertPath"
}
