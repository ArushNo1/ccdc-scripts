#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Compares PersistenceSniper findings and task/service/WMI/Run-key definitions with a fixed baseline.
#>
[CmdletBinding()]
param(
    [switch]$CaptureBaseline,
    [string]$BaselinePath = (Join-Path $env:ProgramData 'CCDC\Monitoring\persistence-baseline.xml'),
    [string]$ModulePath = (Join-Path $PSScriptRoot 'vendor\PersistenceSniper\PersistenceSniper.psd1'),
    [ValidateRange(5, 3600)][int]$IntervalSeconds = 15,
    [ValidateRange(30, 86400)][int]$SniperIntervalSeconds = 300,
    [string]$LogPath = (Join-Path $env:ProgramData 'CCDC\Monitoring\persistence.log'),
    [switch]$Once,
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) { throw 'Run in 64-bit Windows PowerShell.' }
if ($CaptureBaseline -and (Test-Path -LiteralPath $BaselinePath)) { throw 'Baseline already exists. Review it and choose a new -BaselinePath to capture another.' }
if (-not $CaptureBaseline -and -not (Test-Path -LiteralPath $BaselinePath)) { throw 'Capture and review a baseline first with -CaptureBaseline.' }
$module = Import-Module -Name $ModulePath -PassThru -Force
$moduleVersion = $module.Version.ToString()
$script:sniperItems = @()
$script:lastSniperScan = [datetime]::MinValue

function New-PersistenceRecord {
    param([string]$Source, [string]$Name, [string]$Value)
    [pscustomobject]@{ Source = $Source; Name = $Name; Value = $Value }
}

function Get-PersistenceSnapshot {
    $items = New-Object 'System.Collections.Generic.List[object]'
    foreach ($service in Get-CimInstance Win32_Service) {
        $value = [ordered]@{ Account = $service.StartName; StartMode = $service.StartMode; Path = $service.PathName } | ConvertTo-Json -Compress
        $items.Add((New-PersistenceRecord 'Service' $service.Name $value))
    }
    foreach ($task in Get-ScheduledTask) {
        # Full XML includes triggers, principals, actions, settings and enabled state.
        $xml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
        $items.Add((New-PersistenceRecord 'Task' ($task.TaskPath + $task.TaskName) $xml))
    }
    foreach ($class in '__EventFilter', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__FilterToConsumerBinding') {
        foreach ($item in Get-CimInstance -Namespace root/subscription -ClassName $class) {
            $properties = [ordered]@{}
            foreach ($property in $item.CimInstanceProperties | Sort-Object Name) { $properties[$property.Name] = $property.Value }
            $identity = if ($class -eq '__FilterToConsumerBinding') {
                ConvertTo-Json -InputObject @($item.Filter, $item.Consumer) -Compress
            } else { $item.Name }
            $items.Add((New-PersistenceRecord 'WMI' ($class + '|' + $identity) ($properties | ConvertTo-Json -Compress -Depth 8)))
        }
    }
    foreach ($key in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce') {
        if (Test-Path -LiteralPath $key) {
            $registry = Get-Item -LiteralPath $key
            foreach ($name in $registry.GetValueNames()) {
                $value = [ordered]@{ Kind = $registry.GetValueKind($name).ToString(); Data = $registry.GetValue($name, $null, 'DoNotExpandEnvironmentNames') } | ConvertTo-Json -Compress -Depth 5
                $items.Add((New-PersistenceRecord 'Run key' ($key + '\' + $name) $value))
            }
        }
    }
    if (((Get-Date) - $script:lastSniperScan).TotalSeconds -ge $SniperIntervalSeconds) {
        Write-Host 'Scanning PersistenceSniper findings...'
        # Upstream assumes StrictMode is off and suppresses many missing-artifact errors.
        $script:sniperErrors = New-Object 'System.Collections.Generic.List[object]'
        $command = Get-Command Find-AllPersistence
        $methods = @($command.Parameters['PersistenceMethod'].Attributes | Where-Object { $_ -is [Management.Automation.ValidateSetAttribute] } | ForEach-Object ValidValues | Where-Object { $_ -notin 'All', 'Services' })
        if ($methods.Count -eq 0) { throw 'PersistenceSniper does not expose its supported checks.' }
        # Isolate each check: one upstream exception must not abort every later check.
        $findings = @(foreach ($method in $methods) {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $context = $identity.Impersonate()
            try {
                & {
                    Set-StrictMode -Off
                    Find-AllPersistence -PersistenceMethod $method -IncludeHighFalsePositivesChecks -ErrorAction Stop
                }
            } catch {
                $script:sniperErrors.Add([pscustomobject]@{ Check = $method; Error = $_.Exception.Message; ScriptStackTrace = $_.ScriptStackTrace })
            } finally {
                # Some upstream checks impersonate SYSTEM; restore the caller even if they fail.
                $context.Undo()
                $context.Dispose()
                $identity.Dispose()
            }
        })
        if ($script:sniperErrors.Count) {
            $errorLog = $LogPath + '.sniper-errors.log'
            foreach ($problem in $script:sniperErrors) {
                Add-Content -LiteralPath $errorLog -Value ("[$(Get-Date -Format o)] $($problem.Check): $($problem.Error)`r`n$($problem.ScriptStackTrace)") -Encoding UTF8
            }
            Write-Warning "PersistenceSniper reported $($script:sniperErrors.Count) errors; its scan may be incomplete. Details: $errorLog"
        }
        $newSniperItems = @(
            $findings | Group-Object Technique, Path | ForEach-Object {
                $values = @($_.Group | ForEach-Object Value | Sort-Object -Unique)
                New-PersistenceRecord 'PersistenceSniper' ($_.Group[0].Technique + '|' + $_.Group[0].Path) (ConvertTo-Json -InputObject $values -Compress)
            }
        )
        if ($script:sniperErrors.Count) {
            # An incomplete broad scan must not turn unreturned findings into removals.
            $merged = @{}
            foreach ($item in $script:sniperItems) { $merged[$item.Name] = $item }
            foreach ($item in $newSniperItems) { $merged[$item.Name] = $item }
            $script:sniperItems = @($merged.Values)
        } else {
            $script:sniperItems = $newSniperItems
        }
        $script:lastSniperScan = Get-Date
    }
    foreach ($item in $script:sniperItems) { $items.Add($item) }
    $items.ToArray()
}

function ConvertTo-PersistenceMap {
    param([object[]]$Items)
    $map = @{}
    foreach ($item in $Items) {
        $key = $item.Source + '|' + $item.Name
        if ($map.ContainsKey($key)) { throw "Duplicate persistence identity: $key" }
        $map[$key] = $item
    }
    $map
}

function Write-PersistenceChange {
    param([string]$Change, [object]$Item, [AllowNull()][string]$Before, [AllowNull()][string]$After)
    $row = [pscustomobject]@{ Time = (Get-Date).ToString('o'); Change = $Change; Source = $Item.Source; Name = $Item.Name; Before = $Before; After = $After }
    $color = if ($Change -eq 'REMOVED' -or $Change -eq 'RETURNED') { 'Cyan' } else { 'Yellow' }
    $line = '[{0}] {1} | {2} | {3}' -f (Get-Date -Format 'HH:mm:ss'), $Change, $Item.Source, $Item.Name
    Write-Host $line -ForegroundColor $color
    if ($null -ne $Before) { Write-Host "  Before: $Before" }
    if ($null -ne $After) { Write-Host "  After:  $After" }
    Add-Content -LiteralPath $LogPath -Value ($line + "`r`n  Before: $Before`r`n  After: $After") -Encoding UTF8
    if ($PassThru) { $row }
}

foreach ($path in $BaselinePath, $LogPath) {
    $parent = Split-Path -Parent $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
    if (-not (Test-Path -LiteralPath $parent)) { $null = New-Item -Path $parent -ItemType Directory -Force }
}
Write-Warning 'Review the initial findings. A baseline is not proof the host is clean; PersistenceSniper scans are best effort and only cover supported checks and loaded user hives.'
if ($CaptureBaseline) {
    $items = @(Get-PersistenceSnapshot)
    $null = ConvertTo-PersistenceMap $items
    [pscustomobject]@{ SchemaVersion = 1; Computer = $env:COMPUTERNAME; ModuleVersion = $moduleVersion; Collected = (Get-Date).ToString('o'); Items = $items } |
        Export-Clixml -LiteralPath $BaselinePath -Depth 12 -NoClobber
    $csvPath = [IO.Path]::ChangeExtension($BaselinePath, '.csv')
    $items | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 -NoClobber
    Write-Host "Baseline captured: $BaselinePath"
    Write-Host "Review findings: $csvPath"
    if ($PassThru) { [pscustomobject]@{ BaselinePath = $BaselinePath; ReviewPath = $csvPath; Count = $items.Count } }
    return
}
$baseline = Import-Clixml -LiteralPath $BaselinePath
if ($baseline.SchemaVersion -ne 1 -or $baseline.Computer -ne $env:COMPUTERNAME -or $baseline.ModuleVersion -ne $moduleVersion) {
    throw 'Baseline must use this host, schema and PersistenceSniper version.'
}
$baselineMap = ConvertTo-PersistenceMap @($baseline.Items)
$script:sniperItems = @($baseline.Items | Where-Object Source -eq 'PersistenceSniper')
$previousDeviations = @{}
Write-Host "Watching persistence. Baseline stays fixed: $BaselinePath"
Write-Host "Definitions every $IntervalSeconds seconds; PersistenceSniper every $SniperIntervalSeconds seconds. Log: $LogPath. Ctrl+C stops."
do {
    try {
        $current = ConvertTo-PersistenceMap @(Get-PersistenceSnapshot)
        $deviations = @{}
        foreach ($key in @(@($baselineMap.Keys) + @($current.Keys) | Sort-Object -Unique)) {
            $before = if ($baselineMap.ContainsKey($key)) { $baselineMap[$key].Value } else { $null }
            $after = if ($current.ContainsKey($key)) { $current[$key].Value } else { $null }
            if ([string]::Equals($before, $after, [StringComparison]::Ordinal)) { continue }
            $change = if (-not $baselineMap.ContainsKey($key)) { 'ADDED' } elseif (-not $current.ContainsKey($key)) { 'REMOVED' } else { 'MODIFIED' }
            $item = if ($current.ContainsKey($key)) { $current[$key] } else { $baselineMap[$key] }
            $fingerprint = ConvertTo-Json -InputObject @($change, $before, $after) -Compress
            $deviations[$key] = [pscustomobject]@{ Fingerprint = $fingerprint; Item = $item; Before = $before; After = $after }
            if (-not $previousDeviations.ContainsKey($key) -or $previousDeviations[$key].Fingerprint -cne $fingerprint) {
                Write-PersistenceChange $change $item $before $after
            }
        }
        foreach ($key in @($previousDeviations.Keys)) {
            if (-not $deviations.ContainsKey($key)) {
                $old = $previousDeviations[$key]
                Write-PersistenceChange 'RETURNED' $old.Item $old.After $old.Before
            }
        }
        $previousDeviations = $deviations
        Write-Host ('[{0}] Checked | {1} entries differ from baseline' -f (Get-Date -Format 'HH:mm:ss'), $deviations.Count)
    } catch {
        $line = '[{0}] SCAN FAILED | {1}' -f (Get-Date -Format 'HH:mm:ss'), $_.Exception.Message
        Write-Warning $line
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
        if ($Once) { throw }
        # Keep the last successful comparison; a failed scan must not become removals.
    }
    if ($Once) { break }
    Start-Sleep -Seconds $IntervalSeconds
} while ($true)
