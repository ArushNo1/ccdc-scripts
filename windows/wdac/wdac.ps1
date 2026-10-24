#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Manage')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Disable')]
    [switch]$Disable,
    [Parameter(ParameterSetName = 'Manage')]
    [switch]$Deploy,
    [Parameter(ParameterSetName = 'Manage')]
    [switch]$Interactive,
    [Parameter(ParameterSetName = 'Manage')]
    [string[]]$AllowProgram,
    [Parameter(ParameterSetName = 'Manage')]
    [string]$RefreshToolPath,
    [Parameter(ParameterSetName = 'Manage')]
    [guid]$AdoptPolicyId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw 'This policy-management script needs a WDAC-trusted FullLanguage session. The active policy must already trust this script or its signing certificate.'
}
Import-Module ConfigCI

function get-policyxml {
    param([string]$Path)
    [xml]$document = Get-Content -LiteralPath $Path -Raw
    $document
}


function get-policyid {
    param([xml]$Policy)
    $node = $Policy.DocumentElement.SelectSingleNode("*[local-name()='PolicyID']")
    if ($null -eq $node) { $node = $Policy.DocumentElement.SelectSingleNode("*[local-name()='PolicyTypeID']") }
    if ($null -eq $node) { throw 'Policy has no identity.' }
    ([guid]$node.InnerText).ToString('B').ToUpperInvariant()
}

function get-deploymentprofile {
    param([int]$Build, [int]$ProductType)
    if ($Build -lt 10240 -or $ProductType -notin 1, 2, 3 -or ($ProductType -ne 1 -and $Build -lt 14393)) {
        throw 'WDAC requires Windows 10 or Windows Server 2016 or newer.'
    }
    $multiple = if ($ProductType -eq 1) { $Build -ge 18362 } else { $Build -ge 20348 }
    $refresh = if ($ProductType -eq 1) { $Build -ge 16299 } else { $Build -ge 17763 }
    [pscustomobject]@{ Multiple = $multiple; Refresh = $refresh; Build = $Build }
}

function assert-policyformat {
    param([xml]$Policy, [bool]$Multiple)
    $id = $Policy.DocumentElement.SelectSingleNode("*[local-name()='PolicyID']")
    $base = $Policy.DocumentElement.SelectSingleNode("*[local-name()='BasePolicyID']")
    $type = $Policy.DocumentElement.SelectSingleNode("*[local-name()='PolicyTypeID']")
    if ($Multiple) {
        if ($null -eq $id -or $null -eq $base -or $id.InnerText -ne $base.InnerText) {
            throw 'Expected a multiple-format base policy. Existing single policies require explicit migration.'
        }
    } elseif ($null -ne $id -or $null -ne $base -or $null -eq $type -or $Policy.DocumentElement.HasAttribute('PolicyType')) {
        throw 'Expected single-policy XML from this OS template. Refusing automatic policy-format conversion.'
    }
}

function set-recommendedversions {
    param([xml]$Policy, [int]$Build)
    if ($Build -ne 14393) { return }
    $limits = @{ 'msxml3.dll' = '8.110.14393.2550'; 'msxml6.dll' = '6.30.14393.2550'; 'jscript9.dll' = '11.0.14393.2607' }
    foreach ($name in $limits.Keys) {
        $nodes = @($Policy.SelectNodes("//*[local-name()='Deny' and @FileName='$name']"))
        if ($nodes.Count -ne 1) { throw "Expected one recommended rule for $name" }
        $nodes[0].SetAttribute('MaximumFileVersion', $limits[$name])
    }
}

function set-policyoptions {
    param([string]$Path)
    # Remove by name: older ConfigCI versions do not recognize newer option numbers.
    $policy = get-policyxml $Path
    $remove = @('Enabled:Audit Mode', 'Enabled:Boot Audit on Failure', 'Disabled:Script Enforcement',
        'Enabled:Managed Installer', 'Enabled:Intelligent Security Graph Authorization', 'Enabled:Allow Supplemental Policies')
    if (-not $deployment.Refresh) { $remove += 'Enabled:Update Policy No Reboot' }
    foreach ($rule in @($policy.SiPolicy.Rules.Rule)) {
        if ($rule.Option -in $remove) { $null = $rule.ParentNode.RemoveChild($rule) }
    }
    $policy.Save($Path)
    foreach ($option in 0, 6, 9) { Set-RuleOption -FilePath $Path -Option $option }
    if ($deployment.Refresh) { Set-RuleOption -FilePath $Path -Option 16 }
}


function remove-legacyhostblocks {
    param([string]$Path)
    $policy = get-policyxml $Path
    $namespace = New-Object Xml.XmlNamespaceManager($policy.NameTable)
    $namespace.AddNamespace('ci', 'urn:schemas-microsoft-com:sipolicy')
    # Older builds added these rules separately; the XML now supplies the blocklist.
    $managedXPath = "/ci:SiPolicy/ci:FileRules/ci:Deny[starts-with(@ID,'ID_DENY_APPCTRL_HOST_') or starts-with(@ID,'ID_DENY_CCDC_HOST_')]"
    $managedRules = @($policy.SelectNodes($managedXPath, $namespace))
    foreach ($rule in $managedRules) {
        foreach ($reference in @($policy.SelectNodes("//ci:FileRuleRef[@RuleID='$($rule.ID)']", $namespace))) {
            $null = $reference.ParentNode.RemoveChild($reference)
        }
        $null = $rule.ParentNode.RemoveChild($rule)
    }
    foreach ($attribute in $policy.SelectNodes('//@FriendlyName')) {
        $attribute.Value = $attribute.Value -replace '(?i)CCDC','ApplicationControl'
    }
    $policy.Save($Path)
    Write-Host "Removed $($managedRules.Count) obsolete host rules; using the XML blocklist."
    Write-Warning 'Retest scored applications, logon scripts and scheduled tasks. AllowProgram exceptions do not override explicit denies.'
}


function merge-recommendedblocks {
    param([string]$Path)
    $snapshot = Join-Path $PSScriptRoot 'rules.xml'
    $baseline = get-policyxml $Path
    $blocks = get-policyxml $snapshot
    $ns = New-Object Xml.XmlNamespaceManager($blocks.NameTable)
    $ns.AddNamespace('ci','urn:schemas-microsoft-com:sipolicy')
    if ($blocks.SelectNodes('//ci:Allow | //ci:AllowedSigner | /ci:SiPolicy/ci:Signers/*',$ns).Count) {
        throw 'The recommended-rule snapshot must contain deny rules only.'
    }
    # Import deny rules while retaining this base policy's enforcement options.
    set-recommendedversions $blocks $deployment.Build
    $null = $blocks.SiPolicy.ReplaceChild($blocks.ImportNode($baseline.SiPolicy.Rules,$true),$blocks.SiPolicy.Rules)
    $inputPath = Join-Path $policyDirectory 'Recommended.merge.xml'
    $outputPath = Join-Path $policyDirectory 'Recommended.merged.xml'
    try {
        $blocks.Save($inputPath)
        $null = Merge-CIPolicy -PolicyPaths @($Path,$inputPath) -OutputFilePath $outputPath
        Move-Item -LiteralPath $outputPath -Destination $Path -Force
    } finally {
        foreach ($temporary in $inputPath,$outputPath) {
            if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
        }
    }
}

function invoke-policyrefresh {
    param([string]$ToolPath)
    & $ToolPath
    if ($LASTEXITCODE -ne 0) {
        throw "Policy was staged, but RefreshPolicy returned $LASTEXITCODE. Check CodeIntegrity logs before assuming activation."
    }
}

$workingDirectory = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($workingDirectory)) {
    $location = Get-Location
    if ($location.Provider.Name -ne 'FileSystem') { throw 'Run from a filesystem folder.' }
    $workingDirectory = $location.Path
}
if ([string]::IsNullOrWhiteSpace($RefreshToolPath)) {
    $RefreshToolPath = Join-Path $workingDirectory 'RefreshPolicy.exe'
}
$policyDirectory = Join-Path $workingDirectory 'wdac-policy'
$xmlPath = Join-Path $policyDirectory 'MicrosoftOnly.xml'
$template = Join-Path $env:windir 'schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml'
$activeDirectory = Join-Path $env:windir 'System32\CodeIntegrity\CiPolicies\Active'
$legacyPath = Join-Path $env:windir 'System32\CodeIntegrity\SiPolicy.p7b'
$apply = $Deploy -or $Interactive
$os = Get-CimInstance Win32_OperatingSystem
$deployment = get-deploymentprofile -Build ([int]$os.BuildNumber) -ProductType ([int]$os.ProductType)
Write-Host "WDAC build $($deployment.Build): multiple-policy format=$($deployment.Multiple); rebootless updates=$($deployment.Refresh)"

if ($Disable) {
    if (-not (Test-Path -LiteralPath $xmlPath -PathType Leaf)) {
        throw 'Disable requires wdac-policy\MicrosoftOnly.xml from this policy deployment. Run from the original script folder.'
    }
    $managedPolicy = get-policyxml $xmlPath
    assert-policyformat $managedPolicy $deployment.Multiple
    $policyId = get-policyid $managedPolicy
    $options = @($managedPolicy.SiPolicy.Rules.Rule | ForEach-Object { $_.Option })
    if ('Enabled:Unsigned System Integrity Policy' -notin $options) {
        throw 'This switch only removes unsigned policies created by this script. Signed policies need a signed removal update first.'
    }
    $relativePaths = @("CiPolicies\Active\$policyId.cip")
    $savedBinary = Join-Path $policyDirectory "$policyId.cip"
    if (-not $deployment.Multiple) {
        $relativePaths += 'SiPolicy.p7b'
        $savedBinary = Join-Path $policyDirectory 'Deployed-SiPolicy.p7b'
    }
    if (-not (Test-Path -LiteralPath $savedBinary -PathType Leaf)) {
        throw "Missing saved deployed policy: $savedBinary"
    }
    if (-not $PSCmdlet.ShouldProcess($policyId, 'Remove the managed unsigned WDAC policy; reboot required')) { return }

    $unsignedBinary = Join-Path $env:TEMP ('WDAC-unsigned-check-' + [guid]::NewGuid().ToString('N') + '.cip')
    $mountPoint = Join-Path $env:SystemDrive ('WDAC-EFI-' + [guid]::NewGuid().ToString('N'))
    $mounted = $false
    $removedPaths = @()
    try {
        # Recompiling proves the matching binary is our unsigned build, not a signed replacement.
        $null = ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $unsignedBinary
        $expectedHash = (Get-FileHash -LiteralPath $unsignedBinary -Algorithm SHA256).Hash
        if ((Get-FileHash -LiteralPath $savedBinary -Algorithm SHA256).Hash -ne $expectedHash) {
            throw 'Saved XML and deployed build differ. Restore the matching deployment XML before disabling.'
        }

        $roots = @((Join-Path $env:windir 'System32\CodeIntegrity'))
        $efiPartitions = @(Get-Partition | Where-Object {
            $_.IsSystem -and $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        })
        if ($efiPartitions.Count -gt 1) { throw 'Multiple system EFI partitions found; removal needs manual review.' }
        if ($efiPartitions.Count -eq 1) {
            $volumes = @($efiPartitions[0].AccessPaths | Where-Object { $_ -like '\\?\Volume{*' })
            if ($volumes.Count -ne 1) { throw 'Cannot determine the system EFI volume path.' }
            $null = New-Item -Path $mountPoint -ItemType Directory
            & mountvol.exe $mountPoint $volumes[0]
            if ($LASTEXITCODE -ne 0) { throw "Could not mount the EFI system partition: $LASTEXITCODE" }
            $mounted = $true
            $roots += Join-Path $mountPoint 'EFI\Microsoft\Boot'
        }

        # Check every copy before deleting any; another policy may occupy the legacy filename.
        $targets = @(foreach ($root in $roots) {
            foreach ($relativePath in $relativePaths) {
                $path = Join-Path $root $relativePath
                if (Test-Path -LiteralPath $path -PathType Leaf) {
                    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $expectedHash) {
                        throw "Policy copy differs from our unsigned build; no removal performed: $path"
                    }
                    $path
                }
            }
        })
        foreach ($path in $targets) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            $removedPaths += $path
        }
    } catch {
        Write-Warning "Removal stopped. Removed $($removedPaths.Count) files so far."
        throw
    } finally {
        if (Test-Path -LiteralPath $unsignedBinary) { Remove-Item -LiteralPath $unsignedBinary -ErrorAction Stop }
        if ($mounted) {
            & mountvol.exe $mountPoint /D
            if ($LASTEXITCODE -ne 0) { Write-Warning "Could not unmount EFI at $mountPoint. Unmount it manually." }
            else { Remove-Item -LiteralPath $mountPoint -ErrorAction Stop }
        } elseif (Test-Path -LiteralPath $mountPoint -PathType Container) {
            Remove-Item -LiteralPath $mountPoint -ErrorAction Stop
        }
    }
    Write-Warning 'Restart Windows to complete removal. WDAC may still be enforcing until then'
    [pscustomobject]@{
        PolicyId = $policyId
        RemovedPaths = $removedPaths
        RebootRequired = $true
        RemovalVerified = $false
    }
    return
}

if ($deployment.Multiple -and ($apply -or $AllowProgram) -and -not (Test-Path -LiteralPath $RefreshToolPath -PathType Leaf)) {
    throw 'Place Microsoft RefreshPolicy.exe beside this script, or supply -RefreshToolPath.'
}
if ($apply -or $AllowProgram) {
    $automaticAllow = @($PSCommandPath)
    if ($deployment.Multiple) {
    $refreshSignature = Get-AuthenticodeSignature -LiteralPath $RefreshToolPath
    if ($refreshSignature.Status -ne 'Valid' -or $refreshSignature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw 'The policy refresh tool must have a valid Microsoft signature.'
    }
        $automaticAllow += $RefreshToolPath
    }
    $AllowProgram = @(@($AllowProgram; $automaticAllow) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
}
if ($apply -and $deployment.Multiple -and (Test-Path -LiteralPath $legacyPath)) {
    throw 'An existing legacy policy needs review before this script can deploy.'
}

$activePolicies = @()
if (Test-Path -LiteralPath $activeDirectory -PathType Container) {
    $activePolicies = @(Get-ChildItem -LiteralPath $activeDirectory -Filter '*.cip')
}
$adopting = $PSBoundParameters.ContainsKey('AdoptPolicyId')
if ($adopting) {
    if (-not $deployment.Multiple) { throw 'AdoptPolicyId is only supported for multiple-policy deployments.' }
    if (-not $apply) { throw 'Use -AdoptPolicyId together with -Deploy or -Interactive.' }
    # Migration is explicit because the old script did not preserve matching XML.
    $policyId = $AdoptPolicyId.ToString('B').ToUpperInvariant()
    $oldBinary = Join-Path $policyDirectory "$policyId.cip"
    $deployedBinary = Join-Path $activeDirectory "$policyId.cip"
    if (-not (Test-Path -LiteralPath $oldBinary) -or -not (Test-Path -LiteralPath $deployedBinary)) {
        throw 'Adoption requires both the saved build and its staged binary.'
    }
    if ((Get-FileHash -LiteralPath $oldBinary).Hash -ne (Get-FileHash -LiteralPath $deployedBinary).Hash) {
        throw 'Saved and staged binaries differ; adoption stopped.'
    }
    Write-Warning 'Adoption rebuilds the Microsoft-only baseline under this ID; exceptions in the old policy will not be recovered.'
} elseif (Test-Path -LiteralPath $xmlPath) {
    $existing = get-policyxml $xmlPath
    assert-policyformat $existing $deployment.Multiple
    $policyId = get-policyid $existing
} elseif ($activePolicies.Count) {
    throw 'Existing policies have no matching source XML here. Supply the matching XML, or explicitly adopt a saved Microsoft-only build.'
} else {
    $policyId = if ($deployment.Multiple) { [guid]::NewGuid().ToString('B').ToUpperInvariant() } else { get-policyid (get-policyxml $template) }
}

if ($apply) {
    if (-not $deployment.Multiple -and (Test-Path -LiteralPath $legacyPath)) {
        $savedLegacy = Join-Path $policyDirectory 'Deployed-SiPolicy.p7b'
        if (-not (Test-Path -LiteralPath $xmlPath) -or -not (Test-Path -LiteralPath $savedLegacy)) {
            throw 'Existing single policy requires matching source XML and the saved deployed SiPolicy.p7b.'
        }
        if ((Get-FileHash -LiteralPath $legacyPath).Hash -ne (Get-FileHash -LiteralPath $savedLegacy).Hash) {
            throw 'Saved and deployed single policies differ. Refusing to overwrite an unmanaged policy.'
        }
    }
    $unmanaged = @($activePolicies | Where-Object { $_.BaseName -ne $policyId })
    if ($unmanaged.Count) { throw 'Other WDAC policies are staged. Review them before adding exceptions; another base policy may still block the file.' }
}
if (-not $PSCmdlet.ShouldProcess($policyDirectory, "Prepare policy $policyId")) { return }

$null = New-Item -Path $policyDirectory -ItemType Directory -Force
$workPath = Join-Path $policyDirectory 'Pending.xml'
$creating = $adopting -or -not (Test-Path -LiteralPath $xmlPath)
if ($creating) {
    if (-not (Test-Path -LiteralPath $template)) { throw "Missing template: $template" }
    Copy-Item -LiteralPath $template -Destination $workPath -Force
    if ($deployment.Multiple) {
    $null = Set-CIPolicyIdInfo -FilePath $workPath -PolicyName 'Microsoft Only Application Control' -ResetPolicyID
    $document = get-policyxml $workPath
    $document.SiPolicy.PolicyID = $policyId
    $document.SiPolicy.BasePolicyID = $policyId
    $document.Save($workPath)
    } else {
        assert-policyformat (get-policyxml $workPath) $false
        $null = Set-CIPolicyIdInfo -FilePath $workPath -PolicyName 'Microsoft Only Application Control'
    }
} else {
    Copy-Item -LiteralPath $xmlPath -Destination $workPath -Force
}
set-policyoptions $workPath

if ($AllowProgram) {
    $programPaths = @(foreach ($programPath in $AllowProgram) {
        $program = Get-Item -LiteralPath $programPath
        if ($program.PSIsContainer -or $program.PSProvider.Name -ne 'FileSystem') {
            throw "Select one filesystem executable, script or dependency: $programPath"
        }
        $program.FullName
    })
    $rules = New-CIPolicyRule -DriverFilePath $programPaths -Level Hash
    if (-not $rules.Count) { throw 'No hash allowances generated.' }
    $mergedPath = Join-Path $policyDirectory 'Merged.xml'
    $null = Merge-CIPolicy -PolicyPaths $workPath -OutputFilePath $mergedPath -Rules $rules
    Move-Item -LiteralPath $mergedPath -Destination $workPath -Force
    Write-Host "Added hash allowances for $($programPaths.Count) files."
}

if ($Interactive) {
    Write-Host 'Rules apply to files and signers, not process names. Approve dependencies separately.'
    while ($true) {
        Write-Host "`n1: Allow one file by hash"
        Write-Host '2: Allow a signed file by publisher, filename, and minimum version'
        Write-Host '3: Trust a signing certificate for user-mode code'
        Write-Host '4: Apply and refresh now'
        Write-Host '5: Cancel pending changes'
        $choice = Read-Host 'Choose 1-5'
        if ($choice -eq '5') { Remove-Item -LiteralPath $workPath; return }
        if ($choice -eq '4') { break }
        if ($choice -notin '1', '2', '3') { Write-Host 'Choose 1-5.'; continue }
        $inputPath = (Read-Host 'Full path to the file or .cer certificate').Trim().Trim('"')
        try {
            $item = Get-Item -LiteralPath $inputPath
            if ($item.PSIsContainer -or $item.PSProvider.Name -ne 'FileSystem') { throw 'Select one filesystem file.' }
            $inputPath = $item.FullName
            if ($choice -eq '3') {
                if ($item.Extension -ne '.cer') { throw 'Select an exported public signing certificate (.cer).' }
                $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($inputPath)
                try {
                    $certificate | Select-Object Subject, Issuer, Thumbprint, NotAfter | Format-List | Out-Host
                    $isCA = @($certificate.Extensions | Where-Object {
                        $_.Oid.Value -eq '2.5.29.19' -and $_.CertificateAuthority
                    }).Count -gt 0
                    if ($isCA) { throw 'Choose a leaf code-signing certificate, rather than a CA certificate.' }
                    Write-Host 'This trusts user-mode code signed by this certificate, beyond a single application.'
                    if ((Read-Host 'Add this signer? Type yes') -ne 'yes') { continue }
                    Add-SignerRule -FilePath $workPath -CertificatePath $inputPath -User
                } finally { $certificate.Dispose() }
            } else {
                $signature = Get-AuthenticodeSignature -LiteralPath $inputPath
                Get-FileHash -LiteralPath $inputPath | Format-List Path, Hash | Out-Host
                $signature | Select-Object Status, StatusMessage, SignerCertificate | Format-List | Out-Host
                if ($choice -eq '2' -and $signature.Status -ne 'Valid') { throw 'FilePublisher needs a valid signed file. Use hash for an unsigned file.' }
                $level = if ($choice -eq '1') { 'Hash' } else { 'FilePublisher' }
                if ((Read-Host "Add $level allowance? Type yes") -ne 'yes') { continue }
                $rules = New-CIPolicyRule -DriverFilePath $inputPath -Level $level
                if (-not $rules.Count) { throw 'No rules were generated.' }
                $mergedPath = Join-Path $policyDirectory 'Merged.xml'
                $null = Merge-CIPolicy -PolicyPaths $workPath -OutputFilePath $mergedPath -Rules $rules
                Move-Item -LiteralPath $mergedPath -Destination $workPath -Force
            }
        } catch {
            Write-Warning $_.Exception.Message
            continue
        }
        Write-Host 'Allowance added to pending policy.'
    }
}

# Merge the blocklist, then remove rules added separately by older builds.
merge-recommendedblocks $workPath
remove-legacyhostblocks $workPath
$null = Set-CIPolicyIdInfo -FilePath $workPath -PolicyName 'Microsoft Only Application Control'
$document = get-policyxml $workPath
assert-policyformat $document $deployment.Multiple
if ((get-policyid $document) -ne $policyId) {
    throw 'Policy identity changed unexpectedly. No deployment performed.'
}
$options = @($document.SiPolicy.Rules.Rule | ForEach-Object { $_.Option })
if ('Enabled:UMCI' -notin $options -or 'Enabled:Audit Mode' -in $options -or
    'Disabled:Script Enforcement' -in $options -or
    ($deployment.Refresh -and 'Enabled:Update Policy No Reboot' -notin $options) -or
    (-not $deployment.Refresh -and 'Enabled:Update Policy No Reboot' -in $options)) {
    throw 'Expected enforced user-mode control with policy refresh enabled.'
}
$version = [version]$document.SiPolicy.VersionEx
if ($version.Revision -ge 65535) { throw 'Policy revision limit reached.' }
$newVersion = '{0}.{1}.{2}.{3}' -f $version.Major, $version.Minor, $version.Build, ($version.Revision + 1)
Set-CIPolicyVersion -FilePath $workPath -Version $newVersion
$pendingBinary = Join-Path $policyDirectory 'Pending.cip'
$null = ConvertFrom-CIPolicy -XmlFilePath $workPath -BinaryFilePath $pendingBinary

$binaryPath = Join-Path $policyDirectory "$policyId.cip"
$archiveXml = Join-Path $policyDirectory "$policyId.xml"
$destination = Join-Path $activeDirectory "$policyId.cip"
if (-not $deployment.Multiple) {
    $binaryPath = Join-Path $policyDirectory 'SiPolicy.p7b'
    $destination = $legacyPath
}
$deploymentAction = if ($deployment.Refresh) { 'Update policy and request refresh' } else { 'Stage policy for activation at next reboot' }
if ($apply -and -not $PSCmdlet.ShouldProcess($destination, $deploymentAction)) { return }

$backupDirectory = Join-Path $policyDirectory ('backups\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -Path $backupDirectory -ItemType Directory -Force
foreach ($path in @($xmlPath, $archiveXml, $binaryPath)) {
    if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination $backupDirectory }
}
if ($apply -and (Test-Path -LiteralPath $destination)) {
    Copy-Item -LiteralPath $destination -Destination (Join-Path $backupDirectory 'Deployed.cip')
}
if ($apply) {
    $null = New-Item -Path (Split-Path -Parent $destination) -ItemType Directory -Force
    Copy-Item -LiteralPath $pendingBinary -Destination $destination -Force
    if (-not $deployment.Multiple) {
        Copy-Item -LiteralPath $pendingBinary -Destination (Join-Path $policyDirectory 'Deployed-SiPolicy.p7b') -Force
    }
}
Copy-Item -LiteralPath $workPath -Destination $xmlPath -Force
Copy-Item -LiteralPath $workPath -Destination $archiveXml -Force
Copy-Item -LiteralPath $pendingBinary -Destination $binaryPath -Force
Write-Host "Policy XML: $archiveXml"
Write-Host "Compiled policy: $binaryPath"
Write-Host "Previous files: $backupDirectory"
if ($apply) {
    if ($deployment.Multiple) {
        invoke-policyrefresh $RefreshToolPath
    } elseif ($deployment.Refresh) {
        $result = Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{FilePath = $destination} -ErrorAction Stop
        if ($null -eq $result.ReturnValue -or $result.ReturnValue -ne 0) { throw "Policy staged; WMI refresh failed: $($result.ReturnValue). Check CodeIntegrity logs." }
    }
    if ($deployment.Refresh) {
        Write-Host "Refresh requested for $policyId. Verify event 3099 and retest the application. No restart requested."
    } else {
        Write-Warning 'Policy staged only. Reboot required for activation; no restart was requested. Enforcement has not been verified.'
    }
    [pscustomobject]@{ PolicyId = $policyId; Destination = $destination; RebootRequired = -not $deployment.Refresh; ActivationVerified = $false }
}









