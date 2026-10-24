# Usage Notes

10/11/2026: Included Microsoft's recommended block rules from https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol and additional denies based on https://github.com/bohops/UltimateWDACBypassList.

10/11/2026: Included an option to remove this script's WDAC policy in case anything goes wrong.

TODO: Remove `wdac.ps1` from the explicit allow cus of Dovetail.

WDAC can be very powerful; however, please note its primary purpose is to limit what red team can do if they get on the box. **You are expected to do the first 15 correctly to not allow red team to get in.** In the unfortunate case that they do, WDAC will severely limit what they can do. This policy allows code trusted by the Microsoft template and any exceptions we add, and blocks everything else by default, aka an implicit deny. I have added additional applications to be denied as they are known to have bypasses. Some rules only deny specific versions or hashes.

To deploy WDAC on first launch, you must run with the `-Deploy` argument. If you do not, all `wdac.ps1` will do is build the policy.

## CLI Arguments

*Use the allow and disable arguments if smth on Quotient goes down after you apply WDAC.*

- `-AllowProgram` adds an allow exception, but cannot override an explicit deny in `rules.xml`. To permit one of those explicitly denied tools, remove its `<Deny>` and corresponding `<FileRuleRef>` from `rules.xml`, then rerun with `-Deploy`. `-AllowProgram` without `-Deploy` only builds the updated policy.
- `-Deploy` rebuilds and deploys the policy, then requests a refresh on supported Windows versions. Server 2016 cannot refresh automatically and unfortunately requires a reboot. Server refresh works on 2019+; this script uses WMI on 2019 and `RefreshPolicy.exe` on 2022+.
- `-RefreshToolPath` selects the refresh executable. It isn't a refresh switch.
- `-Disable` removes this script's WDAC policy. This requires a reboot because the loaded policy may still be enforcing. You must restart. Other WDAC policies can still be active. Run from the original deployment folder with its matching saved XML and binary. The script must already be trusted by the active policy.

## Expected Outputs

### `-Deploy`

```text
PS C:\Users\administrator\Desktop\wdac> .\wdac.ps1 -Deploy
WDAC build 20348: multiple-policy format=True; rebootless updates=True
"Scan completed successfully"
Added hash allowances for 2 files.
Removed 0 obsolete host rules; using the XML blocklist.
WARNING: Retest scored applications, logon scripts and scheduled tasks. AllowProgram exceptions do not override explicit denies.
Policy XML: C:\Users\administrator\Desktop\wdac\wdac-policy\{8641C9FA-143B-425E-8D9E-A57063DEEB23}.xml
Compiled policy: C:\Users\administrator\Desktop\wdac\wdac-policy\{8641C9FA-143B-425E-8D9E-A57063DEEB23}.cip
Previous files: C:\Users\administrator\Desktop\wdac\wdac-policy\backups\20261011-174113-389
Rebootless ConfigCI Policy Refreshing Succeeded!
Refresh requested for {8641C9FA-143B-425E-8D9E-A57063DEEB23}. Verify event 3099 and retest the application. No restart requested.

PolicyId                               Destination                                                                                    RebootRequired ActivationVerified
--------                               -----------                                                                                    -------------- ------------------
{8641C9FA-143B-425E-8D9E-A57063DEEB23} C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{8641C9FA-143B-425E-8D9E-A57063DEEB23}.cip          False              False

PS C:\Users\administrator\Desktop\wdac>
```

### `-Disable`

```text
PS C:\Users\administrator\Desktop\wdac> .\wdac.ps1 -Disable
WDAC build 20348: multiple-policy format=True; rebootless updates=True
WARNING: Restart Windows to complete removal. WDAC may still be enforcing until then

PolicyId        : {8641C9FA-143B-425E-8D9E-A57063DEEB23}
RemovedPaths    : {C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{8641C9FA-143B-425E-8D9E-A57063DEEB23}.cip}
RebootRequired  : True
RemovalVerified : False

PS C:\Users\administrator\Desktop\wdac>
```

### `-AllowProgram -Deploy`

```text
PS C:\Users\administrator\Desktop\wdac> .\wdac.ps1 -AllowProgram "C:\Program Files\SystemInformer\SystemInformer.exe" -Deploy
WDAC build 20348: multiple-policy format=True; rebootless updates=True
"Scan completed successfully"
Added hash allowances for 3 files.
Removed 0 obsolete host rules; using the XML blocklist.
WARNING: Retest scored applications, logon scripts and scheduled tasks. AllowProgram exceptions do not override explicit denies.
Policy XML: C:\Users\administrator\Desktop\wdac\wdac-policy\{8641C9FA-143B-425E-8D9E-A57063DEEB23}.xml
Compiled policy: C:\Users\administrator\Desktop\wdac\wdac-policy\{8641C9FA-143B-425E-8D9E-A57063DEEB23}.cip
Previous files: C:\Users\administrator\Desktop\wdac\wdac-policy\backups\20261011-174637-171
Rebootless ConfigCI Policy Refreshing Succeeded!
Refresh requested for {8641C9FA-143B-425E-8D9E-A57063DEEB23}. Verify event 3099 and retest the application. No restart requested.

PolicyId                               Destination                                                                                    RebootRequired ActivationVerified
--------                               -----------                                                                                    -------------- ------------------
{8641C9FA-143B-425E-8D9E-A57063DEEB23} C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{8641C9FA-143B-425E-8D9E-A57063DEEB23}.cip          False              False

PS C:\Users\administrator\Desktop\wdac>
```

Three hash allowances is normal from above. System Informer (our example), `wdac.ps1` and `RefreshPolicy.exe`. Allowing the EXE does not automatically allow its DLLs or drivers.
