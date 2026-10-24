# First 15

Hello wonderful CCDC competitors, this is the first 15 folder, meaning that everything here must run ASAP or else your entire comp will be the worst thing you've ever experienced in your life.

I will break down what each file does here.

## main.ps1

This is the account audit and password rotation script. Run it as administrator.

It manages:

- **DC:** Domain users, excluding `krbtgt`.
- **Workstation or member server:** Local users only.

It displays all users and asks for authorized admins and standard users. Use Quotient to find this information. Include required service accounts or preserve them explicitly. Then it:

- Adds approved admins to Domain Admins on a DC, or local Administrators elsewhere.
- Removes memberships that grant privileged roles from accounts outside your admin list, including through nested groups. It keeps unrelated group memberships.
- Disables accounts absent from both authorized lists, unless preserved.
- Enables password expiration and lets users change their passwords.
- Resets passwords by default, including for accounts it disables, unless their passwords are preserved.

On a DC, it also disables reversible password encryption, DES-only authentication, preauthentication exemptions, and the delegation settings it checks. Approved admins are marked as non-delegatable.

**On a DC, these changes affect domain accounts across the domain AND OTHER BOXES THAT DEPEND ON THE DC. Run the domain rotation on one DC only. Password resets can break services, scheduled tasks, and your current access.**

**BE SURE TO UPLOAD NEW CREDS IT OUTPUTS TO QUOTIENT AND TAKE NOTE OF YOUR NEW PASSWORD. DO NOT FOOLISHLY REQUEST A REVERT OF YOUR BOX AND LOSE POINTS BECAUSE YOU DIDN'T TAKE NOTE OF YOUR NEW PASSWORD**

### Arguments - mainly for debugging

- `-AuthorizedAdmins`: Supplies the approved admin account names.
- `-AuthorizedUsers`: Supplies the approved standard user account names.
- `-NonInteractive`: Skips the account-list prompts. Requires `-AuthorizedAdmins`; supply `-AuthorizedUsers` if there are approved standard users.
- `-PreserveAccount`: Skips all changes for named accounts.
- `-PreservePassword`: Keeps their passwords but still changes privileges and settings.
- `-SkipPasswordReset`: Skips all password resets.
- `-CredentialOutputPath`: Saves generated credentials using Windows DPAPI encryption. Recover them using the same Windows identity on the same machine. Otherwise, new passwords print in plaintext.
- `-WhatIf`: Previews the changes without applying them.

Accounts that are already disabled are not automatically enabled. On workstations and member servers, the script stops if local Administrators contains domain accounts or groups that need separate review.

Windows requires the built-in local Administrator to remain in Administrators. If it is not authorized, the script disables it and rotates its password instead of trying to remove that required membership.


## Nmap vulnerability scan

After running `main.ps1`, run this vulnerability scan from a Linux machine with Nmap installed:

```bash
sudo nmap -sC -sV -sS -p- -T5 --min-rate=5000 --script vuln 192.168.1.182
```

## dc-impacket-hardening.ps1

Run on a writable DC as administrator. Audits the attack paths covered by the bundled Impacket tools, including roasting, relay, exposed credentials, delegation and AD permissions.

```powershell
.\dc-impacket-hardening.ps1                  # Compact grouped audit
.\dc-impacket-hardening.ps1 -Detailed        # Full findings and next steps
.\dc-impacket-hardening.ps1 -PassThru | Export-Csv .\dc-audit.csv -NoTypeInformation
.\dc-impacket-hardening.ps1 -Apply -WhatIf   # Preview baseline changes
.\dc-impacket-hardening.ps1 -Apply           # Apply baseline hardening
Get-Help .\dc-impacket-hardening.ps1 -Full   # Targeted service password rotation and cleanup options
```

Review compatibility before applying: signing/channel binding can reject legacy clients, and service password rotation requires updating every dependency. Password strength cannot be inferred from AD metadata. State backups and rotated passwords use Windows DPAPI; recover them with the same identity on the same machine. Run the audit again after changes and GPO refresh.

## hardening.ps1

This is the Windows hardening script. Run it as administrator on each Windows box:

```powershell
.\hardening.ps1
```

On a DC, it asks whether to disable all GPOs in that domain, including the default policies. This affects the whole domain. It runs `gpupdate /force`, applies hardening, then runs `gpupdate /force` again. Apparently this goes against gamification rules? I don't know. I will probably revamp this before regionals.

### What it does

- SMB signing, SMB1 removal and insecure guest logon restrictions.
- Spooler and RemoteRegistry, both disabled by default.
- Deletes all scheduled tasks, including Microsoft and application tasks. Protected tasks may refuse deletion; failures are reported. Already running task processes are not stopped.
- Print driver installation restrictions.
- UAC, anonymous access restrictions and NTLMv2 enforcement.
- WDigest credential caching and LM hash storage restrictions.
- Remote UAC filtering, which can block WinRM for local admins other than the built-in Administrator.
- LLMNR, NetBIOS, AutoRun and elevated installer restrictions.
- RDP Network Level Authentication.
- If Windows SMTP is installed: restrict relay to approved IPv4 addresses, disable SMTP AUTH and authenticated-user relay bypass, and enable SMTP logging. SMTP restarts to apply these settings.
- Windows Time: cap automatic forward/backward corrections at one hour (keep stricter limits), log time-source changes and jumps over five minutes, and preserve the existing time source and domain hierarchy.
- PowerShell logging, process command-line logging and security auditing.
- Defender scanning, PUA blocking and cloud protection.
- ASR rules against credential theft, vulnerable driver abuse, WMI persistence, Office abuse, executable email content, downloaded script executables and Adobe Reader child processes.
- On DCs: machine-account quota, Netlogon settings, LDAP signing and strict LDAP channel binding.
- On applicable older servers: SIGRed and SMBGhost workarounds. Applying the SIGRed workaround restarts DNS.

### Arguments

- `-WhatIf`: previews changes.
- `-KeepPrinting`: keeps Spooler running.
- `-KeepRemoteRegistry`: keeps RemoteRegistry running.
- `-SmtpRelayIPv4`: individual IPv4 addresses allowed to relay through Windows SMTP. Default: `127.0.0.1` only. Replaces the relay list for every virtual server and configured domain. Include only approved application servers. SMTP AUTH is disabled, so review authenticated submission before applying to an existing mail service.
- `-ASRMode Audit`: audits ASR activity instead of blocking. Existing blocks remain.
- `-SkipASR`: skips ASR configuration.
- `-UpdatePackage`: installs supplied `.msu` updates.
- `-ScanUpdates`: searches Windows Update/WSUS

### SMTP and NTP

The script hardens installed services; it does not install SMTP. Windows Time already provides NTP on DCs. On Server 2016, 2019 or 2022, install the SMTP relay role only where needed:

```powershell
Install-WindowsFeature SMTP-Server,Web-Metabase,Web-Lgcy-Mgmt-Console -IncludeManagementTools
```

Then run hardening with your approved relay clients, for example:

```powershell
.\hardening.ps1 -SmtpRelayIPv4 127.0.0.1,192.168.1.20
```

Replace that example IP. This is an SMTP relay, not a mailbox server. Local-domain mail can still arrive anonymously; forwarding to other domains requires an approved relay IP. This does not configure a smart host or TLS certificate. Windows SMTP is unavailable on Server 2025.

Allow required SMTP TCP 25 and NTP UDP 123 sources using `firewall.ps1`. Hardening does not change firewall rules. Review existing remote-domain routes too.

The NTP check warns if the source is the local clock. Serving NTP does not mean the clock has a synchronized upstream reference. Corrections greater than one hour are rejected; a badly skewed clock needs manual review. Changing the source on the forest-root PDC is a separate decision.

# firewall.ps1

This is the Windows firewall script. Run it as administrator on each Windows box.

It blocks inbound traffic by default and allows outbound traffic by default. It recommends inbound ports based on the box's role and running services. Check Quotient for any custom/scored services it misses.

## Using inventory

From the `first15` folder, run:

```powershell
$inv = .\inventory.ps1 -NetworkOnly
notepad (Join-Path $inv.OutputDirectory 'network-review.txt')
notepad $inv.FirewallInputPath
```

Review the summary and `listeners.csv`. In `firewall-input.json`, set:

- `TrustedSubnets`: sources allowed to reach service ports.
- `ManagementSubnets`: your team's sources for management ports.
- `AdditionalServiceTcpPorts` / `AdditionalServiceUdpPorts`: custom/scored ports to add.

Use JSON lists, such as `["192.168.1.0/24"]` for subnets or `[8080, 8443]` for ports. Replace these examples with what your competition needs.

**Empty service sources mean any IP. Empty management sources use the service sources. If both are empty, management is also open to any IP.**

Then preview and apply:

```powershell
.\firewall.ps1 -InventoryPath $inv.FirewallInputPath -WhatIf
.\firewall.ps1 -InventoryPath $inv.FirewallInputPath
```

`-WhatIf` changes nothing. The apply command shows the final rules and asks before changing the firewall. Import skips the port/source questions; add `-Edit` to get those questions too.

The inventory must be complete and from the same box. Unknown listeners are not automatically allowed. Collect again after changing services.

## Without inventory

From the `first15` folder:

```powershell
.\firewall.ps1
```

It shows recommended ports, then asks for service TCP ports, service UDP ports, management TCP ports, and their source IPs/subnets.

For each port question:

- Press Enter to keep the shown list.
- Type `80,443` to replace the entire list with those ports.
- Type `+8080,8443` to add those ports.
- Type `-135,49152-65535` to remove those exact entries.
- Type `none` to clear the list.

Port ranges are supported. To remove part of a range, replace the list with the ports/ranges you want to keep.

For sources, press Enter to keep the shown sources, or type IPs/subnets separated by commas. `Any` allows every IP.

## What it does

- Enables the firewall on all profiles.
- Replaces existing enabled local inbound rules with your selected allowances.
- Sets default inbound to Block and default outbound to Allow. Existing outbound rules stay in place.
- Recommends AD ports on DCs, including RPC TCP 135 and 49152-65535.
- Recommends DNS TCP/UDP 53, plus common IIS, SQL Server and SMTP ports when those services are running.
- Recommends listening SSH, RDP and WinRM ports, plus AD Web Services on DCs.
- Adds selected DHCP exceptions from any source so discovery works.
- Allows essential ICMP error and IPv6 discovery messages.
- Enables blocked traffic logging.
- Exports the previous firewall settings and prints a rollback command. If applying fails, it attempts to restore the export.
- Stops if domain firewall policy prevents local control.

**Removing AD, SMB or RPC ports can break domain operations, Group Policy and replication. Allowing the dynamic RPC range also permits other TCP listeners in that range. This is not ZeroLogon protection.**

## Arguments

- `-InventoryPath`: imports `firewall-input.json` from inventory.
- `-Edit`: asks the port/source questions when importing inventory.
- `-WhatIf`: previews the rules without prompts or changes.
- `-NonInteractive`: skips all questions and applies the selected rules. Preview first.
- `-TrustedSubnets`: service source IPs/subnets. Overrides the input file's service sources.
- `-ManagementSubnets`: management source IPs/subnets. Overrides the input file's management sources.
- `-ManagementTcpPorts`: management ports to recommend when listening. Defaults to 22, 3389, 5985 and 5986.
- `-ServiceTcpPorts` / `-ServiceUdpPorts`: extra service ports, added to any extras in the input file.
- `-AllowFileSharing` / `-BlockFileSharing`: controls SMB recommendations on non-DCs.
- `-AllowLegacyNetbios`: includes TCP 139 and UDP 137-138.
- `-BlockInboundRpc`: blocks inbound TCP 135 and 49152-65535 from every IP, overriding allows. This can break domain operations and replication. It does not cover every Netlogon transport. Rerun without it to remove this script's block.
- `-BackupDirectory`: chooses where the firewall export is saved.

# inventory.ps1

This is the Windows inventory script. Run it as administrator on each Windows box, from the `first15` folder.

## Quick inventory and firewall setup

Start with the network inventory:

```powershell
$inv = .\inventory.ps1 -NetworkOnly
notepad (Join-Path $inv.OutputDirectory 'network-review.txt')
```

This collects the hostname, IP/DNS settings, services, processes, TCP listeners, UDP endpoints and shares. It saves everything in a new timestamped folder.

### Output files

- `network-review.txt`: the short summary. Start here.
- `listeners.csv`: listeners grouped by process, with paths, services and bind addresses. Shows up to 12 ports per group to keep it readable.
- `listener-endpoints.csv`: every listener and UDP endpoint if you need more detail. Loopback-only endpoints are marked; established TCP connections are excluded.
- `firewall-input.json`: the file the firewall script imports.

Before applying the firewall, open the input file:

```powershell
notepad $inv.FirewallInputPath
```

Check Quotient for scored services and edit these fields as needed:

- `TrustedSubnets`: IPs or subnets allowed to reach service ports.
- `ManagementSubnets`: your team's IPs or subnets for SSH, RDP, WinRM and AD Web Services.
- `AdditionalServiceTcpPorts`: extra TCP ports needed by custom/scored services.
- `AdditionalServiceUdpPorts`: extra UDP ports needed by custom/scored services.

These are JSON lists. For example, a subnet list looks like `["192.168.1.0/24"]` and a port list looks like `[8080, 8443]`. Use your actual competition addresses and required ports.

An empty `TrustedSubnets` list means any IP. An empty `ManagementSubnets` list uses the service sources. With both empty, both allow any IP.

**A listener does not mean we should allow it. Unknown listeners are not automatically added to the firewall allowances.**

Preview the rules, then apply them:

```powershell
.\firewall.ps1 -InventoryPath $inv.FirewallInputPath -WhatIf
.\firewall.ps1 -InventoryPath $inv.FirewallInputPath
```

The first command only previews. The second shows the final rules and asks before applying. Add `-Edit` if you want the port/source questions too.

Use the inventory from that same box. Collect again after changing services. Incomplete input is rejected; input over an hour old produces a warning.

## Full inventory

```powershell
.\inventory.ps1
```

This also collects accounts, scheduled tasks, startup entries, software, security settings, and AD, DNS and IIS details where available. `inventory.txt` is the summary; `inventory.json` has the full details. The firewall files are saved before the slower sections finish.

## Arguments

- `-NetworkOnly`: collects just the network inventory and firewall input.
- `-ShowDetails`: also prints the summary in the terminal.
- `-OutputDirectory`: chooses a new output folder.
