# Backups

This saves Windows configuration into a local ZIP you can copy to your host. Run as administrator on each Windows box:

```powershell
$backup = .\backup.ps1
```

The terminal prints the ZIP path. **Copy it off the VM. A backup left only on the box will not help if you lose the box.**

## What it saves

- Firewall rules, security policy and audit policy.
- Network settings and share definitions for reference.
- On DCs: GPO backups, a GPO report, and domain/user/group reference exports.
- On DNS servers: primary zone exports, zone metadata and forwarders. `dns-zone-map.jsonl` maps zone names to their export files.
- On DHCP servers: configuration and leases.
- On IIS servers: IIS configuration.
- Any extra files/folders you supply. `content-map.jsonl` records their original paths.

To include website content or another folder:

```powershell
$backup = .\backup.ps1 -ContentPath 'C:\inetpub\wwwroot','C:\ScoredApp'
```

Website content is only included when you supply its path. IIS configuration alone does not contain the website files.

## Check the result

`Complete: True` means the selected exports finished without reported errors. If something fails, the script warns, continues with the other sections, and records the error in `report.json`. Check that file before relying on the backup.

The timestamped folder is kept next to the ZIP so you can inspect the files. Existing backup folders/files are never overwritten.

**This is not a full AD/system-state backup. It does not save account passwords or provide automatic restoration. Database files copied while running may not be consistent. ZIP files do not preserve NTFS permissions.**

The output is restricted to Administrators and SYSTEM on the VM. The ZIP is not encrypted and may contain application secrets; keep the host copy private.

## Arguments

- `-ContentPath`: extra files/folders to copy.
- `-OutputDirectory`: chooses a new local backup folder. The ZIP uses the same path with `.zip` added.
- `-WhatIf`: previews without creating a backup.

## Restore

See [RECOVERY.md](RECOVERY.md) for extracting the ZIP and selectively restoring files, DNS, GPOs or firewall configuration. AD exports are references, not a full domain backup.
