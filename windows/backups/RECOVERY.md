# Recovery

Copy the ZIP off the VM before making changes. To use it, copy it back and extract into a new folder:

```powershell
Expand-Archive -LiteralPath 'C:\backup.zip' -DestinationPath 'C:\RecoveredBackup'
Get-Content 'C:\RecoveredBackup\report.json'
```

Check `Complete` and the section errors. Restore only the affected service/configuration.

## Files

Read `content-map.jsonl`. Each line has the original `Source` and the folder/file named `Backup` in the extracted ZIP. Copy that item back to the intended location. Stop the application first if its files are in use. Confirm application access afterward; ZIP does not preserve NTFS permissions.

## DNS

Read `dns-zone-map.jsonl` to find the export for your zone. On a DNS server, copy the listed file into `C:\Windows\System32\dns`.

For a missing zone, a file-backed primary zone can load that export:

```powershell
Add-DnsServerPrimaryZone -Name 'example.local' -ZoneFile 'ccdc-FILE-FROM-MAP.dns' -LoadExisting
Resolve-DnsName -Name 'host.example.local' -Server 127.0.0.1
```

Replace both values using the mapping. This creates a file-backed primary, not an AD-integrated replica. It does not restore AD replication, original zone permissions or forwarders. Use `dns-zones.xml` and `dns-forwarders.xml` as references. Do not delete a working domain zone just to import an export. For a few missing records, recreate those records in the existing zone instead.

## GPOs

For a GPO in the same domain, restore a selected backup from the extracted `gpo` folder:

```powershell
Restore-GPO -BackupId 'BACKUP-GUID' -Path 'C:\RecoveredBackup\gpo'
```

The backup GUID is its folder name; `bkupInfo.xml` identifies the original GPO. Check the name before restoring. This overwrites that GPO's settings and can affect linked computers. Domain/OU links and AD permissions are not a full domain recovery. Review links and settings separately before running `gpupdate`.

## Firewall

From the VM console, import the original rules:

```powershell
netsh advfirewall import 'C:\RecoveredBackup\firewall.wfw'
```

This replaces firewall configuration. It can disconnect remote sessions. Check scored services and management access afterward.

## AD limits

`ad-users.xml`, `ad-groups.xml` and `ad-domain.xml` are reference exports. They help inspect identities and memberships; they cannot restore passwords, account SID identity or a lost domain controller. Full AD disaster recovery requires a suitable system-state backup and recovery procedure. The current script does not create one.