# Monitoring

These are separate from the first 15 scripts. Keep the monitor windows open. Ctrl+C stops them.

## persistence.ps1

Run as administrator in 64-bit Windows PowerShell. Keep the `vendor` folder beside the script; PersistenceSniper is included, so nothing downloads when you run it.

Run hardening first so its intentional task removals are not treated as new findings. Then capture the current state:

```powershell
.\persistence.ps1 -CaptureBaseline
```

It prints the baseline and CSV paths. **Review the CSV. Existing persistence can already be in the baseline. Capturing it does not make the box clean. PLEASE DON'T FORGET THIS!!!!!!!!!!!!!!!!!!!**

Then start monitoring:

```powershell
.\persistence.ps1
```

It compares against that same baseline and shows:

- `ADDED`: a new entry.
- `MODIFIED`: an entry's definition/value changed.
- `REMOVED`: an entry from the baseline is gone.
- `RETURNED`: an entry returned to its baseline state.

Before/after details appear below each change. Repeated identical findings are suppressed while the monitor stays open. Restarting shows outstanding differences again.

Tasks, service definitions, WMI subscriptions and machine Run keys are checked every 15 seconds. PersistenceSniper attempts its supported checks individually every five minutes, including service/task checks. A failing check does not stop the remaining checks. The scans run in sequence; slow scans increase the time between checks. Changes that appear and disappear between scans can be missed. Keep Sysmon collecting too.

The baseline stays fixed. To deliberately capture another baseline, choose a new `-BaselinePath`. Existing baselines are never overwritten. The script rejects a baseline from another host or PersistenceSniper version.

### Arguments

- `-CaptureBaseline`: saves a baseline and a CSV to review, then exits.
- `-BaselinePath`: chooses the baseline file. Default: `C:\ProgramData\CCDC\Monitoring\persistence-baseline.xml`.
- `-Once`: compares once and exits.
- `-IntervalSeconds`: delay between definition checks. Default: 15.
- `-SniperIntervalSeconds`: minimum time between PersistenceSniper scans. Default: 300.
- `-LogPath`: changes the text log. Default: `C:\ProgramData\CCDC\Monitoring\persistence.log`.
- `-PassThru`: also returns objects for automation.
- `-ModulePath`: uses another compatible PersistenceSniper module.

Logs and baseline exports can contain task arguments, paths and account details. Keep them private when copying them off-host.

## security-watch.ps1

Run as administrator in another window:

```powershell
.\security-watch.ps1
```

Shows account creation, enable/disable/deletion, password change/reset attempts, account changes, lockouts, group membership changes and audit policy changes. Privileged group additions and Security-log clearing are `CRITICAL`. Other group changes still appear, including groups with custom delegated rights. Severity is a reason to investigate, not proof of an attack. Authorized administrator actions appear too.

Individual failed logons are summarized into bursts: five failures within 60 seconds for the same account or source, counted separately for each event type. This covers logon failures (4625), Kerberos preauthentication failures (4771) and failed NTLM credential validation (4776). It reports another alert at each threshold multiple. Raw failures stay in the Windows Security log.

At startup, the script enables the required audit settings on this computer: Logon, Credential Validation and Kerberos Authentication Service failures, plus User Account Management, Security Group Management and Audit Policy Change successes/failures. Existing success auditing stays enabled. It also makes advanced audit subcategories take precedence over legacy audit categories. This works on DCs, member servers and workstations without running hardening first. It does not edit domain GPOs; domain policy can overwrite these settings later. Audit settings remain enabled when the viewer exits.

- `-LookbackMinutes`: initial history to review. Default: 5; use 0 for new events only.
- `-FailureThreshold`: failures needed for a burst. Default: 5.
- `-FailureWindowSeconds`: burst window. Default: 60.
- `-IntervalSeconds`: polling delay. Default: 3.
- `-Once`: reviews the initial history and exits.
- `-LogPath`: chooses the JSON-lines alert log. Default: `C:\ProgramData\CCDC\Monitoring\security.log`.
- `-PassThru`: also returns alert objects.

Run on each box. DCs receive domain account changes; workstations receive local account changes and local logon events. Logs can roll over before the monitor reads them. It warns about observed unread-record gaps or a record-number reset. It cannot recover erased events or prevent someone with administrator access from stopping it.