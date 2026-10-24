# FTP Service Hardening Checklist (script scope: FTP daemon only)

Ordered by exploitability × impact, so the first items are what Red Team hits in the first minutes. Creds and firewall are out of scope. The script just has to leave them workable (see the dependency notes at the bottom).

Packet constraints that apply: scorer makes an **authenticated** FTP connection and accesses files. Do not change usernames, hostnames, or IPs. Do not move FTP to another VM or public IP. No source-IP allowlisting or knife-edge rules. Keep ICMP working. If you swap the daemon, preserve users, data, and functionality. Free/open-source software only.

## 0. Preflight (not hardening, but required before any change)
- [ ] Detect the daemon and config path: `ss -tlnp | grep ':21'`, `systemctl list-units | grep -Ei 'ftp'`
- [ ] Back up the config and the FTP root: `cp -a /etc/vsftpd.conf{,.orig}`
- [ ] Record the baseline so you can diff later: file list and hashes of the FTP root, `ls -l` of the daemon binary
- [ ] Define a service check (`ftp`/`lftp` login plus `ls` plus `get`). The script runs it after every step and reverts to `.orig` on failure.

## 1. Anonymous access (trivial initial access)
- [ ] vsftpd: `anonymous_enable=NO`, `anon_upload_enable=NO`, `anon_mkdir_write_enable=NO`, `anon_other_write_enable=NO`, `anon_root` unset
- [ ] proftpd: remove or comment out every `<Anonymous>` block, plus `UserAlias anonymous ftp` lines
- [ ] pure-ftpd: `NoAnonymous yes`
- [ ] Verify: `ftp` as `anonymous` with a blank password gets refused. A real user login still works.

## 2. Backdoored or vulnerable daemon (RCE)
- [ ] Get the version: `vsftpd -v` / `proftpd -v`
- [ ] Flag known-bad versions: vsftpd 2.3.4 (smiley backdoor on port 6200), ProFTPD ≤1.3.5 (mod_copy, CVE-2015-3306), ProFTPD 1.3.3c (backdoored source)
- [ ] Verify package integrity: `rpm -V vsftpd` (Rocky) or `debsums -c vsftpd` (Debian/Ubuntu)
- [ ] Check the binary hasn't been swapped: `ls -l $(which vsftpd)`, compare the hash against the package
- [ ] Update or reinstall the package if the version is old or the integrity check fails
- [ ] Check for a rogue listener: `ss -tlnp` for port 6200 or any odd port owned by the ftpd process
- [ ] proftpd: unload `mod_copy` (`LoadModule mod_copy.c` removed) and disable `SITE CPFR/CPTO`

## 3. Upload-to-execute paths (web shell / script drop)
- [ ] Is the FTP root inside or overlapping the web root (`/var/www`, `/srv/www`, `public_html`)? If so, separate it or make it read-only to FTP users. This is the most common FTP-to-RCE path.
- [ ] FTP root isn't world-writable: `find <ftproot> -perm -o+w`
- [ ] No SUID/SGID files: `find <ftproot> -perm /6000`
- [ ] Scan for dropped files: `.php`, `.jsp`, `.sh`, ELF binaries, `.htaccess` in the FTP tree. Diff against the baseline.
- [ ] `write_enable=NO` unless the scorer or an inject needs uploads. If uploads are needed, restrict the writable dir only.
- [ ] `local_umask=022` (uploads not world-writable). proftpd: `Umask 022`
- [ ] vsftpd: set `chown_uploads=NO` and `anon_world_readable_only=YES`

## 4. Chroot and jail (post-auth escape and traversal)
- [ ] `chroot_local_user=YES` (proftpd: `DefaultRoot ~`)
- [ ] `allow_writeable_chroot=NO`. If the chroot root must be writable, use a non-writable root with a writable subdirectory.
- [ ] No `chroot_list_enable` exceptions unless needed. If used, audit `/etc/vsftpd.chroot_list`.
- [ ] Symlinks inside the FTP tree don't point outside it: `find <ftproot> -type l -exec ls -l {} \;`
- [ ] **Test file access immediately.** Chroot is the #1 way to zero the scorer.

## 5. Who can log in (service-level, not password changes)
- [ ] `userlist_enable=YES`, `userlist_deny=NO`, and an explicit allowlist in `/etc/vsftpd.userlist`. **Include every account the scorer uses.**
- [ ] `/etc/ftpusers` and `/etc/vsftpd.ftpusers` deny root and system accounts
- [ ] `ftp` service account has a non-login shell: `/usr/sbin/nologin`
- [ ] `local_enable=YES` only if local users need FTP. `guest_enable` / `virtual_use_local_privs` reviewed if virtual users are in use.
- [ ] `RequireValidShell on` (proftpd). `RootLogin off` (proftpd).

## 6. Service tampering and persistence
- [ ] `systemctl cat vsftpd`: check `ExecStart`, `ExecStartPre`, `ExecStartPost`, `ExecStop` for injected commands. Check for override drop-ins in `/etc/systemd/system/vsftpd.service.d/`.
- [ ] PAM file for the service (`/etc/pam.d/vsftpd`, `/etc/pam.d/proftpd`): no `pam_permit.so` as a sufficient auth, no unknown modules
- [ ] Config file hasn't been modified to enable something weird: diff against package defaults
- [ ] Config ownership and mode: `chown root:root`, `chmod 600`
- [ ] `/etc/vsftpd/` and `/etc/proftpd/` directories aren't writable by non-root
- [ ] Cron jobs or timers touching the FTP service or FTP root: `grep -ri ftp /etc/cron* /var/spool/cron /etc/systemd/system`

## 7. Protocol-level abuse (bounce, SITE, passive hijack)
- [ ] vsftpd: `port_promiscuous=NO` (blocks FTP bounce), `pasv_promiscuous=NO`
- [ ] proftpd: `AllowForeignAddress off`, `SITE` commands restricted via `<Limit SITE_CHMOD SITE_CPFR SITE_CPTO>` → `DenyAll`
- [ ] `ls_recurse_enable=NO`
- [ ] `ascii_upload_enable=NO`, `ascii_download_enable=NO`
- [ ] `deny_file`/`hide_file` for sensitive patterns (`{.*,*.sh,*.php}`) only if it doesn't touch scored files
- [ ] `seccomp_sandbox=YES` (default), `tcp_wrappers` / `hosts_deny` not used to IP-filter scored sources

## 8. Abuse and DoS limits
- [ ] `max_clients`, `max_per_ip`, `idle_session_timeout`, `data_connection_timeout` set sanely. **Leave `max_per_ip` generous so the scorer isn't throttled.**
- [ ] `pasv_enable=YES` with fixed `pasv_min_port`/`pasv_max_port`. Coordinate the range with whoever owns the firewall.
- [ ] `pasv_address` correct for the "public" IP mapping
- [ ] `delay_failed_login=2`, `max_login_fails=5` (vsftpd 3.0+). Tune so repeated scorer logins don't trip it.

## 9. Transport encryption (optional, high risk to scoring)
- [ ] `ssl_enable=YES` with a cert is allowed, but **do not force TLS** (`force_local_logins_ssl`, `force_local_data_ssl`) unless Quotient is confirmed to speak FTPS. Default assumption: plain FTP scoring.
- [ ] If enabling: `ssl_tlsv1=NO`, `ssl_sslv2=NO`, `ssl_sslv3=NO`, `require_ssl_reuse=NO` (many clients break otherwise)
- [ ] Skip this section entirely unless everything above is green and stable.

## 10. Information leakage
- [ ] `ftpd_banner=` generic string (no software or version). proftpd: `ServerIdent off`, `ServerName` neutral.
- [ ] `hide_ids=YES`
- [ ] `dirmessage_enable=NO`
- [ ] `UseReverseDNS off` (proftpd), `reverse_lookup_enable=NO` (vsftpd)

## 11. Logging (needed for incident reports, 20% of the score)
- [ ] `xferlog_enable=YES`, `xferlog_std_format=NO`, `log_ftp_protocol=YES`, `dual_log_enable=YES`
- [ ] `vsftpd_log_file` points at a file root-owned and not world-readable
- [ ] Confirm the log is growing: `tail -f /var/log/vsftpd.log`
- [ ] Logrotate configured so the log doesn't fill the disk

## 12. Final verify and rollback
- [ ] Restart and confirm: `systemctl restart vsftpd && systemctl is-active vsftpd`
- [ ] `ss -tlnp | grep ':21'` shows the listener
- [ ] Authenticated login, `ls`, `get` known file, `put` test file if uploads are required
- [ ] Passive mode test (`passive` in the client)
- [ ] Test from the "public" IP, not just internal
- [ ] Quotient FTP green within a scoring cycle
- [ ] If red: restore `.orig`, restart, re-apply settings one at a time

## Script design rules
- Idempotent. Re-running changes nothing if already hardened.
- One change, then service check, then continue. Auto-revert that change on failure and log which setting broke it.
- Config edits via a helper that sets or replaces a key rather than appending duplicates.
- Run order matches the section order above.
- Detect vsftpd vs proftpd vs pure-ftpd and branch. Don't assume.

## Dependencies on things this script doesn't own
- **Creds:** the userlist allowlist in section 5 must include the scorer's account. Pull it from whoever owns creds before deploying.
- **Firewall:** the fixed passive range and `pasv_address` in section 8 are useless unless the firewall owner opens the same range. Hand them the numbers.