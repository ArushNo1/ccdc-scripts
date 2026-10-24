# Ubuntu Email Server Hardening Checklist (Postfix + Dovecot, Ubuntu 22.04)

**Target:** `172.20.240.15` (public `172.25.20+team#.15`). Scored: SMTP, POP3/IMAP/Webmail with AD usernames.

**Ordering:** ranked by (impact x exploitability) / remediation cost, where cost includes the risk of breaking scoring. This is my judgment, not measured data. Items P1 to P5 should take under 15 minutes total. Everything past P6 is optional if you are short on time.

**Research caveats:** The relay and smuggling items come from Postfix docs and Ubuntu/Debian security trackers. The Dovecot and persistence items are partly from general knowledge, so test them in the Proxmox mock before trusting them. The webmail app and auth backend are unknown. Step 0 finds out.

**Scoring rules that constrain you:**
- Don't rename users, hosts, or IPs.
- Don't filter public services by source IP, and no knife-edge allowlisting for the scorer.
- Keep ICMP.
- Preserve existing mail when changing or replacing services.
- Changes that break scoring are your penalty, not theirs.

**Working loop:** one change, reload, check Quotient, then the next change. Keep the Step 0 tarball for rollback.

---

## Step 0. Backup and enumerate (2 minutes, do first)

- [ ] Back up configs and mail:
```bash
mkdir -p /root/bak && cd /root/bak
tar czf etc-mail-$(date +%F-%H%M).tar.gz /etc/postfix /etc/dovecot /etc/aliases /etc/sssd /etc/krb5.conf 2>/dev/null
tar czf spool-$(date +%F-%H%M).tar.gz /var/mail /var/spool/postfix /home/*/Maildir 2>/dev/null
```
- [ ] Enumerate listeners, processes, versions, and config:
```bash
ss -tulpn
ps auxf | grep -Ei 'postfix|dovecot|apache|nginx|php|sssd'
postconf -n ; postconf -M          # active main.cf + all master.cf services
doveconf -n
postconf -h mail_version ; dovecot --version
apt list --upgradable 2>/dev/null | grep -Ei 'postfix|dovecot|roundcube|php|openssl'
```
- [ ] Identify webmail (Roundcube/SquirrelMail/other) and its web server: `ls /var/www /usr/share/roundcube 2>/dev/null; systemctl list-units --type=service --state=running`
- [ ] Note the auth backend (PAM/SSSD, LDAP, passwd-file, SQL): `doveconf -n | grep -A6 -E 'passdb|userdb'`

---

## P1. Default credentials

- [ ] Change local `sysadmin` password. `Changeme1!` is public in the team pack.
- [ ] Check other local users: `awk -F: '$3>=1000||$3==0{print $1,$3,$7}' /etc/passwd`, and `getent passwd | wc -l` to see if AD users are visible via SSSD.
- [ ] Change scored mail account passwords through the Quotient **PCR tab** (CSV `username,password`). Changes are immediate.
- [ ] Change webmail admin and DB creds (Roundcube DB config, any installer or admin panel).

## P2. Mail-specific persistence hunt (Red Team's favorite)

- [ ] `/etc/aliases`: look for pipes (`|`) and file writes:
```bash
grep -nE '^\s*[^#].*(\||:include:|/)' /etc/aliases ; newaliases
```
- [ ] Forwards and BCC exfil:
```bash
find / -name .forward 2>/dev/null
postconf | grep -E 'bcc|always_bcc|canonical|virtual_alias|transport_maps|mailbox_command|recipient_canonical'
```
- [ ] Postfix map files referenced in `postconf -n`: read every file they point to.
- [ ] Sieve scripts with `pipe`, `execute`, or forwarding: `find / -name '*.sieve' -o -name '.dovecot.sieve' 2>/dev/null`
- [ ] Package integrity (catches replaced binaries or configs):
```bash
debsums -c postfix dovecot-core dovecot-imapd dovecot-pop3d 2>/dev/null || dpkg -V postfix dovecot-core
ls -l /usr/sbin/postdrop /usr/sbin/postqueue   # should be setgid postdrop
```
- [ ] Cron, systemd, and users: `crontab -l -u root; ls /etc/cron.*; systemctl list-unit-files --state=enabled`
- [ ] New UID 0 users and unexpected SSH keys in `/root/.ssh` and `/home/*/.ssh` (overlaps with the persistence person, so coordinate).
- [ ] Stuck or odd mail queue: `postqueue -p | tail`

## P3. Web shells in the webmail root

- [ ] Recently modified PHP files and suspicious functions:
```bash
find /var/www /usr/share/roundcube -name '*.php' -mmin -120 2>/dev/null
grep -rlE 'eval\(|base64_decode|system\(|shell_exec|passthru' /var/www 2>/dev/null
```
- [ ] Remove the installer directory if present (e.g. Roundcube `installer/`).
- [ ] Confirm web root ownership and permissions: not world-writable.

## P4. Listener and `master.cf` audit

- [ ] Compare `ss -tulpn` against what should be listening (25, 587, 110, 143, 993, 995, 80, 443, SSH). Investigate anything else.
- [ ] Review `master.cf` (`postconf -M`) for anything unexpected: extra `inet` listeners on odd ports, `pipe` transports, `-o` overrides that loosen restrictions, `content_filter` or `receive_override_options` entries, `smtpd_milters`.
- [ ] Check Dovecot service sockets: no `auth-master` or `auth-userdb` listener with loose permissions. Run `ls -la /var/run/dovecot/ /var/spool/postfix/private/`.

## P4b. IMAP/POP3 service sanity (do right after P4)

- [ ] Dovecot is up, enabled, and listening:
```bash
systemctl is-active dovecot; systemctl is-enabled dovecot
ss -tlnp | grep -E ':(110|143|993|995)\b'
```
- [ ] Core settings that matter for scoring:
```bash
doveconf -n | grep -E '^(protocols|mail_location|mail_plugins|first_valid_uid|auth_username_format|mail_max_userip_connections)'
```
- [ ] Mailbox permissions: nothing world-readable (data leak and possible privesc path):
```bash
ls -ld /var/mail/* /home/*/Maildir 2>/dev/null
find /home /var/mail -maxdepth 2 -perm -o+r \( -name Maildir -o -type f \) 2>/dev/null | head
```

## P5. Open relay test (fix only if open)

Ubuntu's default is not an open relay, so exploitability is lower than it looks. The test takes seconds.

- [ ] Test from Kali against your own public IP (your own box, so allowed):
```bash
swaks --to victim@gmail.com --from test@yourdomain --server 172.25.20.<team#>.15
# expect: 554 5.7.1 Relay access denied
```
- [ ] If it relays, set relay restrictions. The recommended production value is `permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination`:
```bash
postconf -e 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
```
- [ ] Audit `smtpd_recipient_restrictions` for a `permit` that fires before `reject_unauth_destination` (the classic misordering open relay). Remove anything like `permit` or `check_relay_domains` there.
- [ ] Lock down `mynetworks` to loopback only (a wide CIDR is a relay backdoor):
```bash
postconf -e 'mynetworks = 127.0.0.0/8 [::1]/128'
postconf -e 'mynetworks_style = host'
```
  Watch Quotient. If SMTP checks break, the scorer may rely on a network you removed. Add back only the minimum.
- [ ] `postfix check && postfix reload`

## P6. Package and webmail version check

- [ ] Confirm Postfix and Dovecot are current: `apt policy postfix dovecot-core`.
- [ ] Look up the webmail version against known RCE CVEs. Update only if the patch is low-risk. No major version jumps mid-competition.

## P7. Incident reports (20% of score, start at the first Red Team hit)

- [ ] Log source and destination IPs, timestamps, accounts abused, and what was affected:
```bash
grep -E 'NOQUEUE|reject|auth.*fail|SASL' /var/log/mail.log | tail -100
grep -iE 'failed|invalid' /var/log/auth.log | tail -50
```
- [ ] Write a remediation plan for each incident and submit it. Clarity and accuracy score, frivolous reports cost points.

## P8. `sshd` and SSSD

- [ ] `sshd`: key or strong password only, `PermitRootLogin no`, check `AllowUsers` and `authorized_keys`.
- [ ] If SSSD/Kerberos are in use: confirm `/etc/sssd/sssd.conf` perms are 0600, check `realm list`, and make sure `access_provider` isn't `permit` for everyone if that wasn't intended.

## P9. Dovecot auth hygiene and SASL

- [ ] `auth_mechanisms = plain login` only. No `anonymous`.
- [ ] Authentication debug logging off (`auth_debug_passwords` and `mail_debug` leak creds into logs): `doveconf -n | grep -E 'debug|verbose'`
- [ ] Check passdb and userdb for backdoors: extra `passwd-file` or `static` entries, `allow_all_users`, `default_pass_scheme` oddities. Run `doveadm user '*'` and compare against expected users.
- [ ] `login_trusted_networks` empty or minimal. Anything listed there bypasses some auth checks.
- [ ] SASL via Dovecot, if SMTP AUTH is used. The Ubuntu community guide uses socket `mode = 0666`, which is too loose. Use a postfix-owned socket:
```
# /etc/dovecot/conf.d/10-master.conf
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
```
  Postfix side: `smtpd_sasl_type = dovecot`, `smtpd_sasl_path = private/auth`, `smtpd_sasl_auth_enable = yes`.
- [ ] Don't disable POP3 or IMAP if scored.

## P9b. IMAP/POP3 brute-force and scorer-compat risks

- [ ] **AD lockout.** Red Team can spray IMAP/POP3 with AD usernames and lock the scored accounts, which takes the service down. Ask your Windows/AD person for the domain lockout threshold, and decide how you will unlock accounts fast.
- [ ] **Username format.** The scorer logs in with AD usernames. A wrong `auth_username_format` or a PAM/SSSD change can break auth for them while local users still work. Test after any auth change.
- [ ] **Test the login flow the way the scorer does** (plain 143/110 versus TLS 993/995):
```bash
doveadm auth test <aduser>          # prompts for the password; stays out of shell history
doveadm user '*'
```
- [ ] Find who is spraying you:
```bash
grep -E 'auth failed|Aborted login' /var/log/mail.log | grep -oE 'rip=[0-9.]+' | sort | uniq -c | sort -rn | head
```
- [ ] Connection limits so spray traffic can't exhaust login processes: set `mail_max_userip_connections` (10 to 20), `default_client_limit`, and `service imap-login { process_limit }` to sane values.
- [ ] **Be careful with fail2ban or IP blocking.** Blocking a specific attacking IP is allowed. An automated tool that bans the scoring engine is your penalty. Ban manually, or use a whitelist plus a high threshold.

## P10. Dovecot plaintext and TLS enforcement (high break risk)

- [ ] **Test before enforcing.** `disable_plaintext_auth = yes` and `ssl = required` are the right end state, but the scorer's POP3/IMAP client may use port 110/143 without TLS. Change it, then watch Quotient for 2 to 3 check cycles. Revert immediately if the IMAP/POP3 checks fail.
- [ ] TLS floor: `ssl_min_protocol = TLSv1.2`, `ssl_prefer_server_ciphers = yes`. Replace any snakeoil cert only if time allows.

## P11. Postfix polish (low impact)

- [ ] SMTP smuggling (CVE-2023-51764). Jammy has a patched package (3.6.4-1ubuntu1.3), but patched versions before 3.9 need these two settings for the fix to apply. The `$mynetworks` exclusion is a scorer-compat risk, so watch Quotient:
```bash
postconf -e 'smtpd_forbid_bare_newline = normalize'
postconf -e 'smtpd_forbid_bare_newline_exclusions = $mynetworks'
```
- [ ] Basic abuse reduction:
```bash
postconf -e 'disable_vrfy_command = yes'
postconf -e 'smtpd_helo_required = yes'
postconf -e 'smtpd_banner = $myhostname ESMTP'     # drop version leakage
postconf -e 'smtpd_client_connection_count_limit = 20'
postconf -e 'smtpd_client_connection_rate_limit = 60'
postconf -e 'message_size_limit = 10485760'
```
  Do **not** add strict HELO/sender-domain rejection rules. They can reject the scoring engine.
- [ ] TLS: offer STARTTLS, don't require it on port 25 (the scorer may not support it):
```bash
postconf -e 'smtpd_tls_security_level = may'
postconf -e 'smtpd_tls_protocols = >=TLSv1.2'
postconf -e 'smtpd_tls_mandatory_protocols = >=TLSv1.2'
postconf -e 'smtpd_tls_auth_only = no'   # flip to yes only after confirming scorer behavior
```
- [ ] `postfix check && postfix reload && postconf -n | head -50`

## P12. Host firewall (last, low value)

- [ ] The Palo Alto already covers the perimeter. Only add host rules if time permits. Allow 25, 587, 110, 143, 993, 995, 80, 443, and ICMP. No source-IP filtering of public services, and no scorer-only rules. Blocking a specific IP that is attacking you is allowed.

---

## Verification (after every change)

- [ ] Quotient/team portal: SMTP, POP3, IMAP, webmail still green.
- [ ] `swaks --to <valid user>@domain --server localhost` delivers.
- [ ] `openssl s_client -starttls smtp -connect localhost:25` negotiates TLS 1.2+.
- [ ] `doveadm auth test <aduser>` succeeds.
- [ ] `tail -f /var/log/mail.log /var/log/auth.log` shows no new errors.

---

## Sources
- [Postfix COMPATIBILITY_README](https://www.postfix.org/COMPATIBILITY_README.html)
- [Netdata: Postfix open relay guide](https://www.netdata.cloud/guides/postfix/postfix-open-relay-unauthorized/)
- [Ubuntu CVE-2023-51764](https://ubuntu.com/security/CVE-2023-51764)
- [Plesk: CVE-2023-51764 mitigation](https://support.plesk.com/hc/en-us/articles/20332057992087)
- [Ubuntu community: Postfix/Dovecot SASL](https://help.ubuntu.com/community/PostfixDovecotSASL)
- [Dovecot + Samba AD config example](https://www.github.com/kurosaki1976/samba-ad-dc-integrated-services/blob/master/confs/mail/dovecot/dovecot.conf)