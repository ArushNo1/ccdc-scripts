# DNS Server Hardening Checklist (MWCCDC Invitational #1, Oct 24 2026)

**Read this first:** the 2026 team pack has **no Linux DNS server**. Topology = Rocky Ecom (.10), Ubuntu Email (.15), Debian Splunk (.20), 2022 AD (.100), 2019 MSSQL (.120), 3 workstations, Palo Alto, VyOS. "Ubuntu DNS" only shows up in a stale screenshot from another event. DNS is a scored service, and the only box that can naturally serve it is **2022 AD (172.20.240.100)**.

This checklist covers three cases:
1. **Linux BIND9 box exists** (topology changed / hidden scored service): items 1-20.
2. **DNS is on the Windows AD box**: Appendix A (hand to Windows captain).
3. **Regardless**: items 1, 3, 6, 7, 10 apply to every Linux box (client-side DNS tampering, listeners, creds, SSH).

---

## Scoring scale

Score = (Impact x Exploitability) / Cost. Each 1-5.

- **Impact**: 5 = Red Team gets control or can silently redirect/destroy services; 1 = cosmetic.
- **Exploitability**: 5 = trivial, no auth, one command; 1 = needs chained bugs.
- **Cost**: 1 = under 2 min, no scoring risk; 3 = ~10 min or minor scoring risk; 5 = 30+ min or likely to break a scored check.

Scoring is 40% uptime, 40% injects, 20% IR. **Availability beats elegance.** Never trade a scored check for a theoretical hardening win.

## Hard constraints from the pack (don't violate)

- Don't change hostname, IPs, usernames, VLANs (rules 7, 11). Passwords are fine.
- Public services must answer **all source IPs**. No knife-edge allow-listing of the scorer (rule 9). Blocking specific IPs seen attacking is OK.
- Keep ICMP on (rule 12).
- Don't move services to another VM. Replacing BIND with something else is allowed only if same data/function.
- Only free/open-source software. No offensive scans of anyone.

---

## Step 0: Preflight (5 min, do before any change)

- [ ] **Which box serves DNS?** Quotient (https://quotient.ccdc.events/) services tab: note the DNS check's target IP. Then on every Linux box: `sudo ss -tulpn | grep -E ':53\b'`. If nothing but `systemd-resolved` (127.0.0.53) answers, there is no Linux DNS server: go to Appendix A.
- [ ] **Backup everything** (rollback is your best friend):
  ```bash
  sudo tar czpf /root/dns-baseline-$(date +%s).tgz /etc/bind /etc/named* /var/lib/bind /var/cache/bind /var/named /etc/ssh /etc/resolv.conf /etc/hosts /etc/nsswitch.conf 2>/dev/null
  ```
- [ ] **Know the box:**
  ```bash
  . /etc/os-release; echo $PRETTY_NAME; named -v
  ps -o user=,pid=,cmd= -C named
  sudo named-checkconf -p | less     # EFFECTIVE config incl. every include. Read all of it.
  sudo named-checkconf -z            # loads all zones, flags errors
  ```
  Paths: **Debian/Ubuntu** `/etc/bind/{named.conf,named.conf.options,named.conf.local}`, user `bind`. **Rocky** `/etc/named.conf`, `/var/named`, user `named`. Service is `named` on both (`bind9` alias on Debian/Ubuntu).
- [ ] **Find out what the scorer actually asks** (decides whether recursion can be restricted, item 12):
  ```bash
  sudo tcpdump -ni any -c 60 'port 53 and not src host 127.0.0.1'
  ```
  Run during a scoring cycle. Note the query name(s), type, and source IP. Authoritative names (your zone) only = recursion can be locked down safely. External names (e.g. google.com) = recursion must stay on for the scorer's source.
- [ ] **Dump a golden copy of every zone BEFORE locking transfers** (item 4):
  ```bash
  for z in $(sudo named-checkconf -p | awk -F'"' '/^\s*zone/{print $2}' | grep -v -E '^(\.|localhost|127|0|255)'); do dig @127.0.0.1 $z AXFR +noall +answer | sort > /root/zone-$z.base; done
  ```
- [ ] **Q&A at 7:30, ask White Team:** (a) does a Quotient PCR change only update the scorer's stored credential, or also the VM? (My reading: scorer only. You must change the password on the box too, back-to-back with the PCR.) (b) Which host is the DNS target?

---

## Ranked checklist

### 1. Default credentials: **25** (I5 E5 C1)
All VMs ship with `sysadmin:Changeme1!` and everyone's image is identical, so Red Team knows it.
- [ ] Change `sysadmin` password on the box (`sudo passwd sysadmin`), **then immediately** submit the same via Quotient PCR tab, CSV `sysadmin,<newpass>`. Doing only one breaks the SSH check or leaves a default cred live.
- [ ] Empty passwords / extra UID 0 / odd sudoers:
  ```bash
  sudo awk -F: '($2==""){print "EMPTY PW:",$1}' /etc/shadow
  getent passwd | awk -F: '$3==0{print "UID0:",$1}'
  getent group sudo wheel adm | cut -d: -f1,4
  ```
- [ ] Domain users (SSSD) are Person A's lane. Don't duplicate.

### 2. Dynamic updates / record tampering: **20** (I5 E4 C1)
`allow-update { any; }` lets anyone `nsupdate` your records: redirect ecom/mail, break every service check, phish users.
- [ ] `sudo named-checkconf -p | grep -nE 'allow-update|update-policy|ddns|session-keyfile'`
- [ ] Every zone: `allow-update { none; };` (zone-level statement, not valid in `options`).
- [ ] Verify (expect REFUSED):
  ```bash
  printf 'server 127.0.0.1\nupdate add pwn.<zone> 60 A 1.2.3.4\nsend\n' | nsupdate
  ```
- [ ] If something legitimately needs DDNS, use a **TSIG key** (`update-policy` or `allow-update { key k; }`), never IP-based.

### 3. SSH lockdown: **16** (I4 E4 C1)
SSH is scored with password auth, so don't disable passwords or change the port.
- [ ] Effective config (drop-ins override the main file):
  ```bash
  sudo sshd -T | grep -Ei 'permitrootlogin|passwordauth|permitempty|pubkeyauth|authorizedkeys|allowusers|maxauthtries|permituserenv|port '
  ls /etc/ssh/sshd_config.d/
  ```
- [ ] Drop-in `/etc/ssh/sshd_config.d/00-hardening.conf`:
  ```
  PermitRootLogin no
  PermitEmptyPasswords no
  MaxAuthTries 3
  LoginGraceTime 30
  X11Forwarding no
  PermitUserEnvironment no
  ```
- [ ] Keep one session open, then: `sudo sshd -t && sudo systemctl reload ssh` (`sshd` on Rocky). Test a fresh login before closing anything.
- [ ] Planted keys / key commands:
  ```bash
  sudo find / -xdev \( -name authorized_keys -o -name authorized_keys2 \) -exec ls -l {} \; -exec cat {} \; 2>/dev/null
  sudo grep -rniE 'AuthorizedKeysCommand' /etc/ssh/
  ```
  Delete keys you don't recognize. Everything is baseline-image, so *any* key is suspicious.

### 4. Zone transfers (AXFR): **15** (I3 E5 C1)
One `dig axfr` hands Red Team your whole network map.
- [ ] `options { allow-transfer { localhost; }; };` (localhost kept so you can still diff zones, item 13). Check no zone overrides with `allow-transfer { any; }`: `sudo named-checkconf -p | grep -n allow-transfer`
- [ ] Verify from another box (expect "Transfer failed"): `dig @<dns-ip> <zone> AXFR`
- [ ] Only add a specific secondary's IP if the pack/inject says there is one.

### 5. Rogue forwarders / masters / stub zones in config: **15** (I5 E3 C1)
A planted `forwarders { <attacker>; }` or a zone slaved to a bad master = silent DNS hijack, and nothing looks broken.
- [ ] `sudo named-checkconf -p | grep -nE 'forwarders|forward |type (forward|slave|secondary|stub|redirect)|masters|primaries|also-notify|allow-notify|response-policy|rpz|include'`
- [ ] Every IP found must be one you can explain (AD 172.20.240.100, VyOS 172.16.0.254 / real upstream). Everything else gets removed.
- [ ] Open every file named in `include` lines. Hidden config lives there.

### 6. Client-side DNS on **all** Linux boxes: **12** (I4 E3 C1)
Red Team doesn't need to own your DNS server if it can edit `/etc/hosts` or `resolv.conf` on the clients. This also breaks SSSD/Kerberos (AD lookups) and mail.
- [ ] **Record the originals now, before anything is changed:**
  ```bash
  cat /etc/resolv.conf; resolvectl status 2>/dev/null | head -20
  grep -vE '^\s*(#|$)' /etc/hosts
  grep '^hosts' /etc/nsswitch.conf
  ```
- [ ] Expected: nameserver = the real DNS (AD 172.20.240.100 for AD-joined boxes); `/etc/hosts` = localhost + own name only; `hosts: files dns` (or with `sss`/`resolve`).
- [ ] Re-check every 15-20 min (cheap loop): `watch -n 60 'md5sum /etc/resolv.conf /etc/hosts /etc/nsswitch.conf'`

### 7. Unexpected listeners / processes: **12** (I4 E3 C1)
- [ ] `sudo ss -tulpn`. Expected on a BIND box: `named` 53 udp+tcp, `named` **127.0.0.1:953** (rndc), `sshd` 22, `systemd-resolved` 127.0.0.53 (Ubuntu, harmless). Anything else: `ls -l /proc/<pid>/exe`, kill, find the persistence (item 10).
- [ ] Optional named listeners that shouldn't exist: `sudo named-checkconf -p | grep -nE 'listen-on.*(tls|http)|statistics-channels|inet'` (see item 11).

### 8. rndc key + control channel: **12** (I4 E3 C1)
Identical images mean the rndc key is identical across teams, and Red Team may have a copy. rndc = full control of named (reconfig, dump, add zones).
- [ ] `sudo ss -ltnp | grep 953` must show **127.0.0.1 only**. If `controls { inet 0.0.0.0 ... }` exists, fix to `controls { inet 127.0.0.1 allow { 127.0.0.1; } keys { "rndc-key"; }; };`
- [ ] Rotate the key: `sudo rndc-confgen -a` (writes `/etc/bind/rndc.key` on Debian/Ubuntu, `/etc/rndc.key` on Rocky), then:
  ```bash
  sudo chown root:bind /etc/bind/rndc.key && sudo chmod 640 /etc/bind/rndc.key   # group 'named' on Rocky
  sudo systemctl restart named && sudo rndc status
  ```
- [ ] Any TSIG keys in config (`grep -n 'key "' ...`) are equally compromised if from the image. Rotate if used.

### 9. File permissions on config/zones: **12** (I4 E3 C1)
- [ ] Debian/Ubuntu:
  ```bash
  sudo chown -R root:bind /etc/bind && sudo find /etc/bind -type d -exec chmod 750 {} \; && sudo find /etc/bind -type f -exec chmod 640 {} \;
  ```
  Rocky: `sudo chown root:named /etc/named.conf && sudo chmod 640 /etc/named.conf`; `/var/named` `root:named 750`.
- [ ] Leave bind-writable dirs writable by bind **only** (Debian `/var/lib/bind`, `/var/cache/bind`; Rocky `/var/named/{data,dynamic,slaves}`). Don't blanket-chmod these or named can't write journals.
- [ ] World-writable files in sensitive paths: `sudo find /etc /var/lib/bind /var/cache/bind /var/named -xdev -perm -0002 -type f 2>/dev/null`

### 10. Persistence triage (DNS-box specific): **10** (I5 E4 C2)
Person C owns the full malware sweep. These are the DNS-specific spots plus a fast integrity check.
- [ ] Binary / package integrity: `dpkg --verify bind9 bind9-utils openssh-server` (Debian/Ubuntu) / `rpm -V bind openssh-server` (Rocky). Any output on `/usr/sbin/named` or `sshd` is a rootkit-grade red flag.
- [ ] How named is launched: `systemctl cat named` (look for `ExecStartPre`/drop-ins), `ls /etc/systemd/system/named.service.d/ 2>/dev/null`, `cat /etc/default/named /etc/default/bind9 2>/dev/null` (`OPTIONS=` with odd flags like `-c <other conf>`).
- [ ] Cron/timers/units:
  ```bash
  for u in $(cut -d: -f1 /etc/passwd); do sudo crontab -u $u -l 2>/dev/null | sed "s/^/$u: /"; done
  ls -la /etc/cron.* /etc/crontab; systemctl list-timers --all; systemctl list-unit-files --state=enabled | grep -viE 'ssh|named|cron|rsyslog|systemd|apparmor|ufw|networkd|resolved|getty|dbus'
  ```
- [ ] Shell/loader hooks: `cat /etc/ld.so.preload /etc/rc.local 2>/dev/null; ls /etc/profile.d/`

### 11. Disable features you don't need: **9** (I3 E3 C1)
Several 2026 BIND bugs live in optional features (see item 15). No feature = no exposure, and it costs nothing.
- [ ] Confirm **absent** in effective config: DoH/DoT listeners (`listen-on ... tls/http`), `statistics-channels`, `tkey-gssapi-keytab` / `tkey-gssapi-credential` / `tkey-domain` (GSS-TSIG), `serve-stale`. Remove unless an inject requires them.
- [ ] Make sure a global `options { ... };` block exists (CVE-2026-76163: TKEY query aborts named when no global options statement).

### 12. Restrict recursion: **8** (I4 E4 C2: the 2 is scoring risk)
Open recursion = cache-poisoning surface + amplification abuse.
- [ ] Only after step-0 tcpdump confirms what the scorer asks.
  ```
  acl "internal" { 127.0.0.1; ::1; 172.16.0.0/24; 172.17.0.0/24; 172.20.240.0/24; };
  options {
      allow-query       { any; };         // authoritative answers MUST stay public (rule 9)
      recursion yes;                      // 'no' if scorer only asks your own zone
      allow-recursion   { internal; };
      allow-query-cache { internal; };
  };
  ```
  Confirm the DHCP workstations are actually in those subnets before applying.
- [ ] Verify from a workstation: `dig @<dns-ip> google.com` and `dig @<dns-ip> <your-zone> SOA`. Then watch **two** Quotient cycles. DNS red = revert immediately.

### 13. Zone-data baseline and diff: **7.5** (I5 E3 C2)
- [ ] `sudo named-checkzone <zone> <file>` after any edit. Never leave a zone that fails to load.
- [ ] Watch for tampering (uses the golden copy from step 0):
  ```bash
  while sleep 60; do dig @127.0.0.1 <zone> AXFR +noall +answer | sort > /tmp/zone.now; diff -q /root/zone-<zone>.base /tmp/zone.now >/dev/null || echo "ZONE CHANGED $(date)"; done
  ```
- [ ] Look for: new A/CNAME records pointing off-network, wildcards (`*`), MX changes, TTL=0/1, SOA serial jumps, `.jnl` journal files you didn't create.
- [ ] Zone changed = **write an incident report** (source IP from logs, timeline, what was affected, remediation). IR is 20% of the score.

### 14. sudo / SUID / privileged groups: **7.5** (I5 E3 C2)
- [ ] `sudo grep -rvE '^\s*(#|$)' /etc/sudoers /etc/sudoers.d/`: look for `NOPASSWD`, `ALL` for odd users/groups.
- [ ] `getent group sudo wheel adm docker lxd disk shadow`: remove users that shouldn't be there.
- [ ] `sudo find / -xdev -perm -4000 -type f 2>/dev/null`: red flags: SUID `find`, `vim`, `bash`, `python*`, `cp`, `nmap`.
- [ ] Writable `/etc/passwd` or `/etc/shadow`: `ls -l /etc/passwd /etc/shadow`

### 15. Patch BIND: **6** (I4 E3 C2)
ISC disclosed 14 more BIND 9 CVEs on Sept 16 2026, on top of a heavy 2026 stream. Most are remote crash/CPU-exhaustion bugs: **a crash = scored DNS down**.
- [ ] Debian/Ubuntu: `sudo apt-get update && sudo apt-get install --only-upgrade bind9 bind9-utils bind9-dnsutils` / Rocky: `sudo dnf upgrade bind bind-utils`. **Restarts named: expect ~5-10 s of DNS blip, do it early.** Never `dist-upgrade` (kernel/openssh churn, reboot risk).
- [ ] `named -v` before/after; check the changelog (`apt changelog bind9 | head -40`) mentions the 2026 CVEs. Distros backport, so version numbers alone mislead.
- [ ] Don't compile from source. If the repo version is unpatched, rely on item 11 (remove the optional features) as the mitigation.
- [ ] `sudo named-checkconf -z` before restarting; `sudo systemctl status named` and one `dig` after.

### 16. Run as non-root + MAC enforcing: **6** (I3 E2 C1)
- [ ] `ps -o user= -C named` → `bind` (Debian/Ubuntu) / `named` (Rocky). Never root.
- [ ] Ubuntu: `sudo aa-status | grep -i named`; if complain mode: `sudo aa-enforce /etc/apparmor.d/usr.sbin.named`. Rocky: `getenforce` → Enforcing; if Permissive: `sudo setenforce 1`. Don't disable either. If a change breaks named, check `journalctl -t audit` / `dmesg | grep -i denied` before blaming BIND.
- [ ] Skip chroot (high cost, high breakage, not worth it tomorrow).

### 17. Host firewall (defense in depth): **4.5** (I3 E3 C2)
Palo Alto is the real perimeter. Host firewall only catches lateral movement.
- [ ] Ubuntu/Debian:
  ```bash
  sudo ufw default deny incoming; sudo ufw default allow outgoing
  sudo ufw allow 22/tcp; sudo ufw allow 53/tcp; sudo ufw allow 53/udp
  sudo ufw enable
  ```
  Rocky: `sudo firewall-cmd --permanent --add-service={ssh,dns} && sudo firewall-cmd --reload`
- [ ] **TCP 53 must stay open** (large responses, TCP fallback). **Do not block ICMP.** No source-IP allow-listing for 22/53.
- [ ] Add rules for anything else scored on that box *before* enabling.

### 18. Logging for IR: **4.5** (I3 E3 C2, indirect: feeds the 20% IR score)
- [ ] Send named logs to syslog/journald (no AppArmor file-path pain):
  ```
  logging {
      category default  { default_syslog; };
      category security { default_syslog; };
      category xfer-in  { default_syslog; };
      category xfer-out { default_syslog; };
      category update   { default_syslog; };
  };
  ```
- [ ] Query logging on demand only (costly): `sudo rndc querylog on` / `off`.
- [ ] `journalctl -u named -f | grep -iE 'denied|refused|update|transfer'`
- [ ] Forward to Splunk (172.20.240.20) only if the logging person has the forwarder path ready.

### 19. Response rate limiting: **3** (I2 E3 C2)
- [ ] `rate-limit { responses-per-second 20; exempt-clients { internal; }; };`
- [ ] **Risk:** traffic generators and the scorer generate bursts. Skip on first pass; add only if you see amplification/flood in logs.

### 20. Hide version banner: **3** (I1 E3 C1)
- [ ] `version "none"; hostname none; server-id none;`
- [ ] Cosmetic. Fingerprinting tools still work. Do it only because it's 10 seconds.

---

## Consolidated config pass (do items 2, 4, 5, 11, 12, 19, 20 in ONE edit)

One reload beats seven. Leave existing `directory`, `forwarders`, and `dnssec-validation` lines as they are.

```
acl "internal" { 127.0.0.1; ::1; 172.16.0.0/24; 172.17.0.0/24; 172.20.240.0/24; };

options {
    // ...keep existing directory / forwarders / dnssec lines...
    allow-query       { any; };
    recursion yes;                        // or 'no' per step-0 tcpdump
    allow-recursion   { internal; };
    allow-query-cache { internal; };
    allow-transfer    { localhost; };
    version "none"; hostname none; server-id none;
};

zone "<your-zone>" {
    type master;                          // leave type/file as found
    file "<as found>";
    allow-update   { none; };
    allow-transfer { localhost; };
};
```

Apply loop: edit → `sudo named-checkconf -z` → `sudo rndc reload` (not restart) → `dig @127.0.0.1 <zone> SOA` → wait for next Quotient cycle.

## Suggested run order on comp day

| When | Do |
|------|----|
| 7:00-8:00 (Zoom, Welcome inject) | Read NISE announcements. Ask the Q&A questions (PCR semantics, DNS target host). **No stadium access until 8:00 drop flag.** |
| 8:00-8:05 | Step 0 preflight: find the DNS box, backup, `named-checkconf -p`, golden zone dump. |
| 8:05-8:20 | Items 1, 3, 6, 7 (creds, SSH, client DNS, listeners). Pure Linux, no named restarts. |
| 8:20-8:40 | Items 5, 2, 4, 8, 9 (audit config, then the consolidated edit and one reload). |
| 8:40-9:00 | Item 10 persistence triage, item 15 patch (accept the blip), then 12 recursion after a clean Quotient cycle. |
| 9:00+ | Items 13 (zone diff loop running in a spare terminal), 14, 16-20. Write IR reports for anything caught. |

---

## Appendix A: DNS lives on the 2022 AD box (172.20.240.100). Hand to Windows captain.

Likeliest real situation. AD **requires** DNS (SRV records for `_ldap._tcp.dc._msdcs`, `_kerberos._tcp`, `_gc._tcp`) and the Linux boxes find the DC and Kerberos through it. Break these and SSSD logins, IMAP auth (AD usernames), and AD-WinRM scoring all die at once.

- [ ] **Never delete or "clean up" SRV/`_msdcs` records.** Verify health: `dcdiag /test:dns`, `nltest /dsgetdc:<domain>`.
- [ ] Zone properties → **Dynamic updates = "Secure only"**. Red Team flipping this to "Nonsecure" is the classic record-tamper.
- [ ] Zone properties → **Zone Transfers**: off, or only to listed servers if an inject needs it.
- [ ] Server properties → **Forwarders**: only the real upstream. No unknown IPs.
- [ ] **DnsAdmins** membership should be empty or minimal: `Get-ADGroupMember DnsAdmins`. DnsAdmins can make `dns.exe` (SYSTEM on the DC) load an arbitrary DLL = path to Domain Admin.
- [ ] Check the DLL hook isn't already planted: `reg query HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll` (should not exist).
- [ ] Review all records for off-network IPs, new wildcards, and conditional forwarders you didn't create.
- [ ] Enable DNS debug logging / audit for IR evidence.

## Appendix B: Why DNS matters in this topology (summary)

- **Authoritative:** names for ecom (.10), mail (.15), splunk (.20), AD (.100), MSSQL (.120) on internal 172.20.240.x and "public" 172.25.20+team#.x. The scorer asks, from unknown source IPs, and gets points per correct answer.
- **Resolver:** internal hosts resolve through it, with forwarders upstream for internet names (patches, research).
- **AD glue:** AD owns the `_msdcs`/SRV records. A Linux DNS would forward the AD zone to .100 or secondary it, never shadow it.
- **Dependents:** SSSD/Kerberos on Linux boxes, IMAP/webmail via AD users, SMTP (MX/A), AD-WinRM, SMB (domain vs local), Splunk. DNS breakage cascades.

## Sources

- Hackviser, BIND 9 hardening guide: https://hackviser.com/tactics/hardening/bind9
- DISA BIND 9.x STIG (allow-recursion / authoritative recursion rules): https://guides.g5cybersecurity.com/?p=4745 , https://guides.g5cybersecurity.com/?p=4729
- Debian Securing Manual, BIND config (allow-query/allow-transfer/version): https://www.debian.org/doc/manuals/securing-debian-manual/sec-bind.de.html
- Debian security tracker / package tracker, BIND9 2026 CVEs: https://security-tracker.debian.org/tracker/CVE-2026-5946 , https://tracker.debian.org/pkg/bind9
- Openwall oss-security, ISC 14-CVE disclosure (Sept 16 2026): https://www.openwall.com/lists/oss-security/2026/09/16/4
- Microsoft, Non-Windows DNS for Active Directory (SRV / `_msdcs` requirements): https://technet.microsoft.com/en-us/library/cc959323.aspx
- AD DNS SRV record locations: https://faisal.it.com/?p=2477
- MWCCDC 2026 Invitational Team Pack (topology, rules, scoring)