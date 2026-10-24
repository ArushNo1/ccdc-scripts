# Splunk Server Hardening Checklist (MWCCDC Invitational, Oct 24 2026)

Target: Debian 12 + Splunk 10.0.2, 172.20.240.20 (public 172.25.20+team#.20). Source: team pack.
Scored on this box: Splunk Query (web, auth + search), Splunk Management (8089 open + auth), SSH, Ping.

**Bottom line:** 10.0.2 is nine patch releases behind and carries an actively exploited unauthenticated 9.8 RCE (CVE-2026-20253). The fix is a two-line config change (#2).

I haven't touched the real VM. Assumptions: Debian 12, Splunk 10.0.2, `SPLUNK_HOME=/opt/splunk`. Verify first (30 seconds):

```bash
S=/opt/splunk; ps -eo user:12,cmd | grep [s]plunkd | head -2; $S/bin/splunk version
```

Scoring: Impact x Exploitability / Cost, each 1-5. Cost = time + risk of breaking a scored service. These numbers are my estimates, not measurements.

---

## Ranked checklist

### 1. [ ] Change `sysadmin` password via Quotient PCR (25.0 | I5 E5 C1)
`Changeme1!` is printed in the team pack, so every team and Red Team knows it. Submit `sysadmin,<newpass>` on the PCR tab. My read: PCR updates the scoring engine's credential and you still change the password on the box. Confirm at the 7:30 Q&A, and watch the SSH check go green afterwards.

### 2. [ ] Disable the PostgreSQL sidecar (25.0 | I5 E5 C1)
The sidecar endpoint lacks authentication, so any network-reachable user can create or truncate files without credentials. Splunk PSIRT saw limited exploitation in June 2026. The sidecar is on by default on Splunk Enterprise. Disabling it breaks Edge Processor, OpAmp and SPL2 pipelines, none of which this box should use. I couldn't find which port the vulnerable endpoint listens on, so disable it rather than firewall it.

```bash
grep -n '^\[postgres\]' $S/etc/system/local/server.conf   # make sure it isn't already there
printf '\n[postgres]\ndisabled = true\n' >> $S/etc/system/local/server.conf
# restart ONCE, after batching items 2, 4 and 12 (see execution order)
ps aux | grep -i [p]ostgres    # should be empty afterwards
```

### 3. [ ] SSH sweep (16.0 | I4 E4 C1)
Keep `PasswordAuthentication yes`, because the scorer logs in with a password.

```bash
sshd -T | grep -Ei 'permitroot|passwordauth|authorizedkeys|allowusers|allowgroups|permitempty'
cat /etc/ssh/sshd_config.d/* 2>/dev/null; grep -in '^match' /etc/ssh/sshd_config
find / -xdev -name 'authorized_keys*' 2>/dev/null -exec sh -c 'echo "== $1"; cat "$1"' _ {} \;
# fix: PermitRootLogin no, PermitEmptyPasswords no, delete unknown keys
sshd -t && systemctl reload ssh     # keep an existing session open
```

### 4. [ ] Splunk account passwords (12.5 | I5 E5 C2)
Most 10.0.x RCEs need a logged-in Splunk user. Uploading an app with a scripted input is the classic route to a shell. Splunk creds aren't in the pack, so find out which account Quotient uses (service status page, or ask the White Team).

```bash
cut -d: -f1 $S/etc/passwd                 # local Splunk users, no auth needed
sudo -u splunk $S/bin/splunk edit user admin -password 'NEW' -auth admin:'OLD'
```

Then submit a PCR for the same credentials. Don't rename or delete users (rule 11 forbids username changes). Check Settings -> Licensing too: a free license means no auth at all, which contradicts the scored login, so flag it if you see it.

### 5. [ ] splunkd run-as user and sudo (12.0 | I4 E3 C1)
If splunkd runs as root, any Splunk RCE is a root shell.

```bash
ps -o user:12,cmd -C splunkd | head -2; grep OS_USER $S/etc/splunk-launch.conf
sudo -l -U splunk; grep -rn splunk /etc/sudoers /etc/sudoers.d; id splunk
```

Move it off root only if you've rehearsed it: stop, `chown -R splunk:splunk $S`, set `SPLUNK_OS_USER=splunk`, start.

### 6. [ ] Audit Splunk code-exec surfaces (10.0 | I5 E4 C2)
Red Team may have planted these, or may add them after getting in. Anything non-default and unrecognized gets removed.

```bash
B="sudo -u splunk $S/bin/splunk btool"
$B inputs list --debug | grep -E 'script://' | grep -v 'system/default'
$B alert_actions list --debug | grep -iE 'command|script' | grep -v 'system/default'
$B transforms list --debug | grep -i external_cmd
$B props list --debug | grep -i unarchive_cmd
$B authentication list --debug | grep -iE 'authType|scriptPath'
ls -lat $S/etc/apps $S/etc/deployment-apps $S/etc/users
find $S/etc -newermt 2026-10-01 -type f \( -name '*.conf' -o -name '*.sh' -o -name '*.py' \)
```

### 7. [ ] Baseline, backup and IR evidence (9.0 | I3 E3 C1)
No snapshot revert exists, and 20% of the score is incident response. Do this before changing anything else.

```bash
mkdir -p /root/base && cd /root/base && ss -tulpn > ports && ps -eo user,pid,ppid,cmd > ps
cp -a /etc/passwd /etc/shadow /etc/group /etc/ssh . ; tar czf splunk-etc.tgz $S/etc
# Red Team footprints for incident reports (src IP, timeline):
grep -E 'apps/local|__upload|data/inputs/script|authentication/users' $S/var/log/splunk/splunkd_access.log
ls -la $S/var/run/splunk/apptemp
```

### 8. [ ] OS persistence and privesc sweep (7.5 | I5 E3 C2)

```bash
cat /etc/crontab; ls -la /etc/cron.*; for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null|sed "s/^/$u: /"; done
systemctl list-unit-files --state=enabled --no-pager; systemctl list-timers --all --no-pager
awk -F: '$3==0' /etc/passwd; awk -F: '$2==""' /etc/shadow; cat /etc/ld.so.preload 2>/dev/null
grep -rn 'pam_exec' /etc/pam.d; find / -xdev -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null
```

### 9. [ ] Check Palo Alto exposure (6.0 | I4 E3 C2)
From outside, only 22, 8000, 8089 and ICMP need to reach this box. Block 8088, 9997, 8191 and 5432 at the firewall if they're open. The PAN login in the pack (`admin/Changeme123`) is also public, so whoever owns the firewall should change it.

### 10. [ ] DoS recovery (6.0 | I3 E2 C1)
CVE-2026-76288 lets an unauthenticated user knock Splunk Web offline with one request, and it stays down until Splunk restarts. The only workaround is turning Splunk Web off, which you can't do because it's scored. Keep `$S/bin/splunk restart` ready and watch Quotient. Pull the source IP from `splunk_web_access.log` and block that specific IP (rule 9 permits this).

### 11. [ ] Host firewall for unscored listeners (4.5 | I3 E3 C2)
Check `ss -tulpn` first. Don't drop 9997 if internal forwarders use it.

```bash
nft add table inet hard; nft add chain inet hard in '{ type filter hook input priority 0; }'
nft add rule inet hard in tcp dport '{ 8191, 8088, 5432 }' ip saddr != 127.0.0.1 drop
```

### 12. [ ] Disable unused apps (4.5 | I3 E3 C2)
Disabling Secure Gateway and Pipeline Builders is Splunk's listed mitigation for several Secure Gateway issues and the unauthenticated Edge Processor DoS (CVE-2026-76290).

```bash
ls $S/etc/apps | grep -iE 'secure|pipeline|o11y|observ|spl2'
sudo -u splunk $S/bin/splunk disable app <name> -auth user:pass
```

After the restart, run a real search and confirm Quotient stays green.

### 13. [ ] Role/capability lockdown (4.0 | I4 E2 C2)
Low value, because the bugs need a login in the first place.

```bash
$B authorize list --debug | grep -E 'edit_cmd|edit_manager_xml|schedule_search|run_collect|edit_user'
```

Only admin should hold these. It won't stop CVE-2026-76313 (low-privileged knowledge bundle upload RCE), because that upload endpoint doesn't check the high-privilege capability.

### 14. [ ] Upgrade to 10.0.11 (3.0 | I5 E3 C5)
The only complete fix, but it ranks low for good reason: a download from splunk.com, a restart, and risk to a scored service. Rule 10 means a botched upgrade is unrecoverable short of a new lab reservation. Skip unless you've rehearsed it and the White Team OKs the download. If you do upgrade, use the tarball: Splunk says package upgrades carry a local root escalation (CVE-2026-76266), and the fix is to upgrade with a tar file instead.

### 15. [ ] Patch userland with apt (2.7 | I4 E2 C3)

```bash
apt update && apt list --upgradable 2>/dev/null | grep -Ei 'openssh|sudo|polkit|libc6'
```

Skip the kernel (needs a reboot). I did not research Debian 12 kernel LPEs; that belongs to whoever has the privesc lane.

---

## Don'ts (all break scoring or trigger penalties)
- No SSL on Splunk Web unless you confirm the scorer uses https.
- Don't touch ports 8000/8089, `disableDefaultPort`, or `allowRemoteLogin = never` (the scorer logs in remotely).
- No source-IP allowlists. Rule 9 penalizes knife-edge filtering.
- Don't disable SSH password auth, and don't use `AllowUsers` unless the scoring account is on it.
- Don't reboot, rename or delete users, or change IPs or hostnames.

## Execution order tomorrow
- **Minutes 0-10:** item 7 backup first, then items 1, 2, 3, 4 and 12, then ONE splunkd restart (one blip in the Splunk Query/Management checks instead of four).
- **Minutes 10-30:** items 5, 6 and 8.
- **After that:** items 9, 10 and 11 as time allows.
- **Ask the White Team:** does pulling your own scripts from a public repo count as a "staging area" under rule 4? If not, paste them in the console.

Rehearse items 1-8 on a test Splunk box tonight with a stopwatch. Target: under 10 minutes for the first batch.

## Sources
- SVD-2026-0603 (CVE-2026-20253): https://advisory.splunk.com/advisories/SVD-2026-0603
- SVD-2026-1007 (Oct 21): https://advisory.splunk.com/advisories/SVD-2026-1007
- SVD-2026-1001 (Oct 7): https://advisory.splunk.com/advisories/SVD-2026-1001
- SVD-2026-0302 (edit_cmd RCE): https://advisory.splunk.com/advisories/SVD-2026-0302
- CVE-2026-76313: https://fieldguide.lutrasecurity.com/CVE-2026-76313/
- Splunk sidecar configuration settings, 10.0: https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.0/splunk-sidecars/sidecar-configuration-settings
- HackTricks, Pentesting Splunkd: https://book.hacktricks.xyz/network-services-pentesting/8089-splunkd
- Splunk server.conf reference (allowRemoteLogin): https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.1/configuration-file-reference/9.1.1-configuration-file-reference/server.conf