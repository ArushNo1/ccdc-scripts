# CCDC Linux Captain: First 15 Plan

Scope: Linux lane only. Checklist-only. Automated tests first, rehearsal drills second.
Written from general CCDC knowledge and the red-team "First 15" guidance; verify tool and version specifics in the mock env.

## 0. Principles

- [ ] Uptime beats hardening. A box that's down loses more points than a box that's popped.
- [ ] Order is fixed: **creds → firewall → patch only if exploitable.**
- [ ] Every change gets a verify step, and every verify step gets a scored-service check.
- [ ] Nothing runs on a box unless it has been rehearsed on the mock env.
- [ ] Never close your only door. Keep a console (Proxmox/VM console) open before touching SSH or firewall.
- [ ] Log every change in a shared timeline: time, box, change, who.

## 1. Pre-comp access (the 90% of the work)

**Enumeration baseline per box (do this the moment access opens):**
- [ ] Hostname, OS/version, kernel, IPs, role, scored services
- [ ] `ss -tulpn` and listening-port baseline saved to file
- [ ] Process list and service list (`systemctl list-units --type=service`)
- [ ] All users with UID 0, login shells, sudoers, sudo group members
- [ ] `authorized_keys` for every user, including root
- [ ] Cron (system, per-user, `cron.d`), systemd timers, `at` jobs
- [ ] SUID/SGID binaries, world-writable files, capabilities
- [ ] Installed packages and versions (for vuln mapping)
- [ ] Config file hashes for key services (sshd, web, DB, mail, DNS)
- [ ] Exposed-outside-environment map: what the team packet lists vs. what's actually listening

**Vuln mapping:**
- [ ] Kernel/package versions checked against known easy exploits (PwnKit/polkit, Baron Samedit/sudo, Dirty Pipe/Dirty COW, glibc, Samba, web app CVEs)
- [ ] Each finding rated: exploitable remotely? needs local access? needs a patch or just a mitigation?
- [ ] Decision per box: patch now / mitigate / leave alone

**Rogue stuff hunt:**
- [ ] Extra admin accounts, accounts with empty passwords
- [ ] Backdoored SSH config (`AuthorizedKeysFile`, `PermitRootLogin`, `PermitEmptyPasswords`)
- [ ] Unexpected listening services (netcat, reverse shells, extra web servers)
- [ ] Default app creds: web admin panels, DB root, mail admin, phpMyAdmin, Webmin

## 2. Automation to build and master

Everything below is a script or playbook, tested on the mock env.

| Tool | Purpose | Status |
|---|---|---|
| Baseline collector | One script run on each box, outputs a timestamped report | [ ] |
| Cred rotation script | Changes passwords for all human and service accounts, outputs the new password list | [ ] |
| Password generator | Per-box, per-account, copy-safe (avoid shell-hostile characters) | [ ] |
| SSH key auditor | Lists and optionally wipes unknown `authorized_keys` | [ ] |
| Rogue account finder | UID 0, sudoers, empty password, new users | [ ] |
| Firewall apply script | nftables or iptables ruleset from a per-box port list | [ ] |
| Firewall rollback | Timed auto-revert (cron or `at`) in case you lock yourself out | [ ] |
| Service health checker | Mimics the scoring engine for each scored service | [ ] |
| Persistence hunter | Cron, timers, rc scripts, profile files, systemd units, LD_PRELOAD | [ ] |
| Config integrity checker | Hash diff against baseline | [ ] |
| Ansible inventory and playbooks | Fan-out for all of the above | [ ] |
| Log shipper or tail view | Auth log, web log, bash history in one terminal | [ ] |

## 3. First 15 tasks

### 3.1 Credentials (minutes 0 to 5)
- [ ] Change team-packet creds first (SSH user and root)
- [ ] Change other OS admin and sudo-capable accounts
- [ ] Change application admin creds (web CMS, DB root, mail admin, DNS panels)
- [ ] Check that service creds stored in app configs (DB creds in web app config) still match after the change
- [ ] Record all new creds in the team password store, not in chat or a notes file on the box
- [ ] Disable or lock unused accounts. Don't delete them yet (evidence, and rollback)
- [ ] Wipe unknown SSH keys; install your own team key only if needed
- [ ] Set `PermitRootLogin no` only after confirming a working sudo user

**Risks and gotchas:**
- [ ] Scoring engine may log in with a specific account. Confirm which accounts it uses before changing, per the rules and packet.
- [ ] Special characters break scripts and web logins. Rehearse the generator.
- [ ] Changing the DB password without updating the app config is a self-inflicted outage.
- [ ] Red team may already hold a session. Password changes don't kill live sessions, so kill them (`pkill -KILL -u <user>`, check `w`/`who`).

### 3.2 Firewall (minutes 5 to 10)
- [ ] Host firewall default-deny inbound, allow only scored ports plus your management access
- [ ] Management source restricted to team subnet or jump host
- [ ] Outbound: allow established/related, plus only what each box genuinely needs (DNS, NTP, package mirrors if you patch)
- [ ] Block all other outbound to cut C2 and reverse shells
- [ ] Block SMB/NetBIOS (135-139, 445) from outside where not scored
- [ ] Verify listening-vs-allowed: anything listening but firewalled still gets noted and shut down later
- [ ] Network firewall (if you control it) mirrors the host rules; coordinate with the network lead
- [ ] Rollback timer armed before apply, cancelled after verify

**Risks and gotchas:**
- [ ] Locking out your own SSH session
- [ ] Blocking DNS or NTP breaks the box in subtle ways (time drift breaks Kerberos and logs)
- [ ] Outbound blocking breaks mail relay, DB replication, or updates if a scored service needs them
- [ ] iptables vs. nftables vs. ufw vs. firewalld: know which backend each box uses and that rules persist across reboot
- [ ] Docker bypasses host firewall rules by inserting its own chains

### 3.3 Patch or mitigate (minutes 10 to 15)
- [ ] Only patch what the pre-comp analysis flagged as easily exploitable
- [ ] Prefer a mitigation when it works (remove SUID bit on pkexec for PwnKit, block ports, disable a module)
- [ ] Snapshot before a kernel or major package update if the platform allows
- [ ] Reboot only if the box can afford downtime and the scoring check passes after
- [ ] Skip patching boxes with no easy exploit, to keep uptime

**Risks and gotchas:**
- [ ] Package updates can change service configs or versions that scoring depends on
- [ ] Kernel update plus reboot can break out-of-tree drivers or network config
- [ ] Mitigation commands vary per vuln. Rehearse each one you plan to use.

## 4. Situations to prepare for

- [ ] Red team already inside at minute 0 (persistent shell, rogue cron)
- [ ] A scored service goes down after your change
- [ ] You get locked out of a box
- [ ] A password change fails halfway across boxes
- [ ] Packet creds don't work
- [ ] A service you didn't know about is exposed and scored
- [ ] Inject lands mid-first-15 and pulls a teammate away
- [ ] Ansible or SSH to many boxes at once is blocked or slow
- [ ] A box is already compromised: isolate, reimage, or restore? Decide the rule beforehand
- [ ] Config backup missing when you need to roll back

## 5. Automated tests (build first)

These run from a teammate's box or a monitoring box, on a loop.

**Service tests (scoring-engine mimic):**
- [ ] Per scored service, a check that does what the scorer does: HTTP GET with expected content, SMTP send/receive, DNS lookup, DB login and query, SSH login, FTP login
- [ ] Runs every 30 to 60 seconds, prints PASS/FAIL with timestamp
- [ ] Alert on first failure, not after three

**Hardening verification:**
- [ ] External port scan (nmap from a different host) compared to the allowed-port list
- [ ] Old creds fail, new creds succeed (per account, per service)
- [ ] No unknown UID 0 accounts, no unknown authorized_keys
- [ ] Outbound test: attempt connection to a test server on odd ports, expect block
- [ ] Established connections still work (the legit inbound reply path)
- [ ] Config hash diff against baseline: report drift
- [ ] Firewall rules persist after a simulated reboot (test in mock env)

**Script self-tests:**
- [ ] Each script has a dry-run mode
- [ ] Each script exits non-zero on failure and says what failed
- [ ] CI-style run of the whole first-15 sequence against the mock env, checking all above passes

## 6. Rehearsal drills (build second)

- [ ] **Drill A:** Full first-15 on the mock env with a stopwatch. Target under 15 minutes. Record the time per phase.
- [ ] **Drill B:** Same, but a teammate plays red team and plants a backdoor, cron job, and rogue user beforehand. Can you find them?
- [ ] **Drill C:** Lockout recovery. Deliberately misconfigure SSH or the firewall, then recover through the console and the rollback timer.
- [ ] **Drill D:** Service break. A change takes a scored service down. Time to detect and fix.
- [ ] **Drill E:** Cold start. New box, no baseline, only the packet. Handle it in 15 minutes.
- [ ] **Drill F:** Handoff. Someone else runs your scripts from the checklist alone. If they can't, the docs are broken.
- [ ] **Drill G:** Distraction. Inject drops at minute 7 while you're mid-firewall. Does the team keep the order?
- [ ] After each drill: write down failures, fix the script or checklist, rerun.

## 7. Ways this plan can fail (red-team view)

- [ ] Password list leaks (stored on a compromised box, pasted in shared chat)
- [ ] Red team has a persistence mechanism you didn't hunt: LD_PRELOAD, PAM backdoor, modified binaries, systemd unit, SSH key in an unusual path, web shell
- [ ] They watch for your scripts and mimic or hook them
- [ ] They exploit a service that *is* scored and allowed through the firewall, so firewalling alone doesn't stop web app exploits
- [ ] Lateral movement through allowed management paths (your SSH jump host becomes the target)
- [ ] Reverse shell over an allowed outbound port (DNS, 443) if outbound isn't tightly restricted
- [ ] Live sessions survive credential rotation
- [ ] Local privilege escalation on boxes you decided not to patch
- [ ] Rules revert on reboot because they weren't persisted

## 8. Role assignments (fill in)

- [ ] Who rotates creds on which boxes
- [ ] Who applies firewall rules on which boxes
- [ ] Who owns the service health monitor
- [ ] Who talks to the Windows and network leads
- [ ] Who logs the timeline
- [ ] Backup for each role

## 9. Build order

1. [ ] Baseline collector and service health checker (you need to see before you change)
2. [ ] Cred rotation script and verification tests
3. [ ] Firewall script with rollback timer and external port-scan test
4. [ ] Persistence hunter and rogue account finder
5. [ ] Ansible fan-out for the above
6. [ ] Patch/mitigation runbook per known vuln
7. [ ] Full drills A to G