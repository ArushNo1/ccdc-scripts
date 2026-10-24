# CCDC Kali Workstation Hardening Checklist

**Host:** Kali VM · `172.17.0.2` · VyOS wkst segment (OUTSIDE the Palo Alto) · user `sysadmin`
**Ranking:** (Impact × Exploitability) / Cost, each 1–5 (Cost 5 = expensive)
**Goal:** deny Red Team a foothold, protect credentials, keep the box usable as an outside-in validator. It is probably NOT scored, so harden aggressively. No snapshot revert exists, so keep changes small and tested.
**Time budget:** items 1–4 in the first 10 min (~5 min of work). Items 5–9 after scored servers are stable.

---

## Pre-flight (60 seconds)

- [ ] Check Quotient (`https://quotient.ccdc.events/`) for ANY Kali service (SSH, ping, other)
  - If SSH/anything is scored → password changes go through the **PCR tab** (`username,password` CSV), not local `passwd`
  - If nothing is scored → local `passwd` is fine
- [ ] Open NETLAB console to Kali and keep it open the whole time (out-of-band recovery if a firewall rule locks you out)
- [ ] **Someone** changes `vyos:vyos` on the VyOS router (same segment as Kali; if VyOS falls, Kali is next)
- [ ] Confirm which user Quotient uses for any scored Kali service before restricting anything

---

## 1. Passwords and accounts — Score 25 (I5 E5 C1)

The password `Changeme1!` is in the team packet. Assume Red Team has it.

- [ ] List UID 0 accounts and login shells:
  ```bash
  getent passwd | awk -F: '$3==0 || $7 !~ /(nologin|false)$/'
  ```
- [ ] Check for empty passwords:
  ```bash
  sudo awk -F: '($2==""){print "EMPTY PW: "$1}' /etc/shadow
  ```
- [ ] Change `sysadmin` password (strong, unique, shared via team channel only)
  ```bash
  sudo passwd sysadmin
  ```
- [ ] Lock root:
  ```bash
  sudo passwd -l root
  ```
- [ ] Check for a leftover `kali` user (default `kali:kali`). If present: lock it
  ```bash
  id kali 2>/dev/null && sudo usermod -s /usr/sbin/nologin kali && sudo passwd -l kali
  ```
- [ ] Any other unknown accounts: **LOCK, do not delete** (White/Green Team may need access, rule 4)
  ```bash
  sudo usermod -s /usr/sbin/nologin <user>; sudo passwd -l <user>
  ```
- [ ] Do NOT rename any user (rule 11)

---

## 2. Listening services — Score 20 (I4 E5 C1)

Stock Kali has no listening services, but this image is custom. Verify.

- [ ] Enumerate listeners:
  ```bash
  sudo ss -lntup
  ```
- [ ] Enumerate enabled services:
  ```bash
  systemctl list-unit-files --state=enabled --type=service
  ```
- [ ] Disable anything not required. Drop `ssh` **only if not scored**:
  ```bash
  sudo systemctl disable --now ssh ssh.socket apache2 postgresql smbd nmbd xrdp x11vnc avahi-daemon cups 2>/dev/null
  ```
- [ ] Re-run `ss -lntup` and confirm only expected ports remain
- [ ] Anything unexpected listening → note PID, `ls -l /proc/<pid>/exe`, `ps -fp <pid>`, treat as incident (write report)

---

## 3. Sudo and privileged groups — Score 15 (I5 E3 C1)

- [ ] What can `sysadmin` do:
  ```bash
  sudo -l
  ```
- [ ] Hunt passwordless sudo:
  ```bash
  sudo grep -rE 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d/
  ```
- [ ] Check root-equivalent group membership:
  ```bash
  getent group sudo adm docker disk shadow lxd
  ```
- [ ] Remove unexpected members (`sudo gpasswd -d <user> <group>`)
- [ ] Remove or fix any `NOPASSWD` entries via `visudo` / delete the drop-in in `/etc/sudoers.d/` (never edit with a plain editor)

---

## 4. Credential hygiene — Score 12 (I4 E3 C1)

Your team types passwords for every other box here. Treat this box as a credential store.

- [ ] **READ history first** for attacker/pre-planted activity (needed for IR), then wipe:
  ```bash
  cat ~/.zsh_history ~/.bash_history 2>/dev/null | tail -100
  : > ~/.zsh_history; : > ~/.bash_history
  ```
- [ ] Check SSH material:
  ```bash
  ls -la ~/.ssh; ssh-add -D 2>/dev/null
  ```
- [ ] Clear browser saved passwords / autofill
- [ ] Clear Metasploit DB creds if used (`~/.msf4`)
- [ ] Team rule: no password files on this box, no pasting creds into scratch files
- [ ] If this box is ever found compromised → **rotate every credential typed on it**

---

## 5. Host firewall, default-deny inbound — Score 8 (I4 E4 C2)

Rules: keep **ICMP** (rule 12). Allow scored ports from **ALL sources** (no knife-edge filtering, rule 9). Kali is static, so no DHCP rule needed.

- [ ] Console session open (see pre-flight)
- [ ] Apply ruleset:
  ```bash
  sudo nft -f - <<'EOF'
  flush ruleset
  table inet filter {
    chain input {
      type filter hook input priority 0; policy drop;
      iif lo accept
      ct state established,related accept
      ip protocol icmp accept
      ip6 nexthdr icmpv6 accept
      # tcp dport 22 accept   # ONLY if Kali SSH is scored
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output priority 0; policy accept; }
  }
  EOF
  ```
- [ ] Verify ping to Kali still answers from another box
- [ ] Verify outbound works (`apt update`, DNS)
- [ ] Persist:
  ```bash
  sudo nft list ruleset | sudo tee /etc/nftables.conf >/dev/null
  sudo systemctl enable nftables
  ```
- [ ] If SSH is scored: uncomment the `22` line BEFORE applying, test from another box

---

## 6. Persistence sweep — Score 6 (I4 E3 C2)

Teams should not assume systems are clean (rule: Systems #3).

- [ ] Authorized keys everywhere:
  ```bash
  sudo find / -xdev -name authorized_keys -exec ls -la {} \; 2>/dev/null
  ```
- [ ] Cron and timers:
  ```bash
  sudo ls -la /etc/cron* /var/spool/cron/crontabs 2>/dev/null
  systemctl list-timers --all
  ```
- [ ] Preload and SUID:
  ```bash
  cat /etc/ld.so.preload 2>/dev/null
  sudo find / -xdev -perm -4000 -type f 2>/dev/null
  ```
- [ ] Shell rc files and profile.d (Kali defaults to zsh, so check `.zshrc`):
  ```bash
  grep -HEi 'curl|wget|nc |bash -i|/dev/tcp' ~/.zshrc ~/.bashrc ~/.profile /etc/profile.d/* 2>/dev/null
  ```
- [ ] Unexpected systemd units: `systemctl list-unit-files --state=enabled`, check `/etc/systemd/system/` for recent or odd files
- [ ] Live connections and processes:
  ```bash
  ss -tnp state established
  ps auxf | less
  ```
- [ ] Anything suspicious → screenshot/log it for the incident report before removing

---

## 7. sysctl network hygiene — Score 6 (I3 E2 C1)

- [ ] Check forwarding (**`1` is a red flag**; Kali shouldn't route):
  ```bash
  sysctl net.ipv4.ip_forward
  ```
- [ ] Apply:
  ```bash
  sudo sysctl -w net.ipv4.ip_forward=0 \
    net.ipv4.conf.all.accept_redirects=0 \
    net.ipv4.conf.all.send_redirects=0 \
    net.ipv4.conf.all.accept_source_route=0 \
    net.ipv4.conf.all.rp_filter=1
  ```
- [ ] Persist in `/etc/sysctl.d/99-ccdc.conf` (optional, only if time)

---

## 8. sshd tightening (ONLY if SSH stays on) — Score 4.5 (I3 E3 C2)

Do not disable password auth if scoring logs in with a password. Do not use `AllowUsers` unless you've confirmed the scoring user.

- [ ] Drop-in config:
  ```bash
  printf 'PermitRootLogin no\nMaxAuthTries 3\nPermitEmptyPasswords no\nX11Forwarding no\nLoginGraceTime 30\n' | sudo tee /etc/ssh/sshd_config.d/99-ccdc.conf
  ```
- [ ] Validate then reload:
  ```bash
  sudo sshd -t && sudo systemctl reload ssh
  ```
- [ ] Test a fresh login from another box before closing your session

---

## 9. Logging prep for incident reports — Score 4.5 (I3 E3 C2)

Incident reports are worth points (20% category). They need: source/destination IPs, timeline, what was affected, remediation plan.

- [ ] Persistent journal:
  ```bash
  sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald
  ```
- [ ] Baseline logins:
  ```bash
  last -a | head
  sudo lastb 2>/dev/null | head
  ```
- [ ] Keep a running incident log (time, source IP, dest IP, what happened, what you did)
- [ ] Submit reports to White Team as required; don't spam (frivolous reports can cost points)

---

## 10. Targeted patching only — Score 2.7 (I4 E2 C3)

- [ ] Only if internet works and time allows:
  ```bash
  sudo apt update && sudo apt install --only-upgrade openssh-server sudo
  ```
- [ ] **No full `dist-upgrade`.** No snapshot revert exists; a broken box means a new lab reservation

---

## 11. SSH host keys (ONLY if SSH stays on) — Score 2 (I2 E1 C1)

Images cloned across teams may share host keys. Low risk, cheap.

- [ ] ```bash
  sudo rm /etc/ssh/ssh_host_* && sudo dpkg-reconfigure openssh-server && sudo systemctl restart ssh
  ```
- [ ] Warn teammates: their SSH clients will show a host-key change

---

## Optional: outside-in validation (after hardening)

Only target **your own** ranges. Ask White Team first if unsure.

- [ ] Your own boxes only: `172.17.0.2` (self), `172.20.240.0/24` (inside), `172.25.(20+team#).0/24` (your public pool)
- [ ] Confirm only scored services are reachable from the outside vantage
- [ ] Confirm the PA is blocking what it should

---

## DO NOT

- [ ] ❌ Scan the core link (`172.31.x.1`), other teams, White/Red infra, or the scoring engine. **Instant DQ.**
- [ ] ❌ Block ICMP (rule 12)
- [ ] ❌ Filter SSH or scored ports by source IP (rule 9, knife-edge penalty)
- [ ] ❌ Rename users, change the hostname, or change the IP (rules 7, 11)
- [ ] ❌ Re-task Kali as a server (rule 11: workstations stay workstations)
- [ ] ❌ Delete unknown accounts (lock them; staff may need access)
- [ ] ❌ Run a full `dist-upgrade`
-