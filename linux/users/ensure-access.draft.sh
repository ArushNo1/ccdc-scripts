#!/bin/sh
# status: draft
# risk: lockout
# os: Linux with shadow-utils, OpenSSH and sudo (mutation); any Linux (inventory)
# tested: never
# shellcheck disable=SC2034 # passwd columns and shared helpers are intentionally unused in some steps
# Creates a password admin account and sudo group. Incorrect policy can prevent new admin logins.

# Reference copy of the helper block that is pasted into every script.
# Scripts do NOT source this file: CLAUDE.md requires each one to be a single
# self-contained POSIX sh file. If you change a helper here, change it in the
# scripts too.

PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
export PATH
LC_ALL=C
export LC_ALL

WARNS=0
LOGF=""
if mkdir -p /var/log/ccdc 2>/dev/null && [ -w /var/log/ccdc ]; then
  LOGF="/var/log/ccdc/$(date '+%Y-%m')-main.log"
fi

log() {
  [ -n "$LOGF" ] && printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$LOGF"
  return 0
}
header() { printf '\n== %s ==\n' "$*"; log "== $*"; }
info() { printf '[ ] %s\n' "$*"; log "INFO: $*"; }
ok() { printf '[+] %s\n' "$*"; log "OK: $*"; }
warn() { printf '[!] %s\n' "$*"; log "WARN: $*"; WARNS=$((WARNS + 1)); }

have() { command -v "$1" >/dev/null 2>&1; }

# Warn and carry on; never require root.
check_root() {
  if [ "$(id -u 2>/dev/null)" != 0 ]; then
    warn "Not running as root; results may be incomplete"
  fi
}

# ---------------------------------------------------------------------------

sudo_grants() {
policy=$(sudo -n -l -U "$1" </dev/null 2>/dev/null) || return 2
printf '%s\n' "$policy" | awk '/^[ \t]*\(/ {found=1} END {exit !found}'
}

fail() {
warn "$*"
return 1
}
password() {
[ -r /dev/urandom ] || return 1
# Read a finite amount, avoiding a long-lived random producer in a pipeline.
value=$(dd if=/dev/urandom bs=256 count=1 2>/dev/null | tr -dc 'A-Za-z0-9' | cut -c 1-32)
[ "${#value}" = 32 ] || return 1
printf 'Aa9!%s\n' "$value"
}
backup() {
umask 077
BACKUP=$(mktemp -d /var/backups/ccdc-users.XXXXXXXX 2>/dev/null) || { fail "Cannot create a root-only backup; no changes made"; return 1; }
chmod 700 "$BACKUP" || return 1
for f in passwd shadow group gshadow sudoers subuid subgid passwd- shadow- group- gshadow-; do
if [ -e "/etc/$f" ]; then
cp -p "/etc/$f" "$BACKUP/$f" || return 1
fi
done
[ -s "$BACKUP/passwd" ] && [ -s "$BACKUP/shadow" ] && [ -s "$BACKUP/group" ] && [ -s "$BACKUP/sudoers" ] || return 1
cp -p /etc/ssh/sshd_config "$BACKUP/sshd_config" || return 1
ARMED=1
info "Account and policy backup: $BACKUP"
}
restore() {
[ "$ARMED" = 1 ] || return 0
warn "Restoring account databases and sudo policy from $BACKUP"
for f in passwd shadow group gshadow sudoers subuid subgid passwd- shadow- group- gshadow-; do
if [ -f "$BACKUP/$f" ]; then
cp -p "$BACKUP/$f" "/etc/$f" || warn "RESTORE FAILED: /etc/$f; recover from $BACKUP"
fi
done
if [ -f "$BACKUP/sshd_config" ]; then
cp -p "$BACKUP/sshd_config" /etc/ssh/sshd_config || warn "RESTORE FAILED: sshd_config"
if sshd -t </dev/null; then
kill -HUP "$SSHD_PID" 2>/dev/null || warn "Could not reload restored SSH config"
fi
fi
}
finish() {
restore
[ -z "$WORK" ] || rm -rf "$WORK"
[ "$LOCKED" != 1 ] || rmdir /var/run/ccdc-users.lock 2>/dev/null
printf 'SUMMARY: users workflow warnings=%s success=%s\n' "$WARNS" "$SUCCESS"
}
preflight() {
check_root
if [ "$(id -u)" != 0 ]; then
info "DRY RUN: would back up accounts, validate sudo policy, and apply the supplied account plan"
return 2
fi
for tool in getent awk useradd usermod groupadd chpasswd passwd visudo sudo sshd mktemp dd tr cut cp; do
have "$tool" || { fail "Install $tool; no changes made (doas-only hosts are not supported yet)"; return 1; }
done
visudo -c </dev/null >/dev/null 2>&1 || { fail "Existing sudo policy is invalid"; return 1; }
sshd -t </dev/null || return 1
NOLOGIN=
for f in /usr/sbin/nologin /sbin/nologin /bin/false; do
[ ! -x "$f" ] || { NOLOGIN=$f; break; }
done
[ -n "$NOLOGIN" ] || { fail "Install nologin; no changes made"; return 1; }
mkdir /var/run/ccdc-users.lock 2>/dev/null || { fail "Another account workflow is running, or a stale /var/run/ccdc-users.lock needs investigation"; return 1; }
LOCKED=1
umask 077
WORK=$(mktemp -d 2>/dev/null) || return 1
host=$(hostname 2>/dev/null || uname -n)
}
# Controller injects these as literal validated assignments, never reads stdin.
BACKUP=
WORK=
ARMED=0
LOCKED=0
SUCCESS=FALSE

main() {
exec 3>&1 >&2
trap finish EXIT
trap 'exit 1' HUP INT TERM
preflight
rc=$?
[ "$rc" = 0 ] || return "$rc"
[ -n "${USERFLOW_ADMIN:-}" ] || { fail "No controller-supplied admin name; no changes made"; return 1; }
case "$USERFLOW_ADMIN" in
*[!a-z0-9_.-]*|''|[0-9]*) fail "Invalid admin username"; return 1 ;;
esac
[ "${#USERFLOW_ADMIN}" -le 32 ] || return 1
if getent passwd "$USERFLOW_ADMIN" </dev/null >/dev/null 2>&1; then
fail "Admin name already exists; choose a new account name"
return 1
fi
if awk -F: '$1=="ccdc_admin" {found=1} END {exit !found}' /etc/group; then
fail "ccdc_admin already exists; refuse to grant privileges to an existing group"
return 1
fi
# Reload only the default sshd master identified by its configured pidfile.
pidfile=$(sshd -T </dev/null 2>/dev/null | awk '$1=="pidfile" {print $2}')
[ -n "$pidfile" ] && [ -r "$pidfile" ] || { fail "Cannot identify default sshd master pidfile"; return 1; }
SSHD_PID=$(cat "$pidfile")
case "$SSHD_PID" in ''|*[!0-9]*) return 1 ;; esac
[ "$SSHD_PID" -gt 1 ] && kill -0 "$SSHD_PID" 2>/dev/null || return 1
# PID reuse must not signal an unrelated process.
[ -r "/proc/$SSHD_PID/comm" ] || return 1
[ "$(cat "/proc/$SSHD_PID/comm")" = sshd ] || { fail "SSH pidfile does not point to sshd"; return 1; }
methods=$(sshd -T </dev/null 2>/dev/null | awk '$1=="authenticationmethods" {print "yes"}')
# Insert the user-specific block ahead of existing Match blocks. Global
# allowlists gain only the new admin identity/group; deny rules stay in force.
awk -v u="$USERFLOW_ADMIN" -v methods="$methods" 'function rescue() {
print "Match User " u
print "    PasswordAuthentication yes"
if (methods=="yes") print "    AuthenticationMethods password"
print "Match all"
}
tolower($1)=="match" && !done {rescue(); done=1}
!done && tolower($1)=="allowusers" {sub(/[ \t]*#.*/, ""); $0=$0 " " u}
!done && tolower($1)=="allowgroups" {sub(/[ \t]*#.*/, ""); $0=$0 " ccdc_admin"}
{print}
END {if(!done) rescue()}
' /etc/ssh/sshd_config >"$WORK/sshd_config" || return 1
sshd -t -f "$WORK/sshd_config" </dev/null || return 1
pw=$(password) || { fail "Secure password generation failed"; return 1; }
# Validate the complete candidate before changing account databases.
cp -p /etc/sudoers "$WORK/sudoers" || return 1
printf '\n%%ccdc_admin ALL = (ALL) ALL\n' >>"$WORK/sudoers" || return 1
visudo -c -f "$WORK/sudoers" </dev/null >/dev/null 2>&1 || return 1
backup || return 1
groupadd ccdc_admin </dev/null || return 1
# No home files are created, so rollback only needs account databases.
groupadd "$USERFLOW_ADMIN" </dev/null || return 1
useradd -M -d / -s /bin/sh -g "$USERFLOW_ADMIN" -G ccdc_admin "$USERFLOW_ADMIN" </dev/null || return 1
printf '%s:%s\n' "$USERFLOW_ADMIN" "$pw" | chpasswd || return 1
cp -p "$WORK/sudoers" /etc/sudoers || return 1
visudo -c </dev/null >/dev/null 2>&1 || return 1
id -Gn "$USERFLOW_ADMIN" | tr ' ' '\n' | grep '^ccdc_admin$' >/dev/null || return 1
sudo_grants "$USERFLOW_ADMIN" || return 1
# Preserve original mode and owner while installing the validated candidate.
cat "$WORK/sshd_config" >/etc/ssh/sshd_config || return 1
sshd -t </dev/null || return 1
kill -HUP "$SSHD_PID" || return 1
ARMED=0
SUCCESS=TRUE
printf '%s\t%s\tadmin\tTRUE\t%s\tFALSE\t\t\n' "$host" "$USERFLOW_ADMIN" "$pw" >&3
info "Admin created. Root stays usable until the controller proves a fresh admin SSH login and sudo escalation"
}
( main )
