#!/bin/sh
# status: draft
# risk: lockout
# os: Linux with shadow-utils, OpenSSH and sudo (mutation); any Linux (inventory)
# tested: never
# shellcheck disable=SC2034 # passwd columns and shared helpers are intentionally unused in some steps
# Removes explicitly selected, already locked local account entries. Home directories remain; these accounts stop working.

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
have userdel || { fail "Install userdel; no changes made"; return 1; }
[ -n "${USERFLOW_DELETE:-}" ] || { fail "No operator-selected deletions"; return 1; }
minimum=$(awk '$1=="UID_MIN" {print $2; exit}' /etc/login.defs)
case "$minimum" in ''|*[!0-9]*) minimum=1000 ;; esac
for name in $USERFLOW_DELETE; do
case "$name" in ''|*[!a-z0-9_.-]*|root) return 1 ;; esac
row=$(awk -F: -v u="$name" '$1==u {print $3 ":" $7}' /etc/passwd)
[ -n "$row" ] || return 1
uid=${row%%:*}
shell=${row#*:}
[ "$uid" -ge "$minimum" ] || { fail "Refuse to delete system identity $name"; return 1; }
[ "$shell" = "$NOLOGIN" ] || { fail "$name must already be disabled"; return 1; }
state=$(awk -F: -v u="$name" '$1==u {print $2}' /etc/shadow)
case "$state" in \!*|\**) ;; *) return 1 ;; esac
# userdel must never terminate a live session. Refuse any active UID.
if ps -eo uid= 2>/dev/null | awk -v u="$uid" '$1==u {found=1} END {exit !found}'; then
fail "$name has running processes; keep the account locked"
return 1
fi
done
backup || return 1
for name in $USERFLOW_DELETE; do
userdel "$name" </dev/null || return 1
if getent passwd "$name" </dev/null >/dev/null 2>&1; then return 1; fi
info "$name: account entry removed; home and user-owned files retained"
done
ARMED=0
SUCCESS=TRUE
}
( main )
