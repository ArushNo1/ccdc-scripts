#!/bin/sh
# status: draft
# risk: lockout
# os: Linux with shadow-utils, OpenSSH and sudo (mutation); any Linux (inventory)
# tested: never
# shellcheck disable=SC2034 # passwd columns and shared helpers are intentionally unused in some steps
# Disables root and unauthorized local logins; rotates authorized passwords and group privileges. Service accounts require preserve rows.

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
[ -n "${USERFLOW_PLAN:-}" ] && [ -n "${USERFLOW_ADMIN:-}" ] || { fail "Missing controller-supplied plan/admin; no changes made"; return 1; }
[ "${USERFLOW_CONFIRMED:-}" = YES ] || { fail "A fresh admin SSH login must be confirmed first"; return 1; }
# shellcheck disable=SC2086 # validated space-separated account records
printf '%s\n' $USERFLOW_PLAN >"$WORK/plan"
awk -F: 'NF!=3 || $1 !~ /^[a-z_][a-z0-9_.-]*$/ || ($2!="admin" && $2!="user" && $2!="preserve") || $3!="TRUE" || seen[$1]++ {bad=1} END {exit bad}' "$WORK/plan" || { fail "Invalid or duplicate account plan"; return 1; }
# Plan must contain the verified rescue admin; never rotate that session credential.
awk -F: -v u="$USERFLOW_ADMIN" '$1==u && $2=="admin" {ok=1} END {exit !ok}' "$WORK/plan" || return 1
: >"$WORK/passwords"
while IFS=: read -r name role enabled; do
row=$(awk -F: -v u="$name" '$1==u {print}' /etc/passwd)
[ -n "$row" ] || { fail "Authorized account $name is not local; create it separately or use directory tooling"; return 1; }
uid=$(printf '%s\n' "$row" | cut -d: -f3)
[ "$uid" != 0 ] || { fail "UID 0 cannot be authorized; root login is explicitly disabled by this workflow"; return 1; }
[ "$role" != preserve ] || continue
[ "$name" != "$USERFLOW_ADMIN" ] || continue
pw=$(password) || return 1
printf '%s:%s\n' "$name" "$pw" >>"$WORK/passwords"
done <"$WORK/plan"
# Password candidates and account identities are validated before backup/install.
[ -z "$(cut -d: -f2 "$WORK/passwords" | sort | uniq -d)" ] || return 1
backup || return 1
while IFS=: read -r name ignored uid gid gecos home shell; do
role=$(awk -F: -v u="$name" '$1==u {print $2}' "$WORK/plan")
if [ "$name" = "$USERFLOW_ADMIN" ] || [ "$role" = preserve ]; then continue; fi
case "$role" in
admin|user)
# Roles define exact supplemental groups; service-specific memberships need preserve.
if ! awk -F: -v u="$name" '$1==u {found=1} END {exit !found}' /etc/group; then
groupadd "$name" </dev/null || return 1
fi
primary=$(awk -F: -v u="$name" '$1==u {print $3}' /etc/group)
[ "$primary" -gt 0 ] || { fail "Unsafe primary group for $name"; return 1; }
groups=
if [ "$role" = admin ]; then groups=ccdc_admin; fi
usermod -s /bin/sh -e '' -f -1 -g "$name" -G "$groups" "$name" </dev/null || return 1
# Direct/custom sudo grants cannot safely be rewritten automatically.
if [ "$role" = user ]; then
sudo_grants "$name"
grant=$?
[ "$grant" != 2 ] || { fail "Cannot evaluate sudo privileges for $name"; return 1; }
if [ "$grant" = 0 ]; then
fail "$name retains a custom sudo grant; reverting. Review sudo policy separately"
return 1
fi
fi
;;
*)
# All unauthorized local accounts, including root and service accounts, are locked.
# List scoring/service identities as preserve to leave them untouched.
passwd -l "$name" </dev/null >/dev/null || return 1
usermod -s "$NOLOGIN" "$name" </dev/null || return 1
;;
esac
done </etc/passwd
if [ -s "$WORK/passwords" ]; then chpasswd <"$WORK/passwords" || return 1; fi
visudo -c </dev/null >/dev/null 2>&1 || return 1
sshd -t </dev/null || return 1
# Confirm installed values from account databases, not just command exit status.
while IFS=: read -r name ignored uid gid gecos home shell; do
role=$(awk -F: -v u="$name" '$1==u {print $2}' "$WORK/plan")
[ "$role" != preserve ] || continue
[ "$name" != "$USERFLOW_ADMIN" ] || continue
case "$role" in
admin|user)
[ "$shell" = /bin/sh ] || return 1
[ "$(id -gn "$name")" = "$name" ] || return 1
for installed_group in $(id -Gn "$name"); do
if [ "$installed_group" != "$name" ]; then
[ "$role:$installed_group" = admin:ccdc_admin ] || return 1
fi
done
expiry=$(awk -F: -v u="$name" '$1==u {print $7 ":" $8}' /etc/shadow)
case "$expiry" in :|-1:|:-1|-1:-1) ;; *) fail "$name remains expired/inactive"; return 1 ;; esac
state=$(awk -F: -v u="$name" '$1==u {print $2}' /etc/shadow)
case "$state" in ''|\!*|\**) fail "Authorized user $name still has a locked/empty password"; return 1 ;; esac
if [ "$role" = admin ]; then sudo_grants "$name" || return 1; fi
;;
*)
[ "$shell" = "$NOLOGIN" ] || return 1
state=$(awk -F: -v u="$name" '$1==u {print $2}' /etc/shadow)
case "$state" in \!*|\**) ;; *) return 1 ;; esac
;;
esac
done </etc/passwd
ARMED=0
SUCCESS=TRUE
while IFS=: read -r name pw; do
role=$(awk -F: -v u="$name" '$1==u {print $2}' "$WORK/plan")
printf '%s\t%s\t%s\tTRUE\t%s\tFALSE\t\t\n' "$host" "$name" "$role" "$pw" >&3
done <"$WORK/passwords"
info "Credentials rotated; root and unauthorized local logins locked. Existing sessions were not terminated"
}
( main )
