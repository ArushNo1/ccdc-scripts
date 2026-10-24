#!/bin/sh
# status: draft
# risk: none
# os: Linux with shadow-utils, OpenSSH and sudo (mutation); any Linux (inventory)
# tested: never
# shellcheck disable=SC2034 # passwd columns and shared helpers are intentionally unused in some steps
# Enumerate NSS accounts; stdout is eight-column TSV, diagnostics are stderr.

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

main() {
exec 3>&1 >&2
check_root
host=$(hostname 2>/dev/null || uname -n)
info "Account inventory: $host"
warn "Shell eligibility is not proof of SSH access: PAM, Match rules, keys and directory enumeration may restrict or hide accounts"
if have getent; then
accounts=$(getent passwd </dev/null)
else
warn "Install getent to include enumerable directory accounts; using /etc/passwd"
accounts=$(cat /etc/passwd)
fi
count=0
printf '%s\n' "$accounts" | while IFS=: read -r name ignored uid gid gecos home shell; do
[ -n "$name" ] || continue
priv=user
enabled=TRUE
case "$shell" in
*/nologin|*/false|*/sync|*/shutdown|*/halt) enabled=FALSE ;;
*) [ -z "$shell" ] || [ -x "$shell" ] || enabled=FALSE ;;
esac
[ "$uid" != 0 ] || priv='admin'
if have sudo && sudo_grants "$name"; then priv='admin'; fi
if [ -r /etc/shadow ]; then
state=$(awk -F: -v u="$name" '$1==u {print $2 ":" $8}' /etc/shadow)
# A locked password does not disable key authentication; keep shell eligibility.
case "$state" in
\!*|\** ) info "$name: password locked; keys may still work" ;;
esac
fi
printf '%s\t%s\t%s\t%s\t\tTRUE\t\t\n' "$host" "$name" "$priv" "$enabled" >&3
info "$name: privilege=$priv login-shell=$enabled"
done
count=$(printf '%s\n' "$accounts" | awk -F: 'NF>=7 {n++} END {print n+0}')
printf 'SUMMARY: accounts=%s warnings=%s\n' "$count" "$WARNS"
}
( main )
