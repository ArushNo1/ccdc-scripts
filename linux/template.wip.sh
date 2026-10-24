#!/bin/sh
# status:  wip
# risk:    none        # none | lockout | service-impact
# os:      any linux
# tested:  never
#
# TEMPLATE: copy to <name>.wip.sh, replace this description with the one core
# job of the script, then delete anything you do not use.
# Rules (CLAUDE.md): strict POSIX sh, single file, no options, warn instead of
# requiring root, clean up with a trap, grouped report plus a SUMMARY line.
# No top-level `exit` (coordinate waits out its timeout): use `( main )` if you need one.

PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
export PATH
LC_ALL=C
export LC_ALL

# ---- helpers (same block as utils.sh) --------------------------------------
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

TMP=""
cleanup() {
  [ -n "$TMP" ] && rm -f "$TMP"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

check_root

# ---- 1. first step --------------------------------------------------------
header "First step"

# Pick a tool with fallbacks and warn once if none exist, do not fail:
#   if have ss; then ...; elif have netstat; then ...; else warn "install iproute2"; fi
TMP="$(mktemp 2>/dev/null)" || TMP="/tmp/ccdc-template.$$"
COUNT=0

ok "replace me"

# ---- report ---------------------------------------------------------------
header "Summary"
echo "SUMMARY: items=$COUNT warnings=$WARNS"
