#!/bin/sh
# status:  draft
# risk:    lockout
# os:      any linux with OpenSSH
# tested:  never (container runs only, see testing/README.md)
#
# Moves every authorized_keys file into /root/ccdc-ssh-keys.<time>/, so that
# turning public key logins back on does not bring old keys back with it.
# It only moves them when sshd already has public key logins off (sshd -T),
# which is what ssh-harden sets up. Otherwise it lists the files and stops.
#
# WHAT STOPS WORKING: nothing that still works at that point. Afterwards key
# logins stay dead, even if someone re-enables them, until the files are
# copied back from the backup directory.
# Not root: audit only, nothing is changed.

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

BACKUP="/root/ccdc-ssh-keys.$(date '+%Y%m%d-%H%M%S')"

WORK="$(mktemp -d 2>/dev/null)" || {
  WORK="/tmp/ccdc-ssh-keys.$$"
  mkdir "$WORK" 2>/dev/null
}
# shellcheck disable=SC2317  # called through the trap
cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

KEYS=0
IS_ROOT=0
[ "$(id -u 2>/dev/null)" = 0 ] && IS_ROOT=1

check_root

# ---- 1. are public key logins off? ----------------------------------------
header "Public key logins"

# Effective value. Needs root (host keys). sshd -T pads some values with a space.
PUBKEY=""
if have sshd && sshd -T 2>/dev/null | sed 's/[[:space:]]*$//' >"$WORK/now"; then
  PUBKEY="$(grep '^pubkeyauthentication ' "$WORK/now" | head -n 1 | cut -d' ' -f2)"
fi
[ -n "$PUBKEY" ] || PUBKEY="unknown"
if [ "$PUBKEY" = no ]; then
  ok "pubkeyauthentication no"
else
  info "pubkeyauthentication $PUBKEY"
fi

# ---- 2. find the files ----------------------------------------------------
header "authorized_keys"

KEYPATHS=".ssh/authorized_keys .ssh/authorized_keys2"
if [ -s "$WORK/now" ]; then
  p="$(grep '^authorizedkeysfile ' "$WORK/now" | head -n 1 | cut -d' ' -f2-)"
  [ -n "$p" ] && KEYPATHS="$KEYPATHS $p"
fi
# ssh-harden sets AuthorizedKeysFile none, so the paths sshd used before that
# are read from the configs it backed up.
p="$(cat /root/ccdc-ssh-backup.*/sshd_config /root/ccdc-ssh-backup.*/sshd_config.d/* 2>/dev/null |
  awk 'tolower($1) == "authorizedkeysfile" { for (i = 2; i <= NF; i++) print $i }' | sort -u | tr '\n' ' ')"
[ -n "$p" ] && KEYPATHS="$KEYPATHS $p"

: >"$WORK/keys"
# Paths with spaces are not handled (shortcut: rare, add quoting if seen)
while IFS=: read -r user _ _ _ _ home _; do
  [ -d "$home" ] || continue
  for p in $KEYPATHS; do
    [ "$p" = none ] && continue
    p="$(printf '%s' "$p" | sed "s|%h|$home|g; s|%u|$user|g; s|%%|%|g")"
    case "$p" in
      /*) ;;
      *) p="$home/$p" ;;
    esac
    [ -f "$p" ] && echo "$p" >>"$WORK/keys"
  done
done </etc/passwd
# Also anything named authorized_keys* in the usual places. Container and
# package trees are skipped.
find /root /home /etc /opt /srv /usr/local /tmp /var/tmp /dev/shm /var/www /var/lib \
  \( -path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/snapd -o -path /var/lib/dpkg \) -prune -o \
  -name 'authorized_keys*' -type f -print 2>/dev/null >"$WORK/found"
grep -v '/ccdc-ssh-' "$WORK/found" >>"$WORK/keys"
sort -u "$WORK/keys" >"$WORK/keys.sorted"

NKEYFILES=0
while read -r f; do
  [ -n "$f" ] || continue
  NKEYFILES=$((NKEYFILES + 1))
  n="$(grep -c -v -E '^[[:space:]]*(#|$)' "$f" 2>/dev/null)"
  if have lsattr && lsattr -d "$f" 2>/dev/null | cut -d' ' -f1 | grep i >/dev/null; then
    warn "$f has the immutable flag set"
  fi
  if [ "$((n))" -eq 0 ]; then
    info "$f: empty"
  else
    warn "$f: $((n)) key(s)"
  fi
done <"$WORK/keys.sorted"
[ "$NKEYFILES" -gt 0 ] || ok "no authorized_keys files found"

# ---- 3. move them aside (root only, and only when keys are off) ------------
header "Move"

if [ "$NKEYFILES" = 0 ]; then
  info "Nothing to move"
elif [ "$IS_ROOT" = 0 ]; then
  info "Not root: would move $NKEYFILES file(s), nothing changed"
elif [ "$PUBKEY" != no ]; then
  warn "Public key logins are not off (pubkeyauthentication $PUBKEY): someone may still log in with these keys, nothing moved. Run ssh-harden first"
elif ! mkdir -p "$BACKUP" 2>/dev/null || ! chmod 700 "$BACKUP"; then
  warn "Could not create $BACKUP, refusing to move anything"
else
  while read -r f; do
    [ -n "$f" ] || continue
    n="$(grep -c -v -E '^[[:space:]]*(#|$)' "$f" 2>/dev/null)"
    dest="$BACKUP/$(printf '%s' "$f" | tr '/' '_')"
    if cp -p "$f" "$dest" 2>/dev/null; then
      rm -f "$f" 2>/dev/null
      if [ -e "$f" ] && have chattr; then
        chattr -i "$f" 2>/dev/null
        rm -f "$f" 2>/dev/null
      fi
      if [ -e "$f" ]; then
        warn "Could not remove $f (copied to $dest)"
      else
        ok "Moved $f ($((n)) key(s)) to $dest"
        KEYS=$((KEYS + 1))
      fi
    else
      warn "Could not back up $f, left in place"
    fi
  done <"$WORK/keys.sorted"
fi

# ---- report ---------------------------------------------------------------
header "Summary"
[ "$IS_ROOT" = 0 ] && info "Audit only: run as root to move the files"
echo "SUMMARY: key_files=$NKEYFILES moved=$KEYS warnings=$WARNS"
