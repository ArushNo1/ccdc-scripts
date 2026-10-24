#!/bin/sh
# status:  draft
# risk:    none
# os:      any linux with OpenSSH
# tested:  never (container runs only, see testing/README.md)
#
# Read-only look at the OpenSSH server (sshd): what really listens and runs,
# what the effective configuration says, and which authorized_keys files
# exist. Changes nothing, so it is safe to run as root, and root sees more:
# sshd -T and other users' processes need it.

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

CONFIG="/etc/ssh/sshd_config"
CONFIG_DIR="/etc/ssh/sshd_config.d"

WORK="$(mktemp -d 2>/dev/null)" || {
  WORK="/tmp/ccdc-ssh-audit.$$"
  mkdir "$WORK" 2>/dev/null
}
FIND_PID=""
# shellcheck disable=SC2317  # called through the trap
cleanup() {
  [ -n "$FIND_PID" ] && kill "$FIND_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

check_root

# The file search is slow and independent, so it runs in the background while the
# other checks go on. Container and package trees are skipped.
(
  find /root /home /etc /opt /srv /usr/local /tmp /var/tmp /dev/shm /var/www /var/lib \
    \( -path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/snapd -o -path /var/lib/dpkg \) -prune -o \
    -name 'authorized_keys*' -type f -print 2>/dev/null >"$WORK/found"
) &
FIND_PID=$!

# ---- 1. preflight ---------------------------------------------------------
header "Preflight"

# Effective configuration. Needs root (host keys).
HAVE_T=0
if ! have sshd; then
  warn "sshd not found (install openssh-server): only listeners and key files are checked"
elif [ ! -f "$CONFIG" ]; then
  warn "$CONFIG does not exist: only listeners and key files are checked"
else
  ok "Found $(command -v sshd) and $CONFIG"
  if sshd -T >"$WORK/before" 2>"$WORK/before.err"; then
    HAVE_T=1
  else
    warn "sshd -T failed ($(head -n 1 "$WORK/before.err")), effective values unknown"
  fi
fi
have ssh && info "Version: $(ssh -V 2>&1 | head -n 1)"

PORTS=""
if [ "$HAVE_T" = 1 ]; then
  PORTS="$(grep '^port ' "$WORK/before" | cut -d' ' -f2 | sort -u | tr '\n' ' ')"
fi
if [ -z "$PORTS" ] && [ -f "$CONFIG" ]; then
  PORTS="$(grep -i '^[[:space:]]*Port[[:space:]]' "$CONFIG" | awk '{print $2}' | tr '\n' ' ')"
fi
[ -n "$PORTS" ] || PORTS="22"
info "Configured port(s): $PORTS"

# ---- 2. what is really listening and running ------------------------------
header "Listeners and processes"

# Listening TCP sockets from the kernel: "port inode"
: >"$WORK/listen"
for f in /proc/net/tcp /proc/net/tcp6; do
  [ -r "$f" ] || continue
  while read -r _ local _ st _ _ _ _ _ inode _; do
    [ "$st" = 0A ] || continue
    printf '%d %s\n' "0x${local##*:}" "$inode" >>"$WORK/listen"
  done <"$f"
done

# Socket inode to pid, from one ls of all fd directories
: >"$WORK/owners"
# shellcheck disable=SC2012  # find has no portable way to show link targets
ls -l /proc/[0-9]*/fd 2>/dev/null | while read -r a _ _ _ _ _ _ _ _ _ target; do
  case "$a" in
    /proc/*:)
      pid="${a#/proc/}"
      pid="${pid%%/*}"
      ;;
    *)
      case "$target" in
        socket:\[*)
          inode="${target#socket:[}"
          printf '%s %s\n' "$pid" "${inode%]}" >>"$WORK/owners"
          ;;
      esac
      ;;
  esac
done

SSHD_LISTENING=0
while read -r port inode; do
  pid="$(grep " $inode\$" "$WORK/owners" | head -n 1 | cut -d' ' -f1)"
  exe=""
  cmd=""
  if [ -n "$pid" ]; then
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
    cmd="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null)"
  fi
  base="${exe##*/}"
  ours=0
  for p in $PORTS; do
    [ "$p" = "$port" ] && ours=1
  done
  case "$base" in
    sshd*) kind=sshd ;;
    dropbear*) kind=dropbear ;;
    *) kind=other ;;
  esac
  # Only talk about listeners that matter: sshd anywhere, anything on our port
  [ "$ours" = 1 ] || [ "$kind" != other ] || continue
  if [ -z "$pid" ]; then
    info "port $port: owner unknown (needs root to read other users' /proc)"
    continue
  fi
  if [ "$kind" = sshd ]; then
    SSHD_LISTENING=1
    if [ "$ours" = 1 ]; then
      ok "port $port: sshd pid $pid ($cmd)"
    else
      warn "sshd pid $pid listens on port $port, which is not in the config ($cmd)"
    fi
    case "$cmd" in
      *" -f "*) warn "sshd pid $pid runs with a custom config file: $cmd" ;;
    esac
  elif [ "$kind" = dropbear ]; then
    warn "port $port is dropbear (pid $pid), not OpenSSH: this script does not harden it"
  else
    warn "port $port is held by $exe (pid $pid, $cmd), not sshd"
  fi
done <"$WORK/listen"
[ "$SSHD_LISTENING" = 1 ] || warn "No OpenSSH sshd was seen listening"

# Processes that call themselves sshd but are not an sshd binary (disguised)
for d in /proc/[0-9]*; do
  pid="${d#/proc/}"
  cmd="$(tr '\0' ' ' <"$d/cmdline" 2>/dev/null)"
  # Only argv[0]: other commands may mention sshd in their arguments
  argv0="${cmd%% *}"
  case "$argv0" in
    *sshd*)
      exe="$(readlink "$d/exe" 2>/dev/null)"
      case "${exe##*/}" in
        sshd*) ;;
        "") ;;
        *) warn "pid $pid looks like sshd but runs $exe ($cmd)" ;;
      esac
      ;;
  esac
done

if have who; then
  n="$(who 2>/dev/null | wc -l)"
  info "$((n)) logged-in session(s); this script does not disconnect anyone"
fi

# ---- 3. what the config says now ------------------------------------------
header "Current configuration"

if [ "$HAVE_T" = 1 ]; then
  for key in permitrootlogin passwordauthentication pubkeyauthentication permitemptypasswords authorizedkeyscommand authorizedkeysfile permituserenvironment permituserrc; do
    line="$(grep "^$key " "$WORK/before" | head -n 1)"
    [ -n "$line" ] && info "$line"
  done
  grep '^permitemptypasswords yes' "$WORK/before" >/dev/null && warn "empty passwords are allowed"
  grep '^permitrootlogin yes' "$WORK/before" >/dev/null && warn "root can log in with a password"
  grep '^authorizedkeyscommand ' "$WORK/before" | grep -v ' none$' >/dev/null &&
    warn "AuthorizedKeysCommand is set: $(grep '^authorizedkeyscommand ' "$WORK/before")"
fi

if grep -i '^[[:space:]]*Match[[:space:]]' "$CONFIG" >/dev/null 2>&1; then
  warn "$CONFIG has Match blocks (ssh-harden removes them)"
fi
if [ -d "$CONFIG_DIR" ]; then
  for f in "$CONFIG_DIR"/*; do
    [ -f "$f" ] || continue
    warn "drop-in $f (ssh-harden moves it out); active lines: $(grep -v -E '^[[:space:]]*(#|$)' "$f" | tr '\n' ';')"
  done
fi

# ---- 4. authorized_keys (listed here, moved by ssh-keys) -------------------
header "authorized_keys"

KEYPATHS=".ssh/authorized_keys .ssh/authorized_keys2"
if [ "$HAVE_T" = 1 ]; then
  p="$(grep '^authorizedkeysfile ' "$WORK/before" | head -n 1 | cut -d' ' -f2-)"
  [ -n "$p" ] && KEYPATHS="$KEYPATHS $p"
fi
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
# Also anything named authorized_keys* in the usual places (started at the top)
wait "$FIND_PID" 2>/dev/null
FIND_PID=""
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

# ---- report ---------------------------------------------------------------
header "Summary"
echo "SUMMARY: ports=$(printf '%s' "$PORTS" | tr -s ' ' ',' | sed 's/,$//') sshd_listening=$SSHD_LISTENING key_files=$NKEYFILES warnings=$WARNS"
