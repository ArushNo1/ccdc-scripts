#!/bin/sh
# status:  draft
# risk:    lockout
# os:      any linux
# tested:  never
#
# Creates a local admin user with a random password, locks root, and
# disables the login shell of every other account.

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
if [ "${CCDC_NO_LOG:-0}" != 1 ] && mkdir -p /var/log/ccdc 2>/dev/null && [ -w /var/log/ccdc ]; then
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

# ---- 1. admin user --------------------------------------------------------
header "Admin user"

host="$(hostname 2>/dev/null | cut -d. -f1 | tr -cd 'a-zA-Z0-9-')"
[ -n "$host" ] || host="host"
ADMIN="${host}-admin"

PASS=""
if have openssl; then
  PASS="$(openssl rand -base64 48 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 20)"
fi
if [ "${#PASS}" -lt 20 ]; then
  PASS="$(tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 20)"
fi

ADMIN_OK=0
PASS_SET=0

if id "$ADMIN" >/dev/null 2>&1; then
  info "$ADMIN already exists, resetting its password and groups"
else
  login_shell=/bin/sh
  [ -x /bin/bash ] && login_shell=/bin/bash
  if have useradd; then
    useradd -m -s "$login_shell" "$ADMIN" 2>/dev/null || useradd -m "$ADMIN" 2>/dev/null
  elif have adduser; then
    adduser -D -s "$login_shell" "$ADMIN" 2>/dev/null
  else
    warn "Neither useradd nor adduser found; cannot create $ADMIN"
  fi
fi

if id "$ADMIN" >/dev/null 2>&1; then
  ADMIN_OK=1
  ok "User $ADMIN exists"
else
  warn "User $ADMIN could not be created"
fi

if [ "$ADMIN_OK" = 1 ]; then
  if have chpasswd; then
    echo "${ADMIN}:${PASS}" | chpasswd 2>/dev/null && PASS_SET=1
  elif have passwd; then
    printf '%s\n%s\n' "$PASS" "$PASS" | passwd "$ADMIN" >/dev/null 2>&1 && PASS_SET=1
  fi
  if [ "$PASS_SET" = 1 ]; then
    ok "Password set for $ADMIN"
  else
    warn "Could not set a password for $ADMIN"
  fi
fi

# ---- 2. admin groups ------------------------------------------------------
header "Admin groups"

if [ "$ADMIN_OK" = 1 ]; then
  GOT_ADMIN_GROUP=0
  for grp in wheel sudo admin adm systemd-journal disk dialout uucp; do
    # getent can be missing on small systems; fall back to /etc/group
    if have getent; then
      getent group "$grp" >/dev/null 2>&1 || continue
    else
      grep "^$grp:" /etc/group >/dev/null 2>&1 || continue
    fi
    if have usermod && usermod -a -G "$grp" "$ADMIN" 2>/dev/null; then
      added=1
    elif have gpasswd && gpasswd -a "$ADMIN" "$grp" >/dev/null 2>&1; then
      added=1
    elif have addgroup && addgroup "$ADMIN" "$grp" >/dev/null 2>&1; then
      added=1
    else
      added=0
    fi
    if [ "$added" = 1 ]; then
      ok "Added $ADMIN to $grp"
      case "$grp" in wheel | sudo | admin) GOT_ADMIN_GROUP=1 ;; esac
    else
      warn "Could not add $ADMIN to $grp"
    fi
  done
  [ "$GOT_ADMIN_GROUP" = 1 ] || warn "$ADMIN is in no wheel/sudo/admin group, it may not be able to escalate"
else
  info "Skipped, admin user does not exist"
fi

# ---- 3. lock root ---------------------------------------------------------
header "Root account"

if have passwd && passwd -l root >/dev/null 2>&1; then
  ok "Root password locked"
elif have usermod && usermod -L root 2>/dev/null; then
  ok "Root password locked"
else
  warn "Could not lock root"
fi

# ---- 4. disable login shells ----------------------------------------------
header "Login shells"

TMP="$(mktemp 2>/dev/null)" || TMP="/tmp/ccdc-creds.$$"
(getent passwd 2>/dev/null || cat /etc/passwd) >"$TMP" 2>/dev/null

NOLOGIN="$(command -v nologin 2>/dev/null)"
[ -n "$NOLOGIN" ] || NOLOGIN="$(command -v false 2>/dev/null)"
[ -n "$NOLOGIN" ] || NOLOGIN=/bin/false

DISABLED=0
while IFS=: read -r uname _ _ _ _ _ ushell; do
  [ -n "$uname" ] || continue
  [ "$uname" = "$ADMIN" ] && continue
  # An empty shell field means /bin/sh
  [ -n "$ushell" ] || ushell=/bin/sh

  case "${ushell##*/}" in
    nologin | false | sync | halt | shutdown) continue ;;
  esac

  # Only touch shells that are real login shells
  if [ -r /etc/shells ] && ! grep -x -F -- "$ushell" /etc/shells >/dev/null 2>&1; then
    continue
  fi

  warn "$uname has login shell $ushell"
  if have usermod && usermod -s "$NOLOGIN" "$uname" 2>/dev/null; then
    DISABLED=$((DISABLED + 1))
  elif have chsh && chsh -s "$NOLOGIN" "$uname" >/dev/null 2>&1; then
    DISABLED=$((DISABLED + 1))
  else
    warn "Could not disable shell for $uname"
  fi
done <"$TMP"

ok "Disabled $DISABLED login shell(s)"

# ---- report ---------------------------------------------------------------
header "Summary"
if [ "$PASS_SET" = 1 ]; then
  echo "ADMIN LOGIN: $ADMIN / $PASS"
else
  echo "ADMIN LOGIN: not available (see warnings above)"
fi
echo "SUMMARY: admin=$ADMIN created=$ADMIN_OK shells_disabled=$DISABLED warnings=$WARNS"
