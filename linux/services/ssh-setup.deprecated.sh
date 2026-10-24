#!/bin/sh
# status:  deprecated
# risk:    lockout
# os:      any linux with OpenSSH
# tested:  never
#
# Applies a fixed set of hardening options to sshd_config, validates the result
# before installing it, backs up the original and reloads sshd.
# Port and PasswordAuthentication are left alone on purpose: changing them
# blindly can lock out the team and the scoring engine.

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
BACKUP_DIR="/etc/ssh/sshd_config.backups"

# Option and value, one per line. The first value sshd reads wins.
OPTIONS="PermitRootLogin no
PubkeyAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 5
MaxSessions 10"

WORK="$(mktemp -d 2>/dev/null)" || {
  WORK="/tmp/ccdc-ssh.$$"
  mkdir "$WORK" 2>/dev/null
}
cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

have() { command -v "$1" >/dev/null 2>&1; }

INSTALLED=0
RELOADED=0

check_root

# ---- 1. preflight ---------------------------------------------------------
header "Preflight"

if ! have sshd; then
  warn "sshd not found, nothing to harden"
  echo "SUMMARY: installed=0 reloaded=0 warnings=$WARNS"
  exit 0
fi
if [ ! -f "$CONFIG" ]; then
  warn "$CONFIG does not exist, nothing to harden"
  echo "SUMMARY: installed=0 reloaded=0 warnings=$WARNS"
  exit 0
fi
ok "Found sshd and $CONFIG"

if grep -i '^[[:space:]]*Match[[:space:]]' "$CONFIG" >/dev/null 2>&1; then
  warn "$CONFIG has Match blocks, they can override these settings for some users"
fi

# ---- 2. backup ------------------------------------------------------------
header "Backup"

STAMP="$(date '+%Y%m%d-%H%M%S')"
BACKUP="$BACKUP_DIR/sshd_config.$STAMP"
if mkdir -p "$BACKUP_DIR" 2>/dev/null && cp -p "$CONFIG" "$BACKUP" 2>/dev/null; then
  ok "Backed up $CONFIG to $BACKUP"
  if [ -d "$CONFIG_DIR" ]; then
    cp -pR "$CONFIG_DIR" "$BACKUP_DIR/sshd_config.d.$STAMP" 2>/dev/null &&
      ok "Backed up $CONFIG_DIR"
  fi
else
  # Do not touch a config we could not back up
  warn "Could not create a backup, refusing to change the configuration"
  echo "SUMMARY: installed=0 reloaded=0 warnings=$WARNS"
  exit 0
fi

# ---- 3. build the new config ----------------------------------------------
header "Settings"

cp "$CONFIG" "$WORK/body"

# Remove existing (and commented-out) copies of each option, any case
printf '%s\n' "$OPTIONS" | while read -r key _; do
  grep -iv "^[[:space:]]*#*[[:space:]]*${key}[[:space:]]" "$WORK/body" >"$WORK/body.new"
  mv "$WORK/body.new" "$WORK/body"
done

# Put ours first: sshd uses the first value it sees, and the Include line for
# sshd_config.d/ at the top of newer configs would otherwise win.
{
  echo "# Managed by CCDC ssh-setup, original backed up in $BACKUP_DIR"
  printf '%s\n' "$OPTIONS"
  cat "$WORK/body"
} >"$WORK/new"

printf '%s\n' "$OPTIONS" | while read -r key val; do
  info "$key $val"
done

# ---- 4. validate, then install --------------------------------------------
header "Validate and install"

if ! sshd -t -f "$WORK/new" 2>"$WORK/err"; then
  warn "sshd rejected the new configuration, original left untouched"
  cat "$WORK/err"
  echo "SUMMARY: installed=0 reloaded=0 warnings=$WARNS"
  exit 0
fi
ok "New configuration passes sshd -t"

# cat keeps the existing owner and mode of the file
if cat "$WORK/new" >"$CONFIG" 2>/dev/null; then
  INSTALLED=1
  ok "Installed new $CONFIG"
else
  warn "Could not write $CONFIG"
fi

# ---- 5. reload ------------------------------------------------------------
header "Reload"

if [ "$INSTALLED" = 1 ]; then
  if have systemctl && (systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null); then
    RELOADED=1
  elif have service && (service ssh reload >/dev/null 2>&1 || service sshd reload >/dev/null 2>&1); then
    RELOADED=1
  elif [ -x /etc/init.d/ssh ] && /etc/init.d/ssh reload >/dev/null 2>&1; then
    RELOADED=1
  elif [ -x /etc/init.d/sshd ] && /etc/init.d/sshd reload >/dev/null 2>&1; then
    RELOADED=1
  else
    # Last resort: SIGHUP the daemon through its pid file
    for pidfile in /var/run/sshd.pid /run/sshd.pid; do
      if [ -r "$pidfile" ] && kill -HUP "$(cat "$pidfile")" 2>/dev/null; then
        RELOADED=1
        break
      fi
    done
  fi

  if [ "$RELOADED" = 1 ]; then
    ok "sshd reloaded"
  else
    warn "Could not reload sshd, reload it by hand. Backup: $BACKUP"
  fi
else
  info "Skipped, configuration was not installed"
fi

# ---- 6. check effective values --------------------------------------------
header "Effective configuration"

if [ "$INSTALLED" = 1 ] && sshd -T >"$WORK/effective" 2>/dev/null; then
  printf '%s\n' "$OPTIONS" | tr '[:upper:]' '[:lower:]' >"$WORK/want"
  while read -r key val; do
    if grep -x -F -- "$key $val" "$WORK/effective" >/dev/null 2>&1; then
      ok "$key $val"
    else
      got="$(grep "^$key " "$WORK/effective" | head -n 1)"
      warn "$key is not '$val' (effective: ${got:-unknown})"
    fi
  done <"$WORK/want"
else
  info "Skipped, could not read effective configuration (sshd -T)"
fi

# ---- report ---------------------------------------------------------------
header "Summary"
if grep -x -F 'passwordauthentication yes' "$WORK/effective" >/dev/null 2>&1; then
  info "PasswordAuthentication is still enabled (left alone on purpose)"
fi
echo "SUMMARY: installed=$INSTALLED reloaded=$RELOADED warnings=$WARNS"
echo "Keep this session open and test a NEW connection before closing it."
