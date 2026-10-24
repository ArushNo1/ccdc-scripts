#!/bin/sh
# status:  tested
# risk:    service-impact
# os:      any linux
# tested:  Ubuntu 12026-10-21
#
# Puts back what the newest /root/ccdc-services-backup.*/state records, as
# written by disable-services: unmask, enable and start systemd units,
# re-enable SysV links, drop our Upstart .override, restore xinetd/inetd
# files and reload the super-server. Services that were stopped before
# disable-services ran stay stopped. Leaves the backup in place.

# shellcheck disable=SC2009,SC2012,SC2015,SC2094  # ls/ps are the portable tools here
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
# ---- init system, found from the running system (same block in -----------
# services/audit-services, services/disable-services, services/restore-services).
# INIT is one of: systemd upstart openrc sysv runit s6 none.
# "none" means PID 1 is not an init (a container): there is nothing to enable.
INIT=none
ALSO=""
PID1="$(cat /proc/1/comm 2>/dev/null)"
[ -n "$PID1" ] || PID1="$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ')"
RCD=""
for d in /etc/rc3.d /etc/rc.d/rc3.d /etc/rc2.d; do
  if [ -d "$d" ]; then RCD="$d"; break; fi
done
INITD_COUNT=0
for f in /etc/init.d/*; do [ -f "$f" ] && INITD_COUNT=$((INITD_COUNT + 1)); done

if [ -d /run/systemd/system ]; then
  INIT=systemd
elif have initctl && initctl version </dev/null 2>/dev/null | grep -i upstart >/dev/null 2>&1; then
  INIT=upstart
elif [ -d /run/openrc ] || { [ -d /etc/runlevels ] && [ "$PID1" = init ] && have rc-update; }; then
  INIT=openrc
elif [ "$PID1" = runit ] || [ -d /run/runit ]; then
  INIT=runit
elif [ "$PID1" = s6-svscan ] || [ -d /run/s6 ]; then
  INIT=s6
elif [ "$PID1" = init ] && [ -n "$RCD" ] && [ "${INITD_COUNT:-0}" -gt 0 ]; then
  INIT=sysv
fi
# Things that also start programs on this host, whatever INIT is
if [ "$INIT" != sysv ] && [ "${INITD_COUNT:-0}" -gt 0 ] && [ -n "$RCD" ]; then ALSO="$ALSO sysv"; fi
[ -d /etc/xinetd.d ] && ALSO="$ALSO xinetd"
[ -f /etc/inetd.conf ] && ALSO="$ALSO inetd"

# systemd names carry a type; a bare name means NAME.service
sd_unit() {
  case "$1" in
    *.*) echo "$1" ;;
    *) echo "$1.service" ;;
  esac
}

unit_file() {
  for d in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    if [ -e "$d/$1" ]; then echo "$d/$1"; return 0; fi
  done
  return 1
}

# Is a process with this exact name running? pidfile first, then the table.
proc_running() {
  for pf in /var/run/$1.pid /run/$1.pid /var/run/$1/$1.pid /run/$1/$1.pid; do
    if [ -r "$pf" ]; then
      p="$(head -n 1 "$pf" 2>/dev/null | tr -d ' ')"
      case "$p" in
        ''|*[!0-9]*) ;;
        *) [ -d "/proc/$p" ] && return 0 ;;
      esac
    fi
  done
  if have pgrep; then
    pgrep -x "$1" >/dev/null 2>&1 && return 0
    return 1
  fi
  ps -e -o comm= 2>/dev/null | grep -x "$1" >/dev/null 2>&1
}

sysv_link() {
  [ -n "$RCD" ] || return 1
  for l in "$RCD"/S[0-9][0-9]"$1"; do
    [ -e "$l" ] || [ -L "$l" ] && { echo "$l"; return 0; }
  done
  return 1
}

# svc_exists NAME : is there a service of this name for this init system
svc_exists() {
  case "$INIT" in
    systemd) unit_file "$(sd_unit "$1")" >/dev/null 2>&1 || [ -f "/etc/init.d/$1" ] ;;
    upstart) [ -f "/etc/init/$1.conf" ] || [ -f "/etc/init.d/$1" ] ;;
    sysv|openrc) [ -f "/etc/init.d/$1" ] ;;
    *) return 1 ;;
  esac
}

# svc_active NAME : running now? Uses the process table where the init
# system cannot be trusted (old sysv status actions often always say 0).
svc_active() {
  case "$INIT" in
    systemd) systemctl is-active "$(sd_unit "$1")" </dev/null >/dev/null 2>&1 ;;
    upstart)
      if initctl status "$1" </dev/null 2>/dev/null | grep 'start/running' >/dev/null 2>&1; then return 0; fi
      proc_running "$1"
      ;;
    openrc) rc-service "$1" status </dev/null >/dev/null 2>&1 ;;
    sysv) proc_running "$1" ;;
    *) return 1 ;;
  esac
}

# svc_state NAME : prints enabled | disabled | masked | static | unknown
svc_state() {
  case "$INIT" in
    systemd)
      s="$(systemctl is-enabled "$(sd_unit "$1")" </dev/null 2>/dev/null)"
      case "$s" in
        enabled*|linked*|alias) echo enabled ;;
        masked*) echo masked ;;
        static|indirect|generated) echo static ;;
        disabled) echo disabled ;;
        *) echo unknown ;;
      esac
      ;;
    upstart)
      if sysv_link "$1" >/dev/null 2>&1; then echo enabled; return 0; fi
      if [ -f "/etc/init/$1.override" ] && grep '^manual' "/etc/init/$1.override" >/dev/null 2>&1; then
        echo disabled
      elif [ -f "/etc/init/$1.conf" ]; then
        if grep '^manual' "/etc/init/$1.conf" >/dev/null 2>&1; then echo disabled; else echo enabled; fi
      else
        echo unknown
      fi
      ;;
    openrc)
      if rc-update show 2>/dev/null </dev/null | awk -v n="$1" '$1 == n { f = 1 } END { exit !f }'; then
        echo enabled
      else
        echo disabled
      fi
      ;;
    sysv)
      if have chkconfig && chkconfig --list "$1" </dev/null 2>/dev/null | grep '[35]:on' >/dev/null 2>&1; then
        echo enabled
      elif sysv_link "$1" >/dev/null 2>&1; then
        echo enabled
      elif [ -f "/etc/init.d/$1" ]; then
        echo disabled
      else
        echo unknown
      fi
      ;;
    *) echo unknown ;;
  esac
}

svc_stop() {
  case "$INIT" in
    systemd) systemctl stop "$(sd_unit "$1")" </dev/null >/dev/null 2>&1 ;;
    upstart)
      if [ -f "/etc/init/$1.conf" ]; then
        initctl stop "$1" </dev/null >/dev/null 2>&1
      elif [ -x "/etc/init.d/$1" ]; then
        "/etc/init.d/$1" stop </dev/null >/dev/null 2>&1
      fi
      ;;
    openrc) rc-service "$1" stop </dev/null >/dev/null 2>&1 ;;
    sysv)
      if [ -x "/etc/init.d/$1" ]; then
        "/etc/init.d/$1" stop </dev/null >/dev/null 2>&1
      elif have service; then
        service "$1" stop </dev/null >/dev/null 2>&1
      fi
      ;;
    *) return 1 ;;
  esac
}

svc_start() {
  case "$INIT" in
    systemd) systemctl start "$(sd_unit "$1")" </dev/null >/dev/null 2>&1 ;;
    upstart)
      if [ -f "/etc/init/$1.conf" ]; then
        initctl start "$1" </dev/null >/dev/null 2>&1
      elif [ -x "/etc/init.d/$1" ]; then
        "/etc/init.d/$1" start </dev/null >/dev/null 2>&1
      fi
      ;;
    openrc) rc-service "$1" start </dev/null >/dev/null 2>&1 ;;
    sysv)
      if [ -x "/etc/init.d/$1" ]; then
        "/etc/init.d/$1" start </dev/null >/dev/null 2>&1
      elif have service; then
        service "$1" start </dev/null >/dev/null 2>&1
      fi
      ;;
    *) return 1 ;;
  esac
}

# svc_disable NAME : stop it coming back at boot or on demand. Prints the
# method used (recorded in the backup so restore can undo exactly that).
svc_disable() {
  case "$INIT" in
    systemd)
      systemctl disable "$(sd_unit "$1")" </dev/null >/dev/null 2>&1
      # mask survives a package upgrade re-enabling it; it fails when the
      # unit is a real file in /etc/systemd/system, disable has to do then
      systemctl mask "$(sd_unit "$1")" </dev/null >/dev/null 2>&1
      echo systemctl
      ;;
    upstart)
      if [ -f "/etc/init/$1.conf" ]; then
        echo "manual # ccdc-services" >>"/etc/init/$1.override"
      fi
      if sysv_link "$1" >/dev/null 2>&1; then sysv_disable "$1"; else echo override; fi
      ;;
    openrc)
      rc-update del "$1" </dev/null >/dev/null 2>&1
      echo rc-update
      ;;
    sysv) sysv_disable "$1" ;;
    *) echo none; return 1 ;;
  esac
}

# Debian, RedHat, SUSE and bare systems each have their own tool.
# S links become K links, which is the reversible form on all of them.
sysv_disable() {
  if have chkconfig; then
    chkconfig "$1" off </dev/null >/dev/null 2>&1
    echo chkconfig
  elif have update-rc.d; then
    update-rc.d "$1" disable </dev/null >/dev/null 2>&1
    echo update-rc.d
  elif have insserv; then
    insserv -r "$1" </dev/null >/dev/null 2>&1
    echo insserv
  else
    for l in /etc/rc?.d/S[0-9][0-9]"$1" /etc/rc.d/rc?.d/S[0-9][0-9]"$1"; do
      [ -L "$l" ] || [ -e "$l" ] || continue
      b="$(basename "$l")"
      mv "$l" "$(dirname "$l")/K${b#S}" 2>/dev/null
    done
    echo links
  fi
}

# svc_enable NAME METHOD : undo svc_disable
svc_enable() {
  case "$INIT" in
    systemd)
      systemctl unmask "$(sd_unit "$1")" </dev/null >/dev/null 2>&1
      systemctl enable "$(sd_unit "$1")" </dev/null >/dev/null 2>&1
      ;;
    upstart)
      if [ -f "/etc/init/$1.override" ]; then
        grep -v '# ccdc-services' "/etc/init/$1.override" >"/etc/init/$1.override.new" 2>/dev/null
        if [ -s "/etc/init/$1.override.new" ]; then
          cat "/etc/init/$1.override.new" >"/etc/init/$1.override"
          rm -f "/etc/init/$1.override.new"
        else
          rm -f "/etc/init/$1.override.new" "/etc/init/$1.override"
        fi
      fi
      [ "$2" = override ] || sysv_enable "$1" "$2"
      ;;
    openrc) rc-update add "$1" default </dev/null >/dev/null 2>&1 ;;
    sysv) sysv_enable "$1" "$2" ;;
  esac
}

sysv_enable() {
  case "$2" in
    chkconfig) chkconfig "$1" on </dev/null >/dev/null 2>&1 ;;
    update-rc.d) update-rc.d "$1" enable </dev/null >/dev/null 2>&1 ;;
    insserv) insserv "$1" </dev/null >/dev/null 2>&1 ;;
    links)
      for l in /etc/rc?.d/K[0-9][0-9]"$1" /etc/rc.d/rc?.d/K[0-9][0-9]"$1"; do
        [ -L "$l" ] || [ -e "$l" ] || continue
        b="$(basename "$l")"
        mv "$l" "$(dirname "$l")/S${b#K}" 2>/dev/null
      done
      ;;
  esac
}

# ---- what is listening, from /proc (works when the tools are missing) -------
# listen_table : "proto addr:port inode" for every listening tcp socket and
# every bound udp socket
listen_table() {
  for p in tcp tcp6 udp udp6; do
    [ -r "/proc/net/$p" ] || continue
    awk -v P="$p" '
      # hex to decimal without functions (old awks differ on them)
      NR > 1 {
        if (P ~ /^tcp/ && $4 != "0A") next
        if (P ~ /^udp/ && $4 != "07") next
        n = split($2, a, ":")
        h = tolower(a[1]); x = tolower(a[n]); port = 0
        for (i = 1; i <= length(x); i++) port = port * 16 + index("0123456789abcdef", substr(x, i, 1)) - 1
        if (length(h) == 8) {
          addr = ""
          for (j = 7; j >= 1; j -= 2) {
            v = 0
            for (i = j; i <= j + 1; i++) v = v * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1
            addr = addr (addr == "" ? "" : ".") v
          }
        }
        else if (h ~ /^0+$/) addr = "::"
        else if (h == "00000000000000000000000001000000") addr = "::1"
        else addr = "v6"
        print substr(P, 1, 3), addr ":" port, $10
      }' "/proc/net/$p" 2>/dev/null
  done
}

# socket_owners : "inode pid" for every socket fd we are allowed to see
socket_owners() {
  ls -l /proc/[0-9]*/fd 2>/dev/null | awk '
    /^\/proc\/[0-9]+\/fd:$/ { split($0, a, "/"); pid = a[3]; next }
    /socket:\[[0-9]+\]/ {
      s = $0; sub(/.*socket:\[/, "", s); sub(/\].*/, "", s)
      print s, pid
    }'
}

# listeners_now FILE : "proto addr:port pid" per listening socket, pid is ?
# when no process can be seen (hidden, or we are not root)
listeners_now() {
  listen_table >"$1.sock"
  socket_owners >"$1.own"
  awk 'NR == FNR { own[$1] = $2; next }
       { p = ($3 in own) ? own[$3] : "?"; print $1, $2, p }' "$1.own" "$1.sock" | sort -u >"$1"
  rm -f "$1.sock" "$1.own"
}

# proc_unit PID : the unit or init script that owns this process, or "-"
proc_unit() {
  u=""
  if [ -r "/proc/$1/cgroup" ]; then
    u="$(awk -F/ '$NF ~ /\.(service|scope)$/ { n = $NF } END { print n }' "/proc/$1/cgroup" 2>/dev/null)"
  fi
  if [ -z "$u" ]; then
    for pf in /var/run/*.pid /run/*.pid /var/run/*/*.pid /run/*/*.pid; do
      [ -r "$pf" ] || continue
      if [ "$(head -n 1 "$pf" 2>/dev/null | tr -d ' ')" = "$1" ]; then
        u="$(basename "$pf" .pid)"
        break
      fi
    done
  fi
  echo "${u:--}"
}

# ---- restore: replay a state file written by disable-services ---------------
# line: INIT UNIT STATE ACTIVE METHOD   (or: inetd FILE, xinetd FILE)
# State was recorded before the change, so this puts back exactly that.
replay_state() {
  # $1 = state file, $2 = backup directory
  [ -f "$1" ] || return 1
  while read -r r_init r_unit r_state r_active r_method; do
    case "$r_init" in
      inetd|xinetd)
        if [ -f "$2/$r_init/$(basename "$r_unit")" ]; then
          cat "$2/$r_init/$(basename "$r_unit")" >"$r_unit" 2>/dev/null && ok "put back $r_unit"
          hup_superserver "$r_init"
        else
          warn "no saved copy of $r_unit in $2"
        fi
        ;;
      *)
        [ "$r_init" = "$INIT" ] || { warn "$r_unit was recorded under $r_init, this host runs $INIT: not touched"; continue; }
        # the unit name is already the right shape for this init system
        if [ "$INIT" = systemd ]; then
          systemctl unmask "$r_unit" </dev/null >/dev/null 2>&1
          [ "$r_state" = enabled ] && systemctl enable "$r_unit" </dev/null >/dev/null 2>&1
          [ "$r_active" = yes ] && systemctl start "$r_unit" </dev/null >/dev/null 2>&1
        else
          [ "$INIT" = upstart ] && svc_enable "$r_unit" override
          [ "$r_state" = enabled ] && svc_enable "$r_unit" "$r_method"
          [ "$r_active" = yes ] && svc_start "$r_unit"
        fi
        ok "restored $r_unit (was $r_state, active=$r_active)"
        ;;
    esac
  done <"$1"
  return 0
}

# kill -HUP is a reload: it does not drop what is already connected
hup_superserver() {
  for pn in "$1" openbsd-inetd; do
    for pid in $(pgrep -x "$pn" 2>/dev/null); do
      kill -HUP "$pid" 2>/dev/null
    done
  done
}


D=""
cleanup() {
  [ -n "$D" ] && rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

check_root

main() {
  header "Restore services ($INIT)"
  if [ "$(id -u 2>/dev/null)" != 0 ]; then
    info "not root: cannot read /root/ccdc-services-backup.*, nothing changed"
    echo "SUMMARY: restored=0 warnings=$WARNS"
    return 0
  fi

  # newest backup first (the names carry the time)
  NEWEST=""
  for b in /root/ccdc-services-backup.*; do
    [ -f "$b/state" ] && NEWEST="$b"
  done
  if [ -z "$NEWEST" ]; then
    warn "no /root/ccdc-services-backup.*/state found, nothing to restore"
    echo "SUMMARY: restored=0 warnings=$WARNS"
    return 0
  fi
  info "restoring from $NEWEST"
  N="$(wc -l <"$NEWEST/state" | tr -d ' ')"
  replay_state "$NEWEST/state" "$NEWEST"

  header "Summary"
  info "the backup was left in place: $NEWEST"
  echo "SUMMARY: restored=$N warnings=$WARNS"
}

( main )
