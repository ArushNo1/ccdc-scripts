#!/bin/sh
# status:  tested
# risk:    service-impact
# os:      any linux
# tested:  Ubuntu 2026-10-21
#
# Stops and disables each service named in DENY (below) on this host until
# restore-services runs: connections to it fail. Handles systemd (disable +
# mask, and its .socket), SysV (chkconfig, update-rc.d, insserv or links),
# Upstart (.override, never the .conf), OpenRC and inetd/xinetd.
# Does not touch names in PROTECT, a service that owns a PROTECT_PORTS port,
# sshd or the network. As non-root it only reports. Everything it changes is
# recorded in /root/ccdc-services-backup.<time>/ first; nothing is deleted.
# No restart and no kill: only the named services are stopped.

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


# ---- edit these before a run ------------------------------------------------
# Services to turn off: one name per word, exact names, no wildcards. Take them
# from the DENY= line audit-services prints. A name that is not on a host is
# skipped there without a message, so one list works on every host.
DENY="network-helper"
# Never touched, even if listed in DENY.
PROTECT="ssh sshd networking network NetworkManager systemd-networkd systemd-resolved dbus"
# Ports the scoring engine uses. Must be filled in: with this empty the script
# refuses to change anything. A service that owns one of them is skipped, and
# if one of them stops listening afterwards everything is put back.
PROTECT_PORTS="22"
# ----------------------------------------------------------------------------

D=""
cleanup() {
  [ -n "$D" ] && rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

check_root

in_list() {
  for w in $2; do
    [ "$w" = "$1" ] && return 0
  done
  return 1
}

# ports_up FILE : the protected ports that are listening now, one per line
ports_up() {
  : >"$1.p"
  for p in $PROTECT_PORTS; do
    if awk -v p=":$p" '{ n = length($2) - length(p); if (n >= 0 && substr($2, n + 1) == p) f = 1 } END { exit !f }' "$2"; then
      echo "$p" >>"$1.p"
    fi
  done
  mv "$1.p" "$1"
}

main() {
  header "Disable services ($INIT)"
  NCHG=0
  NSKIP=0

  if [ "$INIT" = none ]; then
    info "no init system here (PID 1 is '${PID1:-unknown}'): nothing to disable"
    echo "SUMMARY: changed=0 skipped=0 warnings=$WARNS"
    return 0
  fi
  case "$INIT" in
    runit|s6) warn "$INIT is not handled by this script, nothing changed"; echo "SUMMARY: changed=0 skipped=0 warnings=$WARNS"; return 0 ;;
  esac
  if [ -z "$DENY" ]; then
    warn "DENY is empty: nothing to do (fill it from the audit-services report)"
    echo "SUMMARY: changed=0 skipped=0 warnings=$WARNS"
    return 0
  fi
  if [ -z "$PROTECT_PORTS" ]; then
    warn "PROTECT_PORTS is empty: refusing to change anything without the scoring ports"
    echo "SUMMARY: changed=0 skipped=0 warnings=$WARNS"
    return 0
  fi

  ROOTOK=1
  if [ "$(id -u 2>/dev/null)" != 0 ]; then
    ROOTOK=0
    info "not root: dry run, only reporting what would change"
  fi

  D="/tmp/ccdc-disable-services.$$"
  mkdir "$D" 2>/dev/null && chmod 700 "$D" || { D=""; warn "cannot make a work directory, nothing changed"; return 1; }

  BACKUP="/root/ccdc-services-backup.$(date '+%Y%m%d-%H%M%S')"
  if [ "$ROOTOK" = 1 ]; then
    if mkdir -p "$BACKUP" 2>/dev/null && chmod 700 "$BACKUP" && : >"$BACKUP/state" 2>/dev/null; then
      ok "Backup in $BACKUP"
    else
      warn "Could not back up to $BACKUP, refusing to change anything"
      echo "SUMMARY: changed=0 skipped=0 warnings=$WARNS"
      return 1
    fi
  fi

  listeners_now "$D/before"
  ports_up "$D/up.before" "$D/before"

  for name in $DENY; do
    if in_list "$name" "$PROTECT"; then
      warn "$name is on the PROTECT list, skipped"
      NSKIP=$((NSKIP + 1))
      continue
    fi

    # a service may own a protected port: find it by unit name or process name
    owns=""
    while read -r _ addrport pid; do
      [ "$pid" = "?" ] && continue
      port="${addrport##*:}"
      in_list "$port" "$PROTECT_PORTS" || continue
      u="$(proc_unit "$pid")"
      c="$(cat "/proc/$pid/comm" 2>/dev/null)"
      case "$u" in "$name"|"$name".service|"$name".socket) owns="$port" ;; esac
      [ "$c" = "$name" ] && owns="$port"
    done <"$D/before"
    if [ -n "$owns" ]; then
      warn "$name listens on protected port $owns, skipped"
      NSKIP=$((NSKIP + 1))
      continue
    fi

    # what to touch: the service itself plus its socket (systemd starts it
    # again on the first connection if only the service is disabled)
    found=0
    for unit in "$name" "$name.socket"; do
      if [ "$unit" = "$name" ]; then
        svc_exists "$name" || continue
        u="$name"
        [ "$INIT" = systemd ] && u="$(sd_unit "$name")"
      else
        [ "$INIT" = systemd ] || continue
        unit_file "$unit" >/dev/null 2>&1 || continue
        u="$unit"
      fi
      found=1
      st="$(svc_state "$u")"
      if svc_active "$u"; then act=yes; else act=no; fi
      if [ "$ROOTOK" = 0 ]; then
        info "would stop and disable $u (state $st, running $act)"
        continue
      fi
      svc_stop "$u"
      method="$(svc_disable "$u")"
      echo "$INIT $u $st $act ${method:-none}" >>"$BACKUP/state"
      if svc_active "$u"; then
        warn "$u is still running after stop"
      else
        NCHG=$((NCHG + 1))
        ok "$u stopped and disabled ($method), was $st, running $act"
      fi
    done

    # inetd family: lines in files, not units
    if [ -f "/etc/xinetd.d/$name" ]; then
      found=1
      if [ "$ROOTOK" = 0 ]; then
        info "would set disable = yes in /etc/xinetd.d/$name"
      else
        mkdir -p "$BACKUP/xinetd" && cp -p "/etc/xinetd.d/$name" "$BACKUP/xinetd/$name" 2>/dev/null &&
          echo "xinetd /etc/xinetd.d/$name - - -" >>"$BACKUP/state" &&
          sed 's/^\([[:space:]]*disable[[:space:]]*=[[:space:]]*\)no/\1yes/' "/etc/xinetd.d/$name" >"$D/x" &&
          cat "$D/x" >"/etc/xinetd.d/$name" &&
          { hup_superserver xinetd; NCHG=$((NCHG + 1)); ok "xinetd: $name disabled"; }
      fi
    fi
    if [ -f /etc/inetd.conf ] && grep "^${name}[[:space:]]" /etc/inetd.conf >/dev/null 2>&1; then
      found=1
      if [ "$ROOTOK" = 0 ]; then
        info "would comment $name out of /etc/inetd.conf"
      else
        if [ ! -f "$BACKUP/inetd/inetd.conf" ]; then
          mkdir -p "$BACKUP/inetd" && cp -p /etc/inetd.conf "$BACKUP/inetd/inetd.conf" 2>/dev/null &&
            echo "inetd /etc/inetd.conf - - -" >>"$BACKUP/state"
        fi
        sed "s|^${name}[[:space:]]|#ccdc# &|" /etc/inetd.conf >"$D/i" &&
          cat "$D/i" >/etc/inetd.conf &&
          { hup_superserver inetd; NCHG=$((NCHG + 1)); ok "inetd: $name commented out"; }
      fi
    fi
    [ "$found" = 1 ] || NSKIP=$((NSKIP + 1))
  done

  # ---- check the result from the system, not from what we wrote ----
  if [ "$ROOTOK" = 1 ] && [ "$NCHG" -gt 0 ]; then
    header "Check"
    listeners_now "$D/after"
    ports_up "$D/up.after" "$D/after"
    LOST=""
    while read -r p; do
      grep -x "$p" "$D/up.after" >/dev/null 2>&1 || LOST="$LOST $p"
    done <"$D/up.before"
    if [ -n "$LOST" ]; then
      warn "protected ports stopped listening:$LOST, putting everything back"
      replay_state "$BACKUP/state" "$BACKUP"
      sleep 2
    else
      ok "every protected port that was listening still listens"
    fi
  fi

  header "Summary"
  [ "$ROOTOK" = 1 ] && info "undo with services/restore-services (backup: $BACKUP)"
  echo "SUMMARY: changed=$NCHG skipped=$NSKIP warnings=$WARNS"
}

( main )
