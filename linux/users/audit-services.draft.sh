#!/bin/sh
# status:  draft
# risk:    none
# os:      any linux
# tested:  never
#
# Look at what listens and what starts at boot or on demand, for systemd,
# SysV, Upstart, OpenRC and bare containers, and report only what is unusual.
# Changes nothing. Normal means the package manager owns the file and it sits
# in a system directory; unusual is an unpackaged unit, drop-in or program, one
# run from /tmp or /home, a deleted binary, a renamed process, a listener with
# no owner, an inetd entry, or a name on the risky list. Listening sockets are
# read from /proc, so a hidden service still shows its port. Without dpkg, rpm
# or apk only locations are checked. Prints a DENY= line to paste into
# services/disable-services when risky names were found.
# Rules (CLAUDE.md): strict POSIX sh, no options, warn instead of requiring
# root, cleanup trap, grouped report plus a SUMMARY line.

# shellcheck disable=SC2009,SC2012,SC2013,SC2015,SC2046,SC2094  # ls/ps are the portable tools here
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
# first15/audit-services, services/disable-services, services/restore-services).
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

D="/tmp/ccdc-audit-services.$$"
cleanup() {
  [ -n "$D" ] && rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

check_root
mkdir "$D" 2>/dev/null && chmod 700 "$D" || { D=""; warn "cannot make a work directory in /tmp, nothing was checked"; }


# Names that are known to be risky. Only used to label what the system itself
# reported, never to decide what exists. Everything else is judged by who owns
# the file (see packaged), not by its name.
label() {
  case "$1" in
    telnet*|rsh*|rlogin*|rexec*|shell|login|tftp*|vsftpd|proftpd|pure-ftpd|ftp|avahi*|cups*|rpcbind|portmap|nfs*|snmpd|smbd|nmbd|samba|bluetooth*|talk|ntalk|echo|chargen|discard|daytime|time) echo risky ;;
    *) echo other ;;
  esac
}

# dual_use NAME : a program that can be turned into a listener or a backdoor.
# Being packaged proves nothing for these (nc is in netcat-openbsd), so a
# listener running one is always reported.
dual_use() {
  case "$1" in
    nc|nc.*|ncat|netcat|socat|openssl|busybox|bash|sh|dash|ash|zsh|ksh|perl*|python*|ruby*|php*|lua*|node|nodejs|awk|gawk|mawk|telnet|cryptcat|sbd) return 0 ;;
  esac
  return 1
}

# packaged FILE : does a package own this file?
# returns 0 yes, 1 no, 2 cannot tell. Without a package manager only the
# location is judged: system directories are normal, /etc is unknowable.
packaged() {
  pk="$1"
  [ -n "$pk" ] || return 2
  case "$PKG" in
    dpkg)
      # dpkg lists /bin or /usr/bin depending on the release, so try both
      for c in "$pk" "/usr$pk" "${pk#/usr}"; do
        grep -Fx "$c" "$D/pkgfiles" </dev/null >/dev/null 2>&1 && return 0
      done
      return 1
      ;;
    rpm) rpm -qf "$pk" </dev/null >/dev/null 2>&1 && return 0; return 1 ;;
    apk) apk info -W "$pk" </dev/null 2>/dev/null | grep owned >/dev/null 2>&1 && return 0; return 1 ;;
  esac
  case "$pk" in
    /usr/*|/bin/*|/sbin/*|/lib*|/opt/*) return 0 ;;
    /etc/*) return 2 ;;
  esac
  return 1
}

# real_path FILE : follow symlinks (a unit enabled by hand is a link into /lib)
real_path() {
  rp="$1"
  n=0
  while [ -L "$rp" ] && [ "$n" -lt 10 ]; do
    n=$((n + 1))
    lt="$(ls -ld "$rp" 2>/dev/null | sed 's/.* -> //')"
    case "$lt" in
      '') break ;;
      /*) rp="$lt" ;;
      *) rp="$(dirname "$rp")/$lt" ;;
    esac
  done
  echo "$rp"
}

# odd_place FILE : is it somewhere a service has no business running from
odd_place() {
  case "$1" in
    *"(deleted)"|/tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*|/run/user/*) return 0 ;;
  esac
  return 1
}

# flag_unit NAME FILE EXEC DROPINS : counts the unit, and warns only if
# something about it is unusual
flag_unit() {
  fu="$1"
  NUNITS=$((NUNITS + 1))
  why=""
  base="${fu%.service}"; base="${base%.socket}"; base="${base%.timer}"
  if [ "$(label "$base")" = risky ]; then why="$why; on the risky list"; fi

  if [ -n "$2" ] && [ -e "$2" ]; then
    f="$(real_path "$2")"
    case "$f" in
      /run/systemd/generator*) ;;
      *) packaged "$f"; [ $? -eq 1 ] && why="$why; $f belongs to no package" ;;
    esac
  fi
  for d in $4; do
    d="$(real_path "$d")"
    packaged "$d"; [ $? -eq 1 ] && why="$why; drop-in $d belongs to no package"
  done
  if [ -n "$3" ]; then
    if odd_place "$3"; then
      why="$why; runs $3"
    elif [ -e "$3" ]; then
      x="$(real_path "$3")"
      packaged "$x"; [ $? -eq 1 ] && why="$why; program $x belongs to no package"
    fi
  fi

  [ -n "$why" ] || return 0
  NODD=$((NODD + 1))
  case "$why" in *"risky list"*) RISKY="$RISKY $base" ;; esac
  case "$INIT" in
    systemd) st="$(svc_state "$fu")" ;;
    *) st="$(svc_state "$base")" ;;
  esac
  if svc_active "$fu" 2>/dev/null; then act=running; else act=stopped; fi
  ports="$(grep -F "$base" "$D/listen.units" 2>/dev/null | awk 'NF == 2 && $2 ~ /:/ { printf "%s ", $2 }')"
  warn "$fu ($st, $act${ports:+, listens $ports}): ${why#; }"
}

main() {
  [ -n "$D" ] || return 0
  RISKY=""
  NLISTEN=0
  NUNITS=0
  NODD=0
  NHIDDEN=0
  EXPECTED=""

  # Who owns files: the package database says what is normal on this host
  PKG=none
  if [ -d /var/lib/dpkg/info ]; then
    cat /var/lib/dpkg/info/*.list >"$D/pkgfiles" 2>/dev/null </dev/null
    [ -s "$D/pkgfiles" ] && PKG=dpkg
  elif have rpm; then
    PKG=rpm
  elif have apk && [ -d /lib/apk ]; then
    PKG=apk
  fi
  if [ "$PKG" = none ]; then
    warn "no dpkg, rpm or apk: cannot tell packaged files from others, only locations are checked"
  fi

  header "Init system"
  info "PID 1 is '${PID1:-unknown}', init system: $INIT, packages: $PKG${ALSO:+, also:$ALSO}"
  case "$INIT" in
    none) info "no init system here (container?): only processes and sockets are listed" ;;
    runit|s6) warn "$INIT is only reported, disable-services does not change it" ;;
  esac

  # ---- listening sockets: the truth, whatever the service is called ----
  header "Unusual listeners"
  : >"$D/listen.units"
  if [ ! -r /proc/net/tcp ]; then
    if have ss; then
      ss -lntup 2>/dev/null </dev/null
    elif have netstat; then
      netstat -lntup 2>/dev/null </dev/null
    else
      warn "no /proc/net, ss or netstat: install iproute2 to see listening ports"
    fi
  else
    listeners_now "$D/listen"
    while read -r proto addrport pid; do
      NLISTEN=$((NLISTEN + 1))
      if [ "$pid" = "?" ]; then
        # as non-root most owners are invisible: count them, warn once at the end
        if [ "$(id -u 2>/dev/null)" = 0 ]; then
          warn "$proto $addrport: no process owns it (hidden?)"
        else
          NHIDDEN=$((NHIDDEN + 1))
        fi
        continue
      fi
      comm="$(cat "/proc/$pid/comm" 2>/dev/null)"
      exe="$(readlink "/proc/$pid/exe" 2>/dev/null </dev/null)"
      owner="$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')"
      unit="$(proc_unit "$pid")"
      echo "$unit ${addrport}/$proto" >>"$D/listen.units"
      echo "$comm $unit" >>"$D/listen.units"
      case "${addrport%:*}" in
        127.*|::1) where="local-only" ;;
        *) where="EXPOSED" ;;
      esac

      why=""
      if [ "$(label "${unit%.service}")" = risky ] || [ "$(label "$comm")" = risky ]; then
        why="$why; on the risky list"
      fi
      # a real service is started by the init system; a listener left in a login
      # session or at the top of the tree was started by hand
      case "$INIT" in
        none) ;;
        systemd) case "$unit" in *.service) ;; *) why="$why; not started by any service (unit=$unit)" ;; esac ;;
        *) [ "$unit" != "-" ] || why="$why; not started by any init script" ;;
      esac
      if dual_use "$comm" || dual_use "$(basename "$exe" 2>/dev/null)"; then
        why="$why; ${comm:-$exe} is a tool that can be used as a backdoor"
      fi
      if [ -n "$exe" ]; then
        if odd_place "$exe"; then
          why="$why; runs $exe"
        else
          packaged "$exe"; own=$?
          [ "$own" -eq 1 ] && why="$why; $exe belongs to no package"
          base="$(basename "$exe" | cut -c1-15)"
          # a renamed process is only interesting if its file is not a known one
          [ "$base" = "$comm" ] || [ "$own" -eq 0 ] || why="$why; named '$comm' but file is $exe"
        fi
      fi

      if [ -n "$why" ]; then
        warn "$proto $addrport $where pid=$pid ${comm:-?} user=${owner:-?} unit=$unit: ${why#; }"
      elif [ "$where" = EXPOSED ]; then
        EXPECTED="$EXPECTED $addrport/$proto(${comm:-?})"
      fi
    done <"$D/listen"
    [ "$NHIDDEN" -eq 0 ] || warn "$NHIDDEN listeners have no visible owner (not root): run as root to see them"
    [ -z "$EXPECTED" ] || info "packaged programs listening on the network:$EXPECTED"
  fi

  # ---- what starts by itself, by init system ----
  header "Unusual startup entries ($INIT)"
  : >"$D/names"
  case "$INIT" in
    systemd)
      systemctl list-unit-files 2>/dev/null </dev/null | awk '$2 == "enabled" && $1 ~ /\.(service|socket|timer)$/ { print $1 }' >>"$D/names"
      systemctl list-units --type=service --state=running 2>/dev/null </dev/null | awk '$1 ~ /\.service$/ { print $1 }' >>"$D/names"
      ;;
    sysv)
      [ -n "$RCD" ] && ls "$RCD" 2>/dev/null | sed -n 's/^S[0-9][0-9]//p' >>"$D/names"
      ;;
    upstart)
      ls /etc/init 2>/dev/null | sed -n 's/\.conf$//p' >>"$D/names"
      [ -n "$RCD" ] && ls "$RCD" 2>/dev/null | sed -n 's/^S[0-9][0-9]//p' >>"$D/names"
      ;;
    openrc)
      rc-update show 2>/dev/null </dev/null | awk '{ print $1 }' >>"$D/names"
      ;;
  esac
  sort -u "$D/names" >"$D/names.u"

  if [ "$INIT" = systemd ] && [ -s "$D/names.u" ]; then
    # one systemctl call for all units; blocks are separated by a blank line
    systemctl show -p Id -p FragmentPath -p DropInPaths -p ExecStart $(cat "$D/names.u") </dev/null 2>/dev/null | awk '
      /^Id=/ { id = substr($0, 4) }
      /^FragmentPath=/ { fp = substr($0, 14) }
      /^DropInPaths=/ { dp = substr($0, 13) }
      /^ExecStart=\{ path=/ { ex = substr($0, 20); sub(/ .*/, "", ex) }
      /^$/ { if (id != "") print id "|" fp "|" ex "|" dp; id = ""; fp = ""; dp = ""; ex = "" }
      END { if (id != "") print id "|" fp "|" ex "|" dp }' >"$D/units"
    while IFS='|' read -r id fp ex dp; do
      flag_unit "$id" "$fp" "$ex" "$dp"
    done <"$D/units"
  else
    while read -r name; do
      [ -n "$name" ] || continue
      f=""
      for c in "/etc/init.d/$name" "/etc/init/$name.conf"; do
        if [ -f "$c" ]; then f="$c"; break; fi
      done
      flag_unit "$name" "$f" "" ""
    done <"$D/names.u"
  fi

  # Super-servers start programs on demand, so every live entry is worth a look
  for f in /etc/xinetd.d/*; do
    [ -f "$f" ] || continue
    if ! grep -E '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$f" </dev/null >/dev/null 2>&1; then
      warn "xinetd serves $(basename "$f") on demand ($f)"
      RISKY="$RISKY $(basename "$f")"
      NODD=$((NODD + 1))
    fi
  done
  if [ -f /etc/inetd.conf ]; then
    for n in $(awk '$1 !~ /^#/ && NF > 0 { print $1 }' /etc/inetd.conf </dev/null); do
      warn "inetd serves $n on demand (/etc/inetd.conf)"
      RISKY="$RISKY $n"
      NODD=$((NODD + 1))
    done
  fi
  [ "$NODD" -gt 0 ] || ok "every startup entry is packaged and in a normal place"

  if [ -n "$RISKY" ]; then
    RISKY="$(echo "$RISKY" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    header "Next step"
    info "paste into DENY in services/disable-services after you have checked them:"
    echo "DENY=\"$RISKY\""
  fi

  header "Summary"
  echo "SUMMARY: init=$INIT listeners=$NLISTEN units=$NUNITS unusual=$NODD warnings=$WARNS"
}

( main )
