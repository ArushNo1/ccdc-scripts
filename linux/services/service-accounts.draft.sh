#!/bin/sh
# status:  draft
# risk:    none
# os:      any linux
# tested:  never
#
# For every running service: which account it runs as, what that account could
# do if the service is taken over, and who besides root can change what it
# runs. Changes nothing. Services are found from the system, not by name: every
# process left under PID 1 with no terminal, the workers in its session, and
# every listening socket in /proc. Warns on a network listener that runs only
# as root, a service run by a person's account or by a uid with no account, a
# service account that can log in (shell plus password or key, empty password,
# or a key with no shell: ssh -N tunnels still work), a root-like group or a
# sudoers rule, a second uid 0, and a program, unit, init script or file named
# on the command line that a non-root user or group can write. System accounts
# that run nothing get the same account checks. Not covered here: which
# accounts may exist, people's accounts and default passwords
# (first15/default-creds), package versions.
# Rules (CLAUDE.md): strict POSIX sh, no options, warn instead of requiring
# root, cleanup trap, grouped report plus a SUMMARY line.

# shellcheck disable=SC2012,SC2013,SC2015  # ls -n is the portable way to read owner and mode

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

# ---- edit these before a run ------------------------------------------------
# Accounts the scoring engine logs in with. Their logins are reported as a note,
# not a warning, so nobody locks them. Names, space separated.
SCORING_USERS=""

# ---- what is listening, from /proc (same as in services/audit-services) -----
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

# odd_place FILE : is it somewhere a service has no business running from
odd_place() {
  case "$1" in
    *"(deleted)"|/tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*|/run/user/*) return 0 ;;
  esac
  return 1
}

# root_ok NAME : programs that must start as root by design (they drop rights
# per connection or need root for their job). Only softens the "runs only as
# root" warning to a note; every other check still applies.
root_ok() {
  case "$1" in
    sshd|sshd-session|dropbear|inetd|xinetd|smbd|nmbd|winbindd|samba|krb5kdc|kadmind|vsftpd|master|sendmail*|dhclient|dhcpcd|NetworkManager|systemd*|dockerd|containerd|rpcbind|rpc.*|cupsd|rsyslogd|syslog-ng) return 0 ;;
  esac
  return 1
}

# priv_group NAME : groups that are root, or one step from it
priv_group() {
  case "$1" in
    root|sudo|wheel|admin|docker|lxd|disk|shadow|kmem) return 0 ;;
  esac
  return 1
}

# uid_name UID / gid_name GID : the name, or uidN / gidN when there is none
uid_name() {
  n="$(awk -F: -v u="$1" '$3 == u { print $1; exit }' "$D/passwd")"
  [ -n "$n" ] || n="$(getent passwd "$1" 2>/dev/null </dev/null | cut -d: -f1)"
  echo "${n:-uid$1}"
}
gid_name() {
  n="$(awk -F: -v g="$1" '$3 == g { print $1; exit }' "$D/group")"
  [ -n "$n" ] || n="$(getent group "$1" 2>/dev/null </dev/null | cut -d: -f1)"
  echo "${n:-gid$1}"
}

# writers FILE : who besides root can change FILE, as "user:NAME group:NAME
# everyone", or nothing. A sticky directory (like /tmp) only lets owners
# replace their own files, so "everyone" does not count there.
# shortcut: mode bits only, ACLs are not read; check getfacl by hand on a hit.
writers() {
  l="$(ls -ldLn -- "$1" 2>/dev/null | awk '{ print $1, $3, $4 }')"
  [ -n "$l" ] || return 0
  m="${l%% *}"
  rest="${l#* }"
  ou="${rest%% *}"
  og="${rest#* }"
  w=""
  case "$m" in ??w*) [ "$ou" != 0 ] && w="user:$(uid_name "$ou")" ;; esac
  case "$m" in ?????w*) [ "$og" != 0 ] && w="$w group:$(gid_name "$og")" ;; esac
  case "$m" in
    d????????[tT]*) ;;
    ????????w*) w="$w everyone" ;;
  esac
  echo "${w# }"
}

# acct NAME : what this account could do for someone who took over a service
# running as it. Prints one line per finding.
acct() {
  line="$(awk -F: -v n="$1" '$1 == n { print; exit }' "$D/passwd")"
  [ -n "$line" ] || return 0
  echo "$1" >>"$D/done"
  NACCT=$((NACCT + 1))
  oldifs="$IFS"
  IFS=:
  set -f
  # shellcheck disable=SC2086  # splitting on : is the point
  set -- $line
  set +f
  IFS="$oldifs"
  an="$1"; apw="$2"; au="$3"; ah="$6"; ash="$7"

  [ "$au" = 0 ] && [ "$an" != root ] && warn "$an has uid 0: it is root under another name"

  # An empty shell field means /bin/sh
  login=yes
  case "$ash" in */nologin|*/false|*/true|*/sync|*/shutdown|*/halt) login=no ;; esac

  # The password field: shadow if we can read it, else what passwd itself holds
  h=""
  [ "$SHADOW" = yes ] && h="$(awk -F: -v n="$an" '$1 == n { print "=" $2; exit }' "$D/shadow")"
  [ -n "$h" ] || h="=$apw"
  case "$h" in
    =) pw=empty ;;
    =x) if [ "$SHADOW" = yes ]; then pw=locked; else pw=unknown; fi ;;
    "=!"*|"=*"*) pw=locked ;;
    *) pw="set" ;;
  esac

  keyf=""
  for k in "$ah/.ssh/authorized_keys" "$ah/.ssh/authorized_keys2"; do
    [ -s "$k" ] && keyf="$k"
  done

  scoring=no
  case " $SCORING_USERS " in *" $an "*) scoring=yes ;; esac

  if [ "$pw" = empty ]; then
    warn "$an has an empty password: anyone can log in or su to it"
  elif [ "$login" = yes ] && { [ "$pw" = set ] || [ -n "$keyf" ]; }; then
    how="shell ${ash:-/bin/sh}"
    [ "$pw" = set ] && how="$how, a password"
    [ -n "$keyf" ] && how="$how, keys in $keyf"
    if [ "$scoring" = yes ]; then
      info "$an can log in ($how): scoring account, leave it"
    else
      warn "$an can log in ($how)"
    fi
  elif [ -n "$keyf" ]; then
    warn "$an has keys in $keyf: with no shell, ssh -N still opens tunnels"
  elif [ "$login" = yes ] && [ "$pw" = unknown ]; then
    info "$an has shell ${ash:-/bin/sh}, password not readable (not root)"
  elif [ "$login" = yes ]; then
    info "$an has shell ${ash:-/bin/sh} but no password or key: only su/sudo reach it"
  fi

  groups=" $(id -Gn "$an" 2>/dev/null </dev/null) "
  for g in $groups; do
    priv_group "$g" && warn "$an is in group $g, which is root or one step from it"
  done

  # sudoers rules whose user list names this account, one of its %groups or ALL
  awk -v n="$an" -v g="$groups" '
    {
      rule = $0; sub(/^[^:]*: */, "", rule); sub(/^[ \t]+/, "", rule)
      split(rule, w, /[ \t]+/)
      who = w[1]
      if (who == "User_Alias") { who = rule; sub(/^[^=]*=/, "", who) }
      m = split(who, a, /[ ,\t]+/)
      for (i = 1; i <= m; i++) {
        if (a[i] == n || a[i] == "ALL") { print; next }
        if (substr(a[i], 1, 1) == "%" && index(g, " " substr(a[i], 2) " ")) { print; next }
      }
    }' "$D/sudoers" >"$D/sudo.hit"
  while IFS= read -r l; do
    warn "$an has sudo: $l"
  done <"$D/sudo.hit"
}

# check_paths KIND FILE : warn for every path listed in FILE, or its directory,
# that someone other than root can change. KIND "arg" (the program or a file
# named on its command line) only gets a note when the one writer is the
# service's own non-root account: that lets an intruder stay, not climb. Unit
# files and init scripts are read by root, so any writer there is a warning.
check_paths() {
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    for x in "$f" "$(dirname "$f")"; do
      grep -Fx -- "$x" "$D/seen" >/dev/null 2>&1 && continue
      echo "$x" >>"$D/seen"
      w="$(writers "$x")"
      [ -n "$w" ] || continue
      if [ "$1" = arg ] && [ -n "$SELF" ] && [ "$w" = "$SELF" ]; then
        info "$x can be changed by its own account ($w): an intruder can stay, not climb"
      else
        warn "$x can be changed by $w, and this service runs as ${RUNAS#, }"
      fi
    done
  done <"$2"
}

# report_service KEY : everything about one service (a unit, or a program name)
report_service() {
  key="$1"
  NSVC=$((NSVC + 1))
  before=$WARNS
  awk -v k="$key" '$1 == k { print $2, $3, $4 }' "$D/map" >"$D/one" # pid uid comm

  ports="$(awk 'NR == FNR { p[$1] = 1; next } ($3 in p) { print $2 "/" $1 }' "$D/one" "$D/listen" | sort -u | tr '\n' ' ')"
  exposed="$(awk 'NR == FNR { p[$1] = 1; next } ($3 in p) && $2 !~ /^127\./ && $2 !~ /^::1:/ { print $2 }' "$D/one" "$D/listen")"

  awk '$2 != "?" { n[$2]++ } END { for (u in n) print u, n[u] }' "$D/one" | sort -n >"$D/uids"
  RUNAS=""
  desc=""
  nonroot=""
  while read -r u n; do
    nm="$(uid_name "$u")"
    RUNAS="$RUNAS, $nm"
    desc="$desc, $nm ($n)"
    [ "$u" = 0 ] || nonroot="$nonroot $nm"
  done <"$D/uids"
  # one non-root account: files it owns alone are "its own"
  SELF=""
  case "$nonroot" in " "*" "*) ;; " "?*) SELF="user:${nonroot# }" ;; esac

  header "$key"
  info "runs as ${desc#, }${ports:+; listens on $ports}"

  # Only root, reachable from the network: one bug in it is a root shell
  if [ -n "$exposed" ] && [ -z "$nonroot" ]; then
    why=""
    for c in $(awk '{ print $3 }' "$D/one" | sort -u); do
      root_ok "$c" && why="$c"
    done
    lp="$(awk 'NR == FNR { p[$1] = 1; next } ($3 in p) { print $3; exit }' "$D/one" "$D/listen")"
    exe="$(readlink "/proc/$lp/exe" 2>/dev/null </dev/null)"
    if [ -n "$why" ] && ! odd_place "$exe"; then
      info "every process runs as root, which is how $why works"
    else
      warn "listens on the network and every process runs as root: a bug in it gives root"
    fi
  fi

  while read -r u n; do
    nm="$(uid_name "$u")"
    case "$nm" in
      uid*) warn "runs as uid $u, which has no account (deleted while it ran? a container?)" ;;
    esac
    if [ "$u" -ge "$UID_MIN" ] && [ "$u" -lt 60000 ]; then
      warn "runs as $nm, a person's account (uid $u): taking it over gives that person's files, keys and sudo"
    fi
    [ "$u" = 0 ] && continue
    if grep -Fx -- "$nm" "$D/done" >/dev/null 2>&1; then
      info "account $nm: see above"
    else
      acct "$nm"
    fi
  done <"$D/uids"

  # What it runs: its unit or init script, the program, and files named on its
  # command line (scripts, configs). Whoever can change those runs code as it.
  : >"$D/run"
  : >"$D/args"
  : >"$D/seen"
  for pid in $(awk '{ print $1 }' "$D/one"); do
    readlink "/proc/$pid/exe" 2>/dev/null </dev/null >>"$D/args"
    [ -r "/proc/$pid/cmdline" ] || continue
    tr '\000' '\n' 2>/dev/null <"/proc/$pid/cmdline" |
      awk 'NR <= 20 { sub(/^[^\/=]*=/, ""); if ($0 ~ /^\//) print }' >>"$D/args"
  done
  case "$key" in
    *.service)
      if have systemctl; then
        systemctl show -p FragmentPath -p DropInPaths "$key" </dev/null 2>/dev/null |
          sed 's/^[^=]*=//' | tr ' ' '\n' | grep '^/' >>"$D/run"
      fi
      ;;
    *) [ -f "/etc/init.d/${key%\[*}" ] && echo "/etc/init.d/${key%\[*}" >>"$D/run" ;;
  esac
  sort -u "$D/run" >"$D/run.u"
  sort -u "$D/args" >"$D/args.u"
  check_paths run "$D/run.u"
  check_paths arg "$D/args.u"

  [ "$WARNS" -gt "$before" ] || ok "nothing unusual"
}

D="/tmp/ccdc-service-accounts.$$"
cleanup() {
  [ -n "$D" ] && rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

check_root
mkdir "$D" 2>/dev/null && chmod 700 "$D" || { D=""; warn "cannot make a work directory in /tmp, nothing was checked"; }

main() {
  [ -n "$D" ] || return 0
  NSVC=0
  NACCT=0
  : >"$D/done"

  UID_MIN="$(awk '$1 == "UID_MIN" { print $2 }' /etc/login.defs 2>/dev/null)"
  case "$UID_MIN" in '' | *[!0-9]*) UID_MIN=1000 ;; esac

  # getent also sees directory (SSSD/LDAP) accounts when they are enumerated
  if have getent; then
    getent passwd >"$D/passwd" 2>/dev/null </dev/null
    getent group >"$D/group" 2>/dev/null </dev/null
  fi
  [ -s "$D/passwd" ] || cat /etc/passwd >"$D/passwd" 2>/dev/null
  [ -s "$D/group" ] || cat /etc/group >"$D/group" 2>/dev/null
  SHADOW=no
  if [ -r /etc/shadow ] && cat /etc/shadow >"$D/shadow" 2>/dev/null; then SHADOW=yes; fi

  # sudoers rules, one per line as "file: rule", without comments or Defaults
  : >"$D/sudoers"
  SUDO_HIDDEN=no
  for f in /etc/sudoers /etc/sudoers.d/* /usr/local/etc/sudoers; do
    [ -f "$f" ] || continue
    if [ -r "$f" ]; then
      awk -v F="$f" '/^[ \t]*#/ || /^[ \t]*$/ || /^[ \t]*Defaults/ { next } { print F ": " $0 }' "$f" >>"$D/sudoers" 2>/dev/null
    else
      SUDO_HIDDEN=yes
    fi
  done

  if [ "$(id -u 2>/dev/null)" != 0 ]; then
    info "not root: passwords, most listener owners and other users' programs cannot be seen"
  fi
  [ "$SUDO_HIDDEN" = no ] || info "sudoers cannot be read: sudo rules are not checked"

  # Process table: "pid ppid sid tty euid". The command name in stat can hold
  # spaces and brackets, so fields are counted from its closing ") ".
  cat /proc/[0-9]*/stat 2>/dev/null | awk '{ s = $0; sub(/.*\) /, "", s); split(s, f, " "); print $1, f[2], f[4], f[5] }' >"$D/stat"
  cat /proc/[0-9]*/status 2>/dev/null | awk '/^Pid:/ { p = $2 } /^Uid:/ { print p, $3 }' >"$D/uid"
  awk 'NR == FNR { u[$1] = $2; next } { print $0, (($1 in u) ? u[$1] : "?") }' "$D/uid" "$D/stat" >"$D/procs"
  listeners_now "$D/listen"

  # Services: what runs under PID 1 with no terminal (the per-user systemd
  # manager aside, that is a desktop), plus whatever owns a listening socket.
  : >"$D/seeds"
  for pid in $(awk -v me="$$" '$2 == 1 && $4 == 0 && $1 != me { print $1 }' "$D/procs"); do
    grep '/user@' "/proc/$pid/cgroup" </dev/null >/dev/null 2>&1 || echo "$pid" >>"$D/seeds"
  done
  awk '$3 != "?" { print $3 }' "$D/listen" >>"$D/seeds"

  # Workers share the session of the daemon that started them. The sessions of
  # PID 1 and of this script are left out: in a container they hold everything,
  # so a seed there is a group of its own. "pid uid group"
  mysid="$(awk -v me="$$" '$1 == me { print $3 }' "$D/procs")"
  awk -v me="$$" -v mysid="$mysid" '
    NR == FNR { seed[$1] = 1; next }
    { sid[$1] = $3; uid[$1] = $5 }
    END {
      for (p in seed) if ((p in sid) && sid[p] != 0 && sid[p] != sid["1"] && sid[p] != mysid) keep[sid[p]] = 1
      for (p in sid) {
        if (p == "1" || p == me) continue
        if (sid[p] in keep) print p, uid[p], sid[p]
        else if (p in seed) print p, uid[p], p
      }
    }' "$D/seeds" "$D/procs" >"$D/svc"

  # Group by systemd unit, else by the program that leads the group, as
  # name[pid]. "key pid uid comm"
  : >"$D/map"
  while read -r pid u grp; do
    [ -d "/proc/$pid" ] || continue # gone mid-scan
    comm="$(tr ' ' '_' 2>/dev/null <"/proc/$pid/comm")"
    unit="$(awk -F/ '$NF ~ /\.service$/ { n = $NF } END { print n }' "/proc/$pid/cgroup" 2>/dev/null)"
    if [ -z "$unit" ]; then
      lead="$(tr ' ' '_' 2>/dev/null <"/proc/$grp/comm")"
      unit="${lead:-${comm:-pid}}[$grp]"
    fi
    echo "$unit $pid $u ${comm:-?}" >>"$D/map"
  done <"$D/svc"

  awk '{ print $1 }' "$D/map" | sort -u >"$D/keys"
  [ -s "$D/keys" ] || warn "no running service could be seen"
  while IFS= read -r key; do
    report_service "$key"
  done <"$D/keys"

  # System accounts that run nothing right now can still be started or su'd to
  header "Other system accounts"
  before=$WARNS
  n0=$NACCT
  awk -F: -v min="$UID_MIN" '$1 != "root" && ($3 < min || $3 >= 60000) { print $1 }' "$D/passwd" >"$D/sys"
  while IFS= read -r an; do
    grep -Fx -- "$an" "$D/done" >/dev/null 2>&1 || acct "$an"
  done <"$D/sys"
  [ "$WARNS" -gt "$before" ] || ok "$((NACCT - n0)) checked, nothing unusual"

  header "Summary"
  echo "SUMMARY: services=$NSVC accounts=$NACCT warnings=$WARNS"
}

( main )
