#!/bin/sh
# status:  draft
# risk:    none        # none | lockout | service-impact
# os:      any linux
# tested:  proxmox VM with coordinate
#
# PERSISTENCE DISCOVERY: print everything on the persistence checklist
# (persistence.md, discovery parts only) so a person can inspect it by hand.
# It only looks: nothing is changed, deleted or disabled.
#
# The slow whole-disk scans (find, package verification) start in the
# background first and are collected in section 7, so the quick sections print
# while they run. Each scan is cut off after SCAN_LIMIT seconds when the
# `timeout` tool exists, so a very big disk gives partial results.
#
# Sections: 1 scheduled tasks, 2 sudoers, 3 PAM, 4 startup/init, 5 RC scripts,
# 6 environment variables, 7 unusual files, 8 drives, 9 processes,
# 10 services/sockets, 11 kernel, 12 dynamic linker.
#
# NOTE: For now #7 UNUSUAL FILES has been disabled as the find commands cause
# timeout.

ORIG_PATH="$PATH"
export ORIG_PATH
PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
export PATH
LC_ALL=C
export LC_ALL

RECENT_DAYS=7     # what "recently modified" means
MAXLINES=60       # longest list printed for one item
SCAN_LIMIT=90     # seconds a background scan may run

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

COUNT=0           # things printed for review
BGPIDS=""         # background scans still running
TMP=""
OUT=""            # scratch file reused by the quick checks
HOMEF=""          # list of "user home" lines
RCF=""            # list of shell startup files that exist
ROOTS="/"         # every real file system, for the find scans
PKG=""            # package tool: dpkg, rpm, apk or pacman
ODD_WHY=""

cleanup() {
  for cl_p in $BGPIDS; do
    kill "$cl_p" 2>/dev/null
  done
  if [ -n "$TMP" ] && [ -d "$TMP" ]; then
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# ---- output helpers --------------------------------------------------------
banner() {
  printf '\n\n############################################################\n'
  printf '# %s\n' "$*"
  printf '############################################################\n'
  log "#### $*"
}
sub() { printf '\n-- %s --\n' "$*"; log "-- $*"; }
line() { printf '    %s\n' "$*"; }
indent() { sed 's/^/    /'; }

# print a result file indented, capped, and count it
emit_file() {
  ef_max="${2:-$MAXLINES}"
  if [ ! -s "$1" ]; then
    line "(none)"
    return 0
  fi
  ef_n="$(wc -l <"$1" | tr -d ' ')"
  head -n "$ef_max" "$1" | indent
  COUNT=$((COUNT + ef_n))
  if [ "$ef_n" -gt "$ef_max" ]; then
    line "... $((ef_n - ef_max)) more lines not shown"
  fi
}

# one warning per line of a result file
warn_file() {
  if [ ! -s "$1" ]; then
    line "(none)"
    return 0
  fi
  wf_n=0
  while IFS= read -r wf_l; do
    wf_n=$((wf_n + 1))
    if [ "$wf_n" -le "$MAXLINES" ]; then
      warn "$wf_l"
    fi
  done <"$1"
  COUNT=$((COUNT + wf_n))
  if [ "$wf_n" -gt "$MAXLINES" ]; then
    WARNS=$((WARNS + wf_n - MAXLINES))
    line "... $((wf_n - MAXLINES)) more not shown"
  fi
}

# print a config file without comments and blank lines (keeps #include lines)
show_conf() {
  if [ ! -e "$1" ]; then
    info "$1 is not present"
    return 0
  fi
  if [ ! -r "$1" ]; then
    warn "$1 is not readable (run as root)"
    return 0
  fi
  printf '  >> %s\n' "$1"
  sc_out="$(sed -n '/^[[:space:]]*#include/p; /^[[:space:]]*#/d; /^[[:space:]]*$/d; p' "$1" 2>/dev/null)"
  if [ -z "$sc_out" ]; then
    line "(no active lines)"
  else
    printf '%s\n' "$sc_out" | head -n 200 | indent
  fi
  COUNT=$((COUNT + 1))
}

# ls -l of a directory, hidden files included
list_dir() {
  if [ ! -d "$1" ]; then
    return 0
  fi
  printf '  >> %s\n' "$1"
  if [ ! -r "$1" ]; then
    line "(not readable)"
    return 0
  fi
  ld_out="$(ls -lA "$1" 2>/dev/null)"
  ld_out="$(printf '%s\n' "$ld_out" | sed '/^total/d')"
  if [ -z "$ld_out" ]; then
    line "(empty)"
  else
    printf '%s\n' "$ld_out" | indent
    COUNT=$((COUNT + 1))
  fi
}

# grep_hits LABEL PATTERN FILE...: print non-comment matches, warn once
grep_hits() {
  gh_label="$1"
  gh_pat="$2"
  shift 2
  gh_res="$(grep -n -E -e "$gh_pat" "$@" /dev/null 2>/dev/null | grep -v '^[^:]*:[0-9]*:[[:space:]]*#')"
  if [ -n "$gh_res" ]; then
    warn "$gh_label"
    printf '%s\n' "$gh_res" | head -n "$MAXLINES" | indent
    COUNT=$((COUNT + 1))
  else
    info "none: $gh_label"
  fi
}

# print the target of a symlink (readlink is not everywhere)
rl() {
  if have readlink; then
    readlink "$1" 2>/dev/null
  else
    rl_out="$(ls -l "$1" 2>/dev/null)"
    case "$rl_out" in
      *' -> '*) printf '%s\n' "${rl_out##* -> }" ;;
    esac
  fi
}

# run a command with a time limit when `timeout` exists
limited() {
  if have timeout; then
    timeout "$SCAN_LIMIT" "$@"
  else
    "$@"
  fi
}

# find_in "DIR DIR ..." EXPRESSION...: limited find over a whitespace-separated
# list of directories. Splitting the list is the point, so it happens here and
# nowhere else (globbing is off so a path is never expanded).
find_in() {
  fi_dirs="$1"
  shift
  set -f
  # shellcheck disable=SC2086
  set -- $fi_dirs "$@"
  set +f
  limited find "$@"
}

# recent FILE DAYS: true when FILE changed in the last DAYS days
recent() {
  [ -n "$(find "$1" -mtime -"$2" -print 2>/dev/null)" ]
}

# print the arguments that are directories: canonical path, no duplicates,
# nothing that is inside another one in the list (merged /usr safe)
real_dirs() {
  rd_all=" "
  for rd in "$@"; do
    [ -d "$rd" ] || continue
    rd_c="$(cd "$rd" 2>/dev/null && pwd -P)"
    [ -n "$rd_c" ] || continue
    rd_all="$rd_all$rd_c "
  done
  for rd in $rd_all; do
    rd_keep=1
    for rd2 in $rd_all; do
      if [ "$rd2" != "$rd" ]; then
        case "$rd" in
          "$rd2"/*) rd_keep=0 ;;
        esac
      fi
    done
    if [ "$rd_keep" = 1 ]; then
      printf '%s\n' "$rd"
    fi
  done | sort -u
}

# ---- package ownership -----------------------------------------------------
detect_pkg() {
  if have dpkg; then
    PKG=dpkg
  elif have rpm; then
    PKG=rpm
  elif have apk; then
    PKG=apk
  elif have pacman; then
    PKG=pacman
  else
    warn "no package manager found (dpkg, rpm, apk, pacman): ownership and integrity checks are skipped"
  fi
}

# exit status 0 = owned by a package, 1 = not owned, anything else = unknown
pkg_owned() {
  case "$PKG" in
    dpkg)
      dpkg -S "$1" >/dev/null 2>&1 </dev/null && return 0
      # merged /usr: a package may list /bin/x while the file is seen as /usr/bin/x
      case "$1" in
        /usr/*) po_alt="${1#/usr}" ;;
        *) po_alt="/usr$1" ;;
      esac
      dpkg -S "$po_alt" >/dev/null 2>&1 </dev/null
      ;;
    rpm) rpm -qf "$1" >/dev/null 2>&1 </dev/null ;;
    apk) apk info -W "$1" >/dev/null 2>&1 </dev/null ;;
    pacman) pacman -Qo "$1" >/dev/null 2>&1 </dev/null ;;
    *) return 2 ;;
  esac
}

# warn for each argument that is a file no package owns
flag_unowned() {
  [ -n "$PKG" ] || return 0
  for fu in "$@"; do
    [ -f "$fu" ] || continue
    pkg_owned "$fu"
    if [ $? = 1 ]; then
      warn "not owned by any package: $fu"
    fi
  done
}

# true when FILE is unowned or recently changed; the reason is in ODD_WHY
odd_file() {
  ODD_WHY=""
  if recent "$1" "$RECENT_DAYS"; then
    ODD_WHY="modified in the last $RECENT_DAYS days"
    return 0
  fi
  if [ -n "$PKG" ]; then
    pkg_owned "$1"
    if [ $? = 1 ]; then
      ODD_WHY="not owned by any package"
      return 0
    fi
  fi
  return 1
}

# list a directory, then print the files in it that are unowned or recent
review_dir() {
  list_dir "$1"
  for rv in "$1"/*; do
    [ -f "$rv" ] || continue
    if odd_file "$rv"; then
      warn "$rv: $ODD_WHY"
      show_conf "$rv"
    fi
  done
}

# list files not owned by root or writable by group/other under the arguments
perm_anomalies() {
  for pa in "$@"; do
    [ -e "$pa" ] || continue
    find "$pa" -xdev ! -type l \( ! -user root -o -perm -0002 -o -perm -0020 \) -exec ls -ld {} + 2>/dev/null
  done
}

# ---- /proc helpers ---------------------------------------------------------
# pid_field PID KEY: first value of KEY: in /proc/PID/status
pid_field() {
  while read -r pf_k pf_v _; do
    if [ "$pf_k" = "$2:" ]; then
      printf '%s\n' "$pf_v"
      return 0
    fi
  done 2>/dev/null <"/proc/$1/status"
}
pid_cmd() { tr '\0\n' '  ' 2>/dev/null <"/proc/$1/cmdline" | cut -c1-200; }
pid_name() {
  if [ -r "/proc/$1/comm" ]; then
    cat "/proc/$1/comm" 2>/dev/null
  else
    pid_cmd "$1"
  fi
}

# ---- setup -----------------------------------------------------------------
make_tmp() {
  TMP="$(mktemp -d 2>/dev/null)"
  if [ -z "$TMP" ] || [ ! -d "$TMP" ]; then
    TMP="/tmp/ccdc-persist.$$"
    mkdir "$TMP" 2>/dev/null || TMP=""
  fi
  if [ -n "$TMP" ]; then
    chmod 700 "$TMP" 2>/dev/null
    OUT="$TMP/out"
    HOMEF="$TMP/homes"
    RCF="$TMP/rcfiles"
  fi
}

# every real file system, so find can use -xdev and skip /proc, /sys, network
get_roots() {
  ROOTS="/"
  if [ ! -r /proc/mounts ]; then
    return 0
  fi
  gr_list="$(awk '$3 ~ /^(ext[234]|xfs|btrfs|jfs|reiserfs|f2fs|vfat|ntfs|ntfs3|exfat|zfs|tmpfs)$/ { print $2 }' /proc/mounts 2>/dev/null)"
  for gr_m in $gr_list; do
    case "$gr_m" in
      /|/proc*|/sys*|/dev|/dev/pts*|/dev/hugepages*|/dev/mqueue*|*\\*) continue ;;
    esac
    ROOTS="$ROOTS $gr_m"
  done
}

# accounts with a usable shell and an existing home directory
build_homes() {
  while IFS=: read -r bh_u _ _ _ _ bh_dir bh_sh; do
    [ -d "$bh_dir" ] || continue
    [ "$bh_dir" = "/" ] && continue
    case "$bh_sh" in
      */nologin|*/false|*/sync|*/shutdown|*/halt) continue ;;
    esac
    printf '%s %s\n' "$bh_u" "$bh_dir"
  done 2>/dev/null </etc/passwd | sort -u >"$HOMEF"
}

# shell startup files that exist: system-wide and in every home
build_rclist() {
  : >"$RCF"
  for br in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/bash.bash_logout /etc/csh.cshrc /etc/csh.login /etc/zsh/zshrc /etc/zsh/zshenv /etc/zsh/zprofile /etc/zsh/zlogin /etc/zshrc /etc/zshenv /etc/zprofile /etc/ksh.kshrc /etc/profile.local /etc/ssh/sshrc /etc/rc.local /etc/rc.d/rc.local /etc/profile.d/*; do
    [ -f "$br" ] && printf '%s\n' "$br" >>"$RCF"
  done
  while read -r _ br_h; do
    for br in .bashrc .bash_profile .bash_login .profile .bash_logout .zshrc .zshenv .zprofile .zlogin .zlogout .kshrc .cshrc .tcshrc .login .logout .xprofile .xinitrc .xsession .xsessionrc .Xclients .pam_environment .ssh/rc .ssh/environment .config/fish/config.fish; do
      [ -f "$br_h/$br" ] && printf '%s\n' "$br_h/$br" >>"$RCF"
    done
  done <"$HOMEF"
}

# grep_rc PATTERN: non-comment lines of every startup file that match
grep_rc() {
  [ -s "$RCF" ] || return 0
  while IFS= read -r gr_f; do
    grep -n -E -e "$1" "$gr_f" /dev/null 2>/dev/null | grep -v '^[^:]*:[0-9]*:[[:space:]]*#'
  done <"$RCF"
}

# ---- background scans (each writes to $TMP/<function name>) ---------------
bg() {
  "$1" >"$TMP/$1" 2>/dev/null </dev/null &
  BGPIDS="$BGPIDS $!"
}

# libraries: standard directories plus everything ld.so.conf names
ld_conf_dirs() {
  for lc_f in /etc/ld.so.conf /etc/ld.so.conf.d/*.conf; do
    [ -f "$lc_f" ] || continue
    grep '^[[:space:]]*/' "$lc_f" 2>/dev/null
  done | sed 's/^[[:space:]]*//' | sort -u
}
lib_dirs() {
  set -- /lib /lib32 /lib64 /libx32 /usr/lib /usr/lib32 /usr/lib64 /usr/libx32 /usr/local/lib /usr/local/lib64
  while IFS= read -r ld_d; do
    if [ -n "$ld_d" ]; then
      set -- "$@" "$ld_d"
    fi
  done <<EOF
$(ld_conf_dirs)
EOF
  real_dirs "$@"
}

scan_suid() {
  find_in "$ROOTS" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print
}
scan_ww_files() {
  find_in "$ROOTS" -xdev -type f -perm -0002 -exec ls -ld {} +
}
scan_ww_dirs() {
  find_in "$ROOTS" -xdev -type d -perm -0002 -exec ls -ld {} +
}
scan_sticky() {
  find_in "$ROOTS" -xdev \( \( -type d -perm -0002 ! -perm -1000 \) -o \( ! -type d -perm -1000 \) \) -exec ls -ld {} +
}
scan_unowned() {
  find_in "$ROOTS" -xdev \( -nouser -o -nogroup \) -exec ls -ldn {} +
}
scan_caps() {
  find_in "$ROOTS" -xdev -type f -exec getcap {} +
}
scan_recent_exec() {
  re_dirs="$(real_dirs /bin /sbin /lib /lib32 /lib64 /usr /opt /srv /root /home)"
  find_in "$re_dirs" -xdev -type f -perm -0100 -mtime -"$RECENT_DAYS" -exec ls -ld {} + | sort -u
}
scan_recent_conf() {
  rc_dirs="$(real_dirs /etc /usr/local/etc /var/spool/cron /var/spool/at)"
  find_in "$rc_dirs" -xdev -type f -mtime -"$RECENT_DAYS" -exec ls -ld {} + | sort -u
}
# executables inside world-writable directories (and /run)
scan_wwexec() {
  {
    find_in "$ROOTS" -xdev -type d -perm -0002 -print | head -n 200 | while IFS= read -r we_d; do
      limited find "$we_d" -xdev -type f \( -perm -0100 -o -perm -0010 -o -perm -0001 \) -exec ls -ld {} +
    done
    limited find /run -xdev -type f \( -perm -0100 -o -perm -0010 -o -perm -0001 \) -exec ls -ld {} +
  } | sort -u
}
scan_symlinks() {
  find_in "$ROOTS" -xdev -type l ! -path '/home/*' ! -path '/root/*' -exec ls -ld {} + | grep -E -e ' -> (/|(\.\./)+)(tmp|var/tmp|dev/shm|home|root|run/user|mnt|media)(/|$)'
  limited find /tmp /var/tmp /dev/shm -xdev -type l -exec ls -ld {} +
}
scan_libs_recent() {
  sl_dirs="$(lib_dirs)"
  find_in "$sl_dirs" -xdev -type f \( -name '*.so' -o -name '*.so.*' \) -mtime -"$RECENT_DAYS" -exec ls -ld {} + | sort -u
}
scan_libs_anomaly() {
  sa_dirs="$(lib_dirs)"
  find_in "$sa_dirs" -xdev ! -type l \( ! -user root -o -perm -0002 -o -perm -0020 \) -exec ls -ld {} + | sort -u
}
scan_pkgverify() {
  if have dpkg; then
    limited dpkg --verify | grep -v ' c /'
  elif have rpm; then
    limited rpm -Va | grep -v ' c /'
  elif have pacman; then
    limited pacman -Qkk | grep -v ' 0 altered files' | grep -v '^backup file'
  elif have apk; then
    limited apk audit --system
  fi
}
# executables in the system bin directories that no package owns
scan_unowned_bins() {
  ub_dirs="$(real_dirs /bin /sbin /usr/bin /usr/sbin)"
  if have dpkg; then
    # dpkg -S names the misses on stderr; ask again with the merged-/usr alias
    find_in "$ub_dirs" -xdev -type f -perm -0100 -print | xargs dpkg -S 2>&1 >/dev/null | grep 'no path found' | sed 's/.*pattern //' | while IFS= read -r ub_f; do
      pkg_owned "$ub_f"
      if [ $? = 1 ]; then
        printf '%s\n' "$ub_f"
      fi
    done
  elif have rpm; then
    find_in "$ub_dirs" -xdev -type f -perm -0100 -print | xargs rpm -qf 2>/dev/null | grep 'not owned by any package' | sed 's/^file //; s/ is not owned.*//'
  fi
}

start_scans() {
  bg scan_suid
  bg scan_ww_files
  bg scan_ww_dirs
  bg scan_sticky
  bg scan_unowned
  bg scan_recent_exec
  bg scan_recent_conf
  bg scan_wwexec
  bg scan_symlinks
  bg scan_libs_recent
  bg scan_libs_anomaly
  bg scan_pkgverify
  bg scan_unowned_bins
  if have getcap; then
    bg scan_caps
  fi
}

# ============================================================================
# 4. Startup and init scripts
# ============================================================================
show_desktop_dir() {
  [ -d "$1" ] || return 0
  for sd in "$1"/*.desktop; do
    [ -f "$sd" ] || continue
    printf '  >> %s\n' "$sd"
    grep -E '^(Name|Exec|TryExec|Hidden|X-GNOME-Autostart-enabled)=' "$sd" 2>/dev/null | indent
    COUNT=$((COUNT + 1))
  done
}

sec_startup() {
  banner "4. Startup and init scripts"

  sub "XDG autostart entries"
  show_desktop_dir /etc/xdg/autostart
  flag_unowned /etc/xdg/autostart/*.desktop
  while read -r _u h; do
    show_desktop_dir "$h/.config/autostart"
  done <"$HOMEF"

  sub "MOTD scripts (files that are unowned or recent are printed)"
  show_conf /etc/motd
  review_dir /etc/update-motd.d
  review_dir /etc/motd.d

  sub "Startup services: systemd units that are enabled"
  if have systemctl && systemctl list-unit-files --state=enabled --no-pager >"$OUT" 2>/dev/null && [ -s "$OUT" ]; then
    emit_file "$OUT" 200
  else
    info "systemctl not usable here: listing the enable links under /etc/systemd/system instead"
    find /etc/systemd/system/*.wants/ ! -type d -exec ls -ld {} + 2>/dev/null | indent
  fi
  line "-- user-level units and lingering users --"
  while read -r _u h; do
    list_dir "$h/.config/systemd/user"
    list_dir "$h/.config/systemd/user/default.target.wants"
  done <"$HOMEF"
  list_dir /var/lib/systemd/linger

  sub "Startup services: other init systems"
  show_conf /etc/inittab
  show_conf /etc/rc.local
  show_conf /etc/rc.d/rc.local
  if have chkconfig; then
    chkconfig --list 2>/dev/null </dev/null | indent
  fi
  if have rc-update; then
    rc-update show 2>/dev/null </dev/null | indent
  fi
  line "-- SysV start links (S*) in runlevels 2-5 --"
  for sv_d in /etc/rc[2-5].d /etc/rc.d/rc[2-5].d; do
    for sv_f in "$sv_d"/S*; do
      if [ -e "$sv_f" ] || [ -L "$sv_f" ]; then
        printf '%s\n' "${sv_f##*/}"
      fi
    done
  done | sort -u | indent
  list_dir /etc/local.d
  list_dir /etc/runit/runsvdir/default
  list_dir /etc/service
  list_dir /var/service

  sub "Init script names"
  for d in /etc/init.d /etc/rc.d/init.d /etc/init /etc/sv; do
    if [ -d "$d" ]; then
      printf '  >> %s\n' "$d"
      for in_f in "$d"/*; do
        if [ -e "$in_f" ] || [ -L "$in_f" ]; then
          printf '%s\n' "${in_f##*/}"
        fi
      done | indent
      flag_unowned "$d"/*
    fi
  done
}
# ---- runner for section 4 ------------------------------------------------
main() {
  check_root
  make_tmp
  if [ -z "$TMP" ]; then
    warn "cannot create a temporary directory: nothing was checked"
    return 0
  fi
  detect_pkg
  get_roots
  build_homes
  build_rclist

  sec_startup

}

main

# ---- report ---------------------------------------------------------------
header "Summary"
echo "SUMMARY: items=$COUNT warnings=$WARNS"
