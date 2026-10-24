#!/bin/sh
# status:  draft
# risk:    none
# os:      any linux with OpenSSH
# tested:  never (container runs only, see testing/README.md)
#
# Read-only hunt for backdoors around SSH logins: the PAM stack sshd uses, PAM
# modules and OpenSSH binaries compared with the package database,
# ld.so.preload, sshrc and per-user rc files, ProxyCommand in ssh client
# configs, and what the sshd systemd unit executes.
# Changes nothing, so it is safe to run as root, and root sees more.

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

PAM_FILE="/etc/pam.d/sshd"

WORK="$(mktemp -d 2>/dev/null)" || {
  WORK="/tmp/ccdc-ssh-backdoors.$$"
  mkdir "$WORK" 2>/dev/null
}
# shellcheck disable=SC2317  # called through the trap
cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# Is there a systemd unit called $1.service? The unit list is slow, read it once.
unit_exists() {
  if [ ! -f "$WORK/units" ]; then
    systemctl list-unit-files 2>/dev/null >"$WORK/units"
  fi
  grep "^$1\.service" "$WORK/units" >/dev/null 2>&1
}

# Run a command with a time limit when timeout(1) works, plain otherwise.
# stdin is closed: coordinate feeds the script itself through stdin.
if have timeout && timeout 5 true >/dev/null 2>&1; then
  run_t() { timeout 10 "$@" </dev/null; }
else
  run_t() { "$@" </dev/null; }
fi

check_root

# ---- 1. PAM ---------------------------------------------------------------
header "PAM"

# Follow includes of the sshd PAM file: "@include x" (Debian), "auth include x" (RHEL)
: >"$WORK/pam"
todo="$PAM_FILE"
depth=0
while [ -n "$todo" ] && [ "$depth" -lt 5 ]; do
  depth=$((depth + 1))
  next=""
  for f in $todo; do
    case "$f" in
      /*) ;;
      *) f="/etc/pam.d/$f" ;;
    esac
    [ -r "$f" ] || continue
    grep -v -E '^[[:space:]]*(#|$)' "$f" | sed "s|^|$f: |" >>"$WORK/pam"
    next="$next $(grep -v -E '^[[:space:]]*#' "$f" |
      sed -n 's/^@include[[:space:]]*\([^[:space:]]*\).*$/\1/p; s/^[[:space:]]*[a-z]*[[:space:]]*\(include\|substack\)[[:space:]]*\([^[:space:]]*\).*$/\2/p' |
      tr '\n' ' ')"
  done
  todo="$next"
done

PAMLINES=0
if [ ! -s "$WORK/pam" ]; then
  info "$PAM_FILE not readable or empty (no PAM audit)"
else
  PAMLINES="$(wc -l <"$WORK/pam" | tr -d ' ')"
  ok "PAM stack read ($PAMLINES lines)"
  grep -E 'auth[[:space:]]+(sufficient|optional)[[:space:]]+pam_permit\.so' "$WORK/pam" >"$WORK/bad"
  while read -r l; do warn "any password would be accepted: $l"; done <"$WORK/bad"
  grep 'pam_exec\.so' "$WORK/pam" >"$WORK/bad"
  while read -r l; do warn "PAM runs a program at login: $l"; done <"$WORK/bad"

  # Every module named in the stack should exist and belong to a package.
  # dpkg -S with a glob scans the whole database per call (slow), so for dpkg
  # all paths are looked up in the package file lists with one grep.
  grep -o -E '[^[:space:]]+\.so' "$WORK/pam" | sort -u >"$WORK/mods"
  : >"$WORK/modpaths"
  while read -r mod; do
    path=""
    case "$mod" in
      /*) [ -f "$mod" ] && path="$mod" ;;
      *)
        for d in /lib/security /lib64/security /usr/lib/security /usr/lib64/security /lib/*/security /usr/lib/*/security; do
          [ -f "$d/$mod" ] && path="$d/$mod" && break
        done
        ;;
    esac
    if [ -z "$path" ]; then
      warn "PAM module $mod not found"
    else
      echo "$path" >>"$WORK/modpaths"
    fi
  done <"$WORK/mods"

  : >"$WORK/owners.pkg"
  if [ -d /var/lib/dpkg/info ]; then
    # /lib may be a symlink to /usr/lib: look for both spellings
    while read -r path; do
      echo "$path"
      case "$path" in
        /usr/*) echo "${path#/usr}" ;;
        *) echo "/usr$path" ;;
      esac
    done <"$WORK/modpaths" >"$WORK/pats"
    grep -F -x -f "$WORK/pats" /var/lib/dpkg/info/*.list >"$WORK/hits" 2>/dev/null
    while read -r path; do
      hit="$(grep -F -e ":$path" -e ":/usr$path" -e ":${path#/usr}" "$WORK/hits" | head -n 1)"
      if [ -n "$hit" ]; then
        pkg="${hit%%:/*}"
        pkg="${pkg##*/}"
        pkg="${pkg%.list}"
        echo "${pkg%%:*}" >>"$WORK/owners.pkg"
      else
        warn "PAM module $path is not owned by any package"
      fi
    done <"$WORK/modpaths"
  elif have rpm; then
    while read -r path; do
      owner="$(rpm -qf "$path" 2>/dev/null | head -n 1)"
      if [ -n "$owner" ]; then echo "$owner" >>"$WORK/owners.pkg"; else warn "PAM module $path is not owned by any package"; fi
    done <"$WORK/modpaths"
  fi

  # Is the content of the owning packages still what the package database says?
  if [ -s "$WORK/owners.pkg" ]; then
    sort -u "$WORK/owners.pkg" >"$WORK/owners.uniq"
    while read -r pkg; do
      if have dpkg; then
        run_t dpkg --verify "$pkg" 2>/dev/null | grep -v ' c /' >"$WORK/bad"
      else
        run_t rpm -V "$pkg" 2>/dev/null | grep -v ' c /' >"$WORK/bad"
      fi
      while read -r l; do warn "PAM package $pkg modified: $l"; done <"$WORK/bad"
    done <"$WORK/owners.uniq"
  fi
fi

# ---- 2. binaries and persistence spots -------------------------------------
header "Binaries and persistence"

if have rpm && rpm -q openssh-server >/dev/null 2>&1; then
  run_t rpm -V openssh-server openssh-clients 2>/dev/null | grep -v ' c /' >"$WORK/verify"
elif have dpkg && dpkg -s openssh-server >/dev/null 2>&1; then
  run_t dpkg --verify openssh-server openssh-client 2>/dev/null | grep -v ' c /' >"$WORK/verify"
else
  : >"$WORK/verify"
  info "No rpm/dpkg package found for OpenSSH, binaries not verified (install the package manager tool or compare by hand)"
fi
if [ -s "$WORK/verify" ]; then
  while read -r l; do warn "modified package file: $l"; done <"$WORK/verify"
else
  ok "OpenSSH package files match the package database (or could not be checked)"
fi

if [ -s /etc/ld.so.preload ] && grep -v -E '^[[:space:]]*(#|$)' /etc/ld.so.preload >/dev/null; then
  warn "/etc/ld.so.preload is not empty: $(tr '\n' ' ' </etc/ld.so.preload)"
fi

[ -e /etc/ssh/sshrc ] && warn "/etc/ssh/sshrc exists (runs at every login)"
while IFS=: read -r user _ _ _ _ home _; do
  [ -d "$home" ] || continue
  [ -e "$home/.ssh/rc" ] && warn "$home/.ssh/rc exists (user $user)"
  if [ -f "$home/.ssh/config" ] &&
    grep -i -E '^[[:space:]]*(ProxyCommand|LocalCommand|PermitLocalCommand)' "$home/.ssh/config" >/dev/null 2>&1; then
    warn "$home/.ssh/config has ProxyCommand/LocalCommand (runs when $user uses ssh)"
  fi
done </etc/passwd
for f in /etc/ssh/ssh_config /etc/ssh/ssh_config.d/*; do
  [ -f "$f" ] || continue
  if grep -i -E '^[[:space:]]*(ProxyCommand|LocalCommand|PermitLocalCommand)' "$f" >/dev/null 2>&1; then
    warn "$f has ProxyCommand/LocalCommand (runs when anyone uses ssh)"
  fi
done

if have systemctl && [ -d /run/systemd/system ]; then
  for u in sshd ssh; do
    unit_exists "$u" || continue
    systemctl cat "$u" 2>/dev/null >"$WORK/unit"

    # drop-ins / overrides are a common hiding spot
    grep -E '^# /(etc|run)/systemd/system/' "$WORK/unit" | while read -r _ f; do
      case "$f" in
        */$u.service) ;;                          # base unit, fine
        *) warn "$u.service has override/drop-in: $f" ;;
      esac
    done

    grep -E '^Exec(Start|StartPre|StartPost|Stop|Reload)=' "$WORK/unit" >"$WORK/exec"
    while read -r l; do
      case "$l" in
        ExecStartPre=/usr/sbin/sshd\ -t* |\
        ExecStart=/usr/sbin/sshd\ -D* |\
        ExecReload=/usr/sbin/sshd\ -t* |\
        ExecReload=/bin/kill\ -HUP\ \$MAINPID |\
        ExecReload=/usr/bin/kill\ -HUP\ \$MAINPID)
          info "$u.service: $l" ;;
        *) warn "$u.service runs something unexpected: $l" ;;
      esac
    done <"$WORK/exec"
    break
  done
fi

# ---- report ---------------------------------------------------------------
header "Summary"
echo "SUMMARY: pam_lines=$PAMLINES warnings=$WARNS"
