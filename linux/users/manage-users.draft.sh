#!/bin/sh
# status: draft
# risk: lockout
# os: Linux controller with coordinate
# tested: never
# shellcheck disable=SC2034 # passwd columns and shared helpers are intentionally unused in some steps
# Runs the account workflow; root and unauthorized SSH logins stop working.

# Reference copy of the helper block that is pasted into every script.
# Scripts do NOT source this file: CLAUDE.md requires each one to be a single
# self-contained POSIX sh file. If you change a helper here, change it in the
# scripts too.

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
header() {
  printf '\n== %s ==\n' "$*"
  log "== $*"
}
info() {
  printf '[ ] %s\n' "$*"
  log "INFO: $*"
}
ok() {
  printf '[+] %s\n' "$*"
  log "OK: $*"
}
warn() {
  printf '[!] %s\n' "$*"
  log "WARN: $*"
  WARNS=$((WARNS + 1))
}

have() { command -v "$1" >/dev/null 2>&1; }

# Warn and carry on; never require root.
check_root() {
  if [ "$(id -u 2>/dev/null)" != 0 ]; then
    warn "Not running as root; results may be incomplete"
  fi
}

# ---------------------------------------------------------------------------

# No command-line flags. Configure file locations with environment variables.
BASE=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
COORD=${USERFLOW_COORDINATE:-$BASE/coordinate}
HOSTS=${USERFLOW_HOSTS:-$BASE/users/hosts.tsv}
AUTH=${USERFLOW_AUTH:-$BASE/users/authorized.tsv}
RESULTS=${USERFLOW_RESULTS:-$BASE/users/results}
WORK=
COUNT=0
FAILS=0
cleanup() {
  [ -z "$WORK" ] || rm -rf "$WORK"
  printf 'SUMMARY: hosts=%s failures=%s warnings=%s\n' "$COUNT" "$FAILS" "$WARNS" >&2
}

# coordinate can report failure in its text while returning zero.
remote() {
  script=$1
  phase_log=$(basename "$script" .sh)
  login=$2
  secret=$3
  escalate=$4
  set -- -t "$address" -u "$login" -p "$secret" -P "$port" -T 60 -q -y
  if [ "$escalate" = YES ]; then
    # coordinate -S uses sudo -i, which cannot work once root has nologin.
    # Send a normal SSH script that explicitly invokes /bin/sh through sudo.
    {
      printf '%s\n' "USERFLOW_CODE=''"
      od -A n -t o1 -v "$script" | awk '{printf "USERFLOW_CODE=\"$USERFLOW_CODE"; for(i=1;i<=NF;i++) printf "\\0%s",$i; print "\""}'
      printf "USERFLOW_PASSWORD='"
      printf '%s' "$secret" | od -A n -t o1 -v | awk '{for(i=1;i<=NF;i++) printf "\\0%s",$i}'
      printf "'\n"
      # shellcheck disable=SC2016 # literal code for the remote login shell
      printf '%s\n' 'if [ "$(id -u)" = 0 ]; then' '/bin/sh -c "$(printf "%b" "$USERFLOW_CODE")"' 'else' 'printf "%b\n" "$USERFLOW_PASSWORD" | sudo -S -p "" /bin/sh -c "$(printf "%b" "$USERFLOW_CODE")"' 'fi' 'unset USERFLOW_CODE USERFLOW_PASSWORD'
    } >"$WORK/elevated.sh"
    script="$WORK/elevated.sh"
  fi
  remote_rc=0
  "$COORD" "$@" "$script" </dev/null >"$WORK/raw" 2>&1 || remote_rc=$?
  # Strip ANSI sequences before checking errors or extracting TSV rows.
  esc=$(printf '\033')
  sed "s/$esc\[[0-9;]*[A-Za-z]//g" "$WORK/raw" >"$WORK/out"
  cp "$WORK/out" "$RESULTS/$label.$phase_log.log" || return 1
  [ "$remote_rc" = 0 ] || return 1
  if grep -e '\[ERROR' -e '\[CRIT' "$WORK/out" >/dev/null; then return 1; fi
  return 0
}

make_script() {
  # The only interpolated data is restricted to a validated alphabet.
  file=$1
  step=$2
  {
    printf "USERFLOW_ADMIN='%s'\n" "$admin"
    printf "USERFLOW_CONFIRMED='YES'\n"
    if [ -n "$plan" ]; then
      printf "USERFLOW_PLAN='"
      tr '\n' ' ' <"$plan"
      printf "'\n"
    fi
    cat "$step"
  } >"$file"
}

extract() {
  # coordinate trims trailing tabs from the end of a captured stdout block.
  awk -F '\t' 'NF>=6 && NF<=8 && $4 ~ /^(TRUE|FALSE)$/ && $6 ~ /^(TRUE|FALSE)$/ {printf "%s\t%s\t%s\t%s\t%s\t%s\t\t\n", $1,$2,$3,$4,$5,$6}' "$WORK/out"
}

verify() {
  # Proof is only printed after coordinate has escalated this fresh connection.
  # shellcheck disable=SC2016 # this code executes on the remote host
  printf '%s\n' 'if [ "$(id -u)" = 0 ]; then printf "USERFLOW_ROOT_OK\\n"; fi' >"$WORK/prove.sh"
  attempt=0
  while [ "$attempt" -lt 3 ]; do
    if remote "$WORK/prove.sh" "$admin" "$adminpw" YES && grep '^USERFLOW_ROOT_OK$' "$WORK/out" >/dev/null; then return 0; fi
    attempt=$((attempt + 1))
    [ "$attempt" -ge 3 ] || sleep 1
  done
  return 1
}

run_host() {
  COUNT=$((COUNT + 1))
  info "Host $label ($address): inventory"
  remote "$inventory_script" "$login" "$loginpw" YES || return 1
  extract >"$RESULTS/$label.inventory.tsv"
  [ -s "$RESULTS/$label.inventory.tsv" ] || {
    warn "No inventory rows received"
    return 1
  }
  # Derive the account from the target's hostname, never the supplied label.
  host=$(awk -F '\t' 'NR==1 {print $1}' "$RESULTS/$label.inventory.tsv")
  admin="$host-admin"
  case "$admin" in '' | *[!a-z0-9_.-]* | [0-9-]*)
    warn "Hostname cannot form a portable account name: $host"
    return 1
    ;;
  esac
  [ "${#admin}" -le 32 ] || {
    warn "Hostname-admin exceeds 32 characters"
    return 1
  }
  awk -F '\t' -v h="$label" '$1==h {print $2 ":" $3 ":TRUE"}' "$AUTH" >"$WORK/plan"
  [ -s "$WORK/plan" ] || {
    warn "No authorization rows for $label; skipping host"
    return 1
  }
  # Never let a generated admin collide with any input identity.
  if awk -F: -v u="$admin" '$1==u {found=1} END {exit !found}' "$WORK/plan"; then
    warn "Generated admin conflicts with authorization input"
    return 1
  fi
  awk -F '[:\t]' 'NR==FNR {ok[$1]=1; next} !($2 in ok) {print}' "$WORK/plan" "$RESULTS/$label.inventory.tsv" >"$RESULTS/$label.unauthorized.tsv"
  info "Accounts outside the allowlist on $label (including noninteractive service accounts):"
  cut -f2 "$RESULTS/$label.unauthorized.tsv" >&2
  printf '%s\n' "$admin:admin:TRUE" >>"$WORK/plan"
  plan=
  make_script "$WORK/bootstrap.sh" "$access_script"
  remote "$WORK/bootstrap.sh" "$login" "$loginpw" YES || return 1
  extract >"$RESULTS/$label.admin.tsv"
  adminpw=$(awk -F '\t' -v u="$admin" '$2==u && $3=="admin" && $6=="FALSE" {print $5}' "$RESULTS/$label.admin.tsv")
  [ -n "$adminpw" ] || {
    warn "Admin bootstrap failed; inspect protected diagnostics"
    return 1
  }
  # Save credentials before probing SSH so they survive any later host failure.
  cat "$RESULTS/$label.admin.tsv" >>"$RESULTS/credentials.tsv"
  verify || {
    warn "New admin SSH/sudo failed; root and existing credentials have not been disabled"
    return 1
  }
  info "Fresh SSH login and sudo confirmed for $admin"
  # Required operator checkpoint; input comes from the tty, never the script stream.
  if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
    warn "No terminal for deletion review; stopping before credential rotation"
    return 1
  fi
  printf 'Host %s: enter unauthorized local usernames safe to delete, separated by spaces (empty = keep accounts locked): ' "$label" >/dev/tty
  IFS= read -r deletions </dev/tty || return 1
  : >"$WORK/delete"
  for n in $deletions; do
    case "$n" in '' | *[!a-z0-9_.-]* | root)
      warn "Invalid deletion selection"
      return 1
      ;;
    esac
    awk -F '\t' -v u="$n" '$2==u {ok=1} END {exit !ok}' "$RESULTS/$label.unauthorized.tsv" || {
      warn "Deletion selection is authorized or not inventoried: $n"
      return 1
    }
    printf '%s\n' "$n" >>"$WORK/delete"
  done
  plan="$WORK/plan"
  make_script "$WORK/rotate.sh" "$rotate_script"
  remote "$WORK/rotate.sh" "$admin" "$adminpw" YES || return 1
  extract >"$RESULTS/$label.rotated.tsv"
  grep 'success=TRUE' "$WORK/out" >/dev/null || {
    warn "Rotation did not commit; account backups were restored"
    return 1
  }
  cat "$RESULTS/$label.rotated.tsv" >>"$RESULTS/credentials.tsv"
  verify || {
    warn "Post-rotation admin login failed; use recorded remote backup for recovery"
    return 1
  }
  if [ -s "$WORK/delete" ]; then
    {
      printf "USERFLOW_DELETE='"
      tr '\n' ' ' <"$WORK/delete"
      printf "'\n"
      cat "$delete_script"
    } >"$WORK/delete.sh"
    remote "$WORK/delete.sh" "$admin" "$adminpw" YES || return 1
    grep 'success=TRUE' "$WORK/out" >/dev/null || return 1
  fi
  info "Completed $label"
}
main() {
  exec 3>&1 >&2
  trap cleanup EXIT
  trap 'exit 1' HUP INT TERM
  check_root
  [ -s "$HOSTS" ] && [ -s "$AUTH" ] || {
    warn "Set USERFLOW_HOSTS and USERFLOW_AUTH; see users/README.md"
    return 1
  }
  [ "${UMDINATE_UNTESTED:-}" = 1 ] || {
    warn "Draft workflow: set UMDINATE_UNTESTED=1 only for a lab run"
    return 1
  }
  [ -x "$COORD" ] || {
    warn "Install coordinate or set USERFLOW_COORDINATE"
    return 1
  }

  # Resolve the four phases from the service manifest, just as umdinate does.
  phases=$(sed -n 's/^[[:space:]]*-[[:space:]]*run:[[:space:]]*//p' "$BASE/services/manage-users.yml")
  phase_count=0
  for phase in $phases; do
    case "$phase" in users/user-inventory | users/ensure-access | users/change-credentials | users/delete-users) ;; *)
      warn "Unexpected account workflow phase"
      return 1
      ;;
    esac
    set -- "$BASE/$phase".*.sh
    [ "$#" = 1 ] && [ -f "$1" ] || {
      warn "Ambiguous or missing workflow script: $phase"
      return 1
    }
    phase_count=$((phase_count + 1))
    case "$phase_count:$phase" in
    1:users/user-inventory) inventory_script=$1 ;;
    2:users/ensure-access) access_script=$1 ;;
    3:users/change-credentials) rotate_script=$1 ;;
    4:users/delete-users) delete_script=$1 ;;
    *)
      warn "Unexpected account workflow order"
      return 1
      ;;
    esac
  done
  [ "$phase_count" = 4 ] || {
    warn "Account workflow requires four phases"
    return 1
  }

  umask 077
  # Never overwrite prior credentials, or follow an existing output directory.
  mkdir "$RESULTS" || {
    warn "Results directory must be new: $RESULTS"
    return 1
  }
  chmod 700 "$RESULTS" || return 1
  WORK=$(mktemp -d 2>/dev/null) || return 1
  # TSV, no header, no empty fields: label address login password port.
  awk -F '\t' 'NF!=5 || $1 !~ /^[a-zA-Z0-9_-]+$/ || $2 !~ /^[a-zA-Z0-9_.:-]+$/ || $3 !~ /^[a-z_][a-z0-9_.-]*$/ || $4 ~ /,/ || $4=="" || $5 !~ /^[0-9]+$/ || $5<1 || $5>65535 || seen[$1]++ {bad=1} END {exit bad}' "$HOSTS" || {
    warn "Invalid hosts TSV"
    return 1
  }
  awk -F '\t' 'NF!=3 || $1 !~ /^[a-zA-Z0-9_-]+$/ || $2 !~ /^[a-z_][a-z0-9_.-]*$/ || ($3!="admin" && $3!="user" && $3!="preserve") || seen[$1 SUBSEP $2]++ {bad=1} END {exit bad}' "$AUTH" || {
    warn "Invalid authorization TSV"
    return 1
  }
  : >"$RESULTS/credentials.tsv"
  tab=$(printf '\t')
  while IFS="$tab" read -r label address login loginpw port; do
    if ! run_host; then
      FAILS=$((FAILS + 1))
      cp "$WORK/out" "$RESULTS/$label.failure.log" 2>/dev/null || :
      warn "Stopped $label; diagnostics and any issued credentials remain in $RESULTS"
    fi
  done <"$HOSTS"
  cat "$RESULTS/credentials.tsv" >&3
  [ "$FAILS" = 0 ]
}
(main)
