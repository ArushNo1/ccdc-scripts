#!/bin/sh
# Static checks for every script in this repo. Runs in about a second and needs
# no VM, no root and executes none of the scripts under test.
#
#   sh testing/check-syntax.sh
#
# Exit status is the number of failed checks (0 = clean).
# shellcheck disable=SC2086,SC2181,SC2015,SC2016,SC2013  # word lists and "cmd && pass || fail" are the idiom here

# Behaviour is tested separately, in containers: testing/test-scripts.sh and
# testing/test-ssh.sh.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAILS=0
cd "$ROOT" || exit 1
TMPD="$(mktemp -d 2>/dev/null)" || { TMPD="/tmp/ccdc-check.$$"; mkdir "$TMPD"; }
trap 'rm -rf "$TMPD"' EXIT
trap 'exit 1' HUP INT TERM

fail() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
pass() { printf '  ok    %s\n' "$*"; }
skip() { printf '  skip  %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Every script needs a status suffix: one without it fails, so leaving the
# suffix off is not a way around the rules. The exceptions are named here.
LEGACY="./CCDC.sh" # bash menu from before the framework, never run through umdinate
SCRIPTS="$(find . -name '*.sh' -not -path './testing/*' -not -path './.git/*' | sort)"
echo "== Scripts =="
CHECKED=""
INACTIVE=""
for f in $SCRIPTS; do
  case "$f" in
    *.broken.sh | *.deprecated.sh) INACTIVE="$INACTIVE $f" ;;
    ./utils.sh | ./services/template.sh | *.wip.sh | *.draft.sh | *.tested.sh | *.stable.sh)
      CHECKED="$CHECKED $f" ;;
    "$LEGACY") skip "$f is legacy and outside the framework, not checked" ;;
    *) fail "$f has no status suffix (name.<status>.sh, see README.md)" ;;
  esac
done
# Tools that run on this machine, not on targets (no status header, may exit)
for f in ./umdinate ./testing/*.sh; do
  [ -f "$f" ] && CHECKED="$CHECKED $f"
done
SCRIPTS="$CHECKED"

# The label: suffix and "# status:" agree, and a claim of tested or stable
# names the run that backs it.
check_status() {
  suffix="$(basename "$1" .sh)"
  suffix="${suffix##*.}"
  status="$(sed -n 's/^# status:[[:space:]]*//p' "$1" | head -n 1)"
  # The template is the one script that is deliberately unsuffixed
  [ "$1" = ./services/template.sh ] && suffix="$status"
  case "$suffix" in
    wip | draft | tested | stable | broken | deprecated) ;;
    *) fail "filename needs a status suffix (name.draft.sh), got '$suffix'" ;;
  esac
  if [ "$status" = "$suffix" ]; then
    pass "status header matches suffix ($status)"
  else
    fail "status header '$status' != suffix '$suffix'"
  fi
  case "$status" in
    tested | stable)
      if sed -n 's/^# tested:[[:space:]]*//p' "$1" | head -n 1 |
        grep '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' >/dev/null; then
        pass "'# tested:' names a dated run"
      else
        fail "status is $status but '# tested:' names no run (os YYYY-MM-DD)"
      fi
      ;;
  esac
}

# ---- 1. which shells can we test with? -------------------------------------
echo "== Shells available =="
SHELLS=""
for sh in dash bash ksh mksh posh; do
  if have "$sh"; then
    # dash has no --version, so only ask the shells that do
    case "$sh" in
      bash | ksh) ver="$("$sh" --version 2>&1 | head -n 1)" ;;
      *) ver="" ;;
    esac
    printf '  %-6s %s\n' "$sh" "${ver:-(version not reported)}"
    SHELLS="$SHELLS $sh"
  else
    skip "$sh not installed"
  fi
done
if have busybox && busybox sh -c : >/dev/null 2>&1; then
  printf '  %-6s %s\n' busybox "$(busybox 2>&1 | head -n 1)"
  SHELLS="$SHELLS busybox"
else
  skip "busybox not installed"
fi
[ -n "$SHELLS" ] || fail "no shells to test with"

# ---- 1b. old shells in containers (optional) --------------------------------
# Images are never pulled here: that is slow and needs the network.
# Pull once with: docker pull bash:3.2 busybox:1.28
echo
echo "== Old shells (Docker) =="
DOCKER_IMAGES="bash:3.2:bash busybox:1.28:sh"
# `command -v docker` is not enough: WSL ships a stub that exists but fails
if have docker && docker info >/dev/null 2>&1; then
  for entry in $DOCKER_IMAGES; do
    img="${entry%:*}"
    cmd="${entry##*:}"
    if ! docker image inspect "$img" >/dev/null 2>&1; then
      skip "$img not pulled (docker pull $img)"
      continue
    fi
    out="$(docker run --rm -v "$ROOT":/w:ro -w /w "$img" sh -c \
      'c=$1; shift; for f in "$@"; do if "$c" -n "$f" 2>/dev/null; then echo "ok $f"; else echo "FAIL $f"; fi; done' \
      x "$cmd" $SCRIPTS 2>&1)"
    printf '%s\n' "$out" | while read -r status path; do
      [ "$status" = ok ] && pass "$img $cmd -n $path"
    done
    bad="$(printf '%s\n' "$out" | grep -v '^ok ' | grep -v '^$')"
    if [ -n "$bad" ]; then
      fail "$img:
$bad"
    fi
  done
else
  skip "docker not available (see testing/README.md)"
fi

# ---- 2. per script ---------------------------------------------------------
# Broken and deprecated scripts are kept for reference only: umdinate will not
# run them as root, so only their label is checked.
for f in $INACTIVE; do
  echo
  echo "== $f (inactive, label only) =="
  check_status "$f"
done

for f in $SCRIPTS; do
  echo
  echo "== $f =="

  # Shebang
  case "$(head -n 1 "$f")" in
    '#!/bin/sh') pass "shebang is #!/bin/sh" ;;
    *) fail "first line must be #!/bin/sh" ;;
  esac

  # Syntax under every shell we have
  for sh in $SHELLS; do
    if [ "$sh" = busybox ]; then
      out="$(busybox sh -n "$f" 2>&1)"
    else
      out="$("$sh" -n "$f" 2>&1)"
    fi
    if [ $? -eq 0 ]; then pass "$sh -n"; else fail "$sh -n: $out"; fi
  done
  if have bash; then
    out="$(bash --posix -n "$f" 2>&1)" && pass "bash --posix -n" || fail "bash --posix -n: $out"
  fi

  # run shellcheck when it is installed
  if have shellcheck; then
    out="$(shellcheck -s sh "$f" 2>&1)" && pass "shellcheck" || fail "shellcheck:
$out"
  else
    skip "shellcheck not installed"
  fi

  # Bashisms and GNU-only options. Comments are stripped first.
  body="$(grep -v '^[[:space:]]*#' "$f")"
  # The local tools contain awk code and quoted test strings that these greps
  # would misread, so only shell syntax and shellcheck apply to them.
  case "$f" in
    ./umdinate | ./testing/*) LOCAL=1 ;;
    *) LOCAL=0 ;;
  esac
  check_absent() {
    # $1 = description, $2 = grep pattern
    [ "$LOCAL" = 1 ] && return 0
    hit="$(printf '%s\n' "$body" | grep -n -e "$2" | head -n 3)"
    if [ -n "$hit" ]; then fail "$1:
$hit"; fi
  }
  check_absent "[[ ]] test"            '\[\[[[:space:]]'
  check_absent "=~ regex"              '=~'
  check_absent "&> redirect"           '&>'
  check_absent "<<< here-string"       '<<<'
  check_absent "process substitution"  '<('
  check_absent "\${!var} indirection"  '\${!'
  check_absent "case modification"     '\${[a-zA-Z_]*\(,,\|\^\^\)'
  check_absent "array syntax"          '[a-zA-Z_]=('
  check_absent "source (use .)"        '^[[:space:]]*source '
  check_absent "function keyword"      '^[[:space:]]*function '
  check_absent "\$EUID / \$RANDOM"     '\$EUID\|\$RANDOM'
  check_absent "echo -e / echo -n"     'echo -[en]'
  check_absent "read -p"               'read[[:space:]]\{1,\}-[a-z]*p'
  check_absent "stat -c"               'stat -c'
  check_absent "date %F / -d"          "date .*\(%F\|-d \)"
  check_absent "grep -P / --exclude-dir" 'grep .*\(-P\|--exclude-dir\)'
  check_absent "readlink -f"           'readlink -f'
  check_absent "sed -i"                'sed -i'
  check_absent "set -o pipefail"       'pipefail'
  check_absent "getopts / flags"       'getopts'

  # Metadata header, and filename suffix matches it
  case "$f" in
    ./utils.sh | ./umdinate | ./testing/*) ;;
    *)
      # coordinate rewrites lines that carry its directives, comments included
      hit="$(grep -n -e '^[[:space:]]*#DROP' -e '#CALLBACK_IP' "$f" | head -n 3)"
      if [ -n "$hit" ]; then fail "coordinate directive (#DROP / #CALLBACK_IP) in the script:
$hit"; fi

      # coordinate feeds the script to a shell and waits for an end marker: an
      # exit outside a function kills that shell and coordinate waits out its
      # whole timeout. A function that exits must only be reached from ( main ).
      # testing/test-scripts.sh is the real test of this; here it is a grep.
      top="$(awk '
        /^[A-Za-z_][A-Za-z0-9_]*\(\)[ \t]*\{/ { if ($0 !~ /\}[ \t]*$/) infn = 1; next }
        infn { if ($0 ~ /^\}/) infn = 0; next }
        /^[ \t]*#/ { next }
        /(^|[^A-Za-z0-9_"\047-])exit([ \t;)]|$)/ { print "    line " NR ": " $0 }
      ' "$f")"
      if [ -n "$top" ]; then
        fail "exit outside a function: coordinate will wait out its timeout (see CLAUDE.md)
$top"
      elif grep -v -e '^[[:space:]]*#' -e '^trap ' "$f" | grep -w exit >/dev/null 2>&1; then
        if [ "$(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$f" | tail -n 1)" = "( main )" ]; then
          pass "exit only inside functions, and the file ends with ( main )"
        else
          fail "a function calls exit, so the file must end with ( main ) (see CLAUDE.md)"
        fi
      else
        pass "no exit, coordinate sees the end of the script"
      fi

      check_status "$f"
      for key in risk os tested; do
        grep "^# $key:" "$f" >/dev/null 2>&1 || fail "missing '# $key:' header"
      done
      grep '^trap ' "$f" >/dev/null 2>&1 || {
        grep 'mktemp' "$f" >/dev/null 2>&1 && fail "uses mktemp but sets no trap"
      }

      # Embedded helper block must match utils.sh (comments/blank lines ignored)
      norm() {
        sed -n '/^WARNS=0/,/^# -----/p' "$1" | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$'
      }
      norm utils.sh >"$TMPD/a"
      norm "$f" >"$TMPD/b"
      if diff "$TMPD/a" "$TMPD/b" >/dev/null 2>&1; then
        pass "helper block matches utils.sh"
      else
        fail "helper block differs from utils.sh"
      fi
      ;;
  esac
done

# ---- 3. playbooks: every step must point at something real -------------------
echo
echo "== Playbooks =="
for y in playbooks/*.yml; do
  [ -f "$y" ] || continue
  before="$FAILS"
  for stem in $(sed -n 's/^[[:space:]]*-\{0,1\}[[:space:]]*run:[[:space:]]*//p' "$y"); do
    set -- "$stem".*.sh
    if [ $# != 1 ] || [ ! -f "$1" ]; then
      fail "$y: 'run: $stem' must match exactly one $stem.<status>.sh"
    fi
  done
  for svc in $(sed -n 's/^[[:space:]]*-[[:space:]]*service:[[:space:]]*//p' "$y"); do
    [ -f "playbooks/$svc.yml" ] || fail "$y: 'service: $svc' but there is no playbooks/$svc.yml"
  done
  [ "$before" = "$FAILS" ] && pass "$y: every step resolves"
done

# ---- 4. umdinate against a fake coordinate -----------------------------------
echo
echo "== umdinate tests =="
if [ -f testing/test-umdinate.sh ]; then
  out="$(sh testing/test-umdinate.sh 2>&1)"
  if [ $? -eq 0 ]; then
    pass "testing/test-umdinate.sh"
  else
    fail "testing/test-umdinate.sh:
$(printf '%s\n' "$out" | grep -E 'FAIL|RESULT')"
  fi
else
  skip "testing/test-umdinate.sh not found"
fi

echo
if [ "$FAILS" -eq 0 ]; then
  echo "RESULT: all checks passed"
else
  echo "RESULT: $FAILS check(s) failed"
fi
exit "$FAILS"
