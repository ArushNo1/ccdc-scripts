#!/bin/sh
# Does a script hand control back to coordinate? Runs it the way coordinate
# does (script text typed into an interactive shell, then an end marker) and
# checks that the marker comes back.
#
#   sh testing/check-exit.sh                       scripts with "# risk: none"
#   sh testing/check-exit.sh services/x.tested.sh  exactly these scripts
#
# THIS EXECUTES THE SCRIPTS. It refuses to run as root, so scripts that follow
# CLAUDE.md (non-root = audit only) change nothing, but scripts that do not
# (see first15/) can still try. That is why the default is risk: none only.
# Ending states:
#   ok        marker came back
#   FAIL exit the shell died before the marker (a top-level exit)
#   FAIL slow still running at the limit (hang, or just slow: raise LIMIT)

LIMIT=${LIMIT:-30}
MARKER="__CCDC_END_MARKER__"

if [ "$(id -u 2>/dev/null)" = 0 ]; then
  echo "refusing to run as root: this executes the scripts" >&2
  exit 2
fi
command -v timeout >/dev/null 2>&1 || { echo "timeout(1) not installed, cannot run" >&2; exit 2; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2

if [ $# -gt 0 ]; then
  LIST="$*"
else
  LIST=""
  for f in $(find ./first15 ./services -name '*.sh' | sort); do
    risk="$(sed -n 's/^# risk:[[:space:]]*//p' "$f" | head -n 1 | cut -d' ' -f1)"
    [ "$risk" = none ] && LIST="$LIST $f"
  done
fi
[ -n "$LIST" ] || { echo "no scripts with '# risk: none'; name scripts on the command line"; exit 0; }

SHELLS="sh"
command -v bash >/dev/null 2>&1 && SHELLS="sh bash"

FAILS=0
for f in $LIST; do
  [ -f "$f" ] || { echo "  FAIL  $f: not found"; FAILS=$((FAILS + 1)); continue; }
  for s in $SHELLS; do
    out="$( ( cat "$f"; echo; echo "echo $MARKER" ) | timeout -s KILL "$LIMIT" "$s" -i 2>/dev/null )"
    rc=$?
    # 124 = timeout's own code, 137 = killed. Interactive shells ignore SIGTERM,
    # so look at this before the marker: a late marker is still too slow.
    if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
      printf '  FAIL  %s (%s -i): still running after %ss, hang or slow\n' "$f" "$s" "$LIMIT"
      FAILS=$((FAILS + 1))
    elif printf '%s\n' "$out" | grep -x "$MARKER" >/dev/null 2>&1; then
      printf '  ok    %s (%s -i)\n' "$f" "$s"
    else
      printf '  FAIL  %s (%s -i): the shell exited before the end marker, a top-level exit\n' "$f" "$s"
      FAILS=$((FAILS + 1))
    fi
  done
done

echo
if [ "$FAILS" -eq 0 ]; then echo "RESULT: all scripts return control"; else echo "RESULT: $FAILS failure(s)"; fi
exit "$FAILS"
