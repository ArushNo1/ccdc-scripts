#!/bin/sh
# Behaviour tests. Runs every active script inside throwaway Docker containers,
# fed to a shell the way coordinate feeds it, as root and as an unprivileged
# user. Nothing is executed on this machine outside a container.
#
#   sh testing/test-scripts.sh                        every active script
#   sh testing/test-scripts.sh services/x.draft.sh    only these
#
# Checked on every run:
#   - the end marker comes back (no top-level exit, nothing ate stdin, no hang)
#   - a SUMMARY line is printed
#   - a non-root run prints the not-root warning
#   - /tmp is empty afterwards (the cleanup trap works)
# Images are never pulled or built here, see testing/README.md.
# shellcheck disable=SC2016  # the sh -c text below is meant for the container

LIMIT=${LIMIT:-60}
MARKER="__CCDC_END_MARKER__"
# image:shell. On a target the script runs in the login shell of the account,
# not in /bin/sh, so the Debian image is tried with both of its shells.
IMAGES=${CCDC_TEST_IMAGES:-"bash:3.2:bash busybox:1.28:sh ccdc-test:debian:sh ccdc-test:debian:bash ccdc-test:users:sh ccdc-test:users:bash"}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2

if ! docker info >/dev/null 2>&1; then
  echo "docker is not available, nothing was tested (see testing/README.md)" >&2
  exit 2
fi

if [ $# -gt 0 ]; then
  LIST="$*"
else
  LIST="$(find first15 services persistence users -name '*.sh' 2>/dev/null |
    grep -v -e '\.deprecated\.sh$' -e '\.broken\.sh$' | sort)"
fi

FAILS=0
RUNS=0
fail() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

for entry in $IMAGES; do
  img="${entry%:*}"
  shell="${entry##*:}"
  echo "== $img ($shell) =="
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    echo "  skip  $img is not here (see testing/README.md)"
    continue
  fi
  for f in $LIST; do
    for uid in 0 65534; do
      RUNS=$((RUNS + 1))
      name="ccdc-test-$$-$RUNS"
      # coordinate trims every line, drops the empty ones and writes the rest to
      # the stdin of the shell, then echoes a marker and waits for it.
      out="$(timeout -s KILL "$LIMIT" docker run --rm --name "$name" --network none -u "$uid" \
        -v "$ROOT":/w:ro "$img" sh -c '
          { sed "s/^[[:space:]]*//; s/[[:space:]]*\$//" "$2" | grep -v "^\$"; echo "echo $3"; } | "$1" 2>&1
          echo "__TMP__ $(ls -A /tmp | tr "\n" " ")"' x "$shell" "/w/$f" "$MARKER" 2>&1)"
      if [ $? = 137 ]; then
        docker rm -f "$name" >/dev/null 2>&1
        fail "$f (uid $uid): still running after ${LIMIT}s"
        continue
      fi
      bad=""
      printf '%s\n' "$out" | grep -x "$MARKER" >/dev/null || bad="$bad no-end-marker"
      printf '%s\n' "$out" | grep '^SUMMARY:' >/dev/null || bad="$bad no-SUMMARY"
      printf '%s\n' "$out" | grep -x '__TMP__ ' >/dev/null || bad="$bad left-files-in-/tmp"
      if [ "$uid" != 0 ]; then
        printf '%s\n' "$out" | grep 'Not running as root' >/dev/null || bad="$bad no-root-warning"
      fi
      if [ -n "$bad" ]; then
        fail "$f (uid $uid):$bad"
        printf '%s\n' "$out" | tail -n 12 | sed 's/^/        /'
      else
        printf '  ok    %s (uid %s)\n' "$f" "$uid"
      fi
    done
  done
done

echo
if [ "$RUNS" = 0 ]; then
  echo "RESULT: no image available, nothing was tested"
  exit 2
fi
if [ "$FAILS" -eq 0 ]; then echo "RESULT: $RUNS runs passed"; else echo "RESULT: $FAILS of $RUNS runs failed"; fi
[ "$FAILS" -eq 0 ]
