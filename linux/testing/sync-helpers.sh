#!/bin/sh
# Copies the helper block from utils.sh into every script that has one.
#
#   sh testing/sync-helpers.sh
#
# The block in a script starts at the "# ---- helpers (same block as utils.sh)"
# line and ends at the next line made only of dashes. Both lines stay; what is
# between them is replaced by utils.sh from line 7 on (after the shebang and
# the "reference copy" comment). Scripts without the start line are skipped.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
START='# ---- helpers (same block as utils.sh) --------------------------------------'
END='# ---------------------------------------------------------------------------'
TMP="${TMPDIR:-/tmp}/sync-helpers.$$"
trap 'rm -f "$TMP" "$TMP.body"' EXIT

main() {
  cd "$ROOT" || exit 1
  sed -n '7,$p' utils.sh >"$TMP.body" || exit 1
  [ -s "$TMP.body" ] || { echo "utils.sh has no helper block"; exit 1; }

  changed=0
  for f in $(find . -name '*.sh' -not -path './testing/*' -not -name utils.sh | sort); do
    if ! grep -qxF "$START" "$f"; then
      echo "skip     $f (no start line)"
      continue
    fi
    if ! grep -qxF "$END" "$f"; then
      echo "skip     $f (no end line)"
      continue
    fi
    # awk prints the start line, the new block, then resumes at the end line
    awk -v start="$START" -v end="$END" -v body="$TMP.body" '
      $0 == start && !done { print; while ((getline l < body) > 0) print l; skip = 1; next }
      skip && $0 == end { print; skip = 0; done = 1; next }
      !skip { print }
    ' "$f" >"$TMP" || { echo "FAILED   $f"; continue; }
    if cmp -s "$f" "$TMP"; then
      echo "same     $f"
    else
      # cat keeps the original file's mode and owner
      cat "$TMP" >"$f" && echo "updated  $f" && changed=$((changed + 1))
    fi
  done
  echo "$changed script(s) updated"
}

( main )
