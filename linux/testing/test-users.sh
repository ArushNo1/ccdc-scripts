#!/bin/sh
# Real account/SSH scenarios inside disposable containers; never edits this host.
ROOT=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
if ! docker info >/dev/null 2>&1; then
printf '%s\n' 'Docker unavailable: user workflow scenarios not tested' >&2
exit 2
fi
if ! docker image inspect ccdc-test:users >/dev/null 2>&1; then
printf '%s\n' 'Build first: docker build -f testing/users.Dockerfile -t ccdc-test:users testing' >&2
exit 2
fi
fails=0
for scenario in normal controller backup-failure custom-grant existing-admin; do
if docker run --rm --network none --hostname testbox -v "$ROOT:/w:ro" ccdc-test:users sh /w/testing/users-scenarios.sh "$scenario"; then
printf 'PASS users: %s\n' "$scenario"
else
printf 'FAIL users: %s\n' "$scenario"
fails=$((fails + 1))
fi
done
exit "$fails"
