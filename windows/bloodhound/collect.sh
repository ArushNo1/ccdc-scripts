#!/usr/bin/env bash
# BloodHound prompts for a password unless authentication flags are supplied.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
collector="$root/.venv/bin/bloodhound-ce-python"
if [[ ! -x "$collector" ]]; then
    printf 'Run %s/setup.sh first.\n' "$root" >&2
    exit 1
fi
umask 077
mkdir -p "$root/output"
cd "$root/output"
exec "$collector" -u administrator -d umd.local -ns 192.168.1.182 "$@"
