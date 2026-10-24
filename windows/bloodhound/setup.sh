#!/usr/bin/env bash
# Install the CE Python collector and its dependencies inside this folder.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export PIP_CACHE_DIR="$root/.cache/pip"
"${PYTHON:-python3}" -m venv "$root/.venv"
"$root/.venv/bin/python" -m pip install -r "$root/requirements.txt"
"$root/.venv/bin/python" -m pip check
printf 'Installed collector: %s\n' "$root/.venv/bin/bloodhound-ce-python"
