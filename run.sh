#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -d .venv ]]; then
  echo "Not installed yet. Run: ./install.sh"
  exit 1
fi
. .venv/bin/activate
python3 reconx.py "$@"
