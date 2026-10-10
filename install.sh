#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required. Install it with: sudo apt install python3 python3-venv python3-pip"
  exit 1
fi
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
chmod +x reconx.py run.sh
mkdir -p reports
echo
echo "Vidyexd ReconX installed successfully."
echo "Next: source .venv/bin/activate"
echo "Try:  python3 reconx.py example.com"
