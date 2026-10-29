#!/usr/bin/env bash
set -euo pipefail
umask 077
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"${PYTHON_BIN:-python3}" -m venv "$root/.venv"
"$root/.venv/bin/python" -m pip install -r "$root/requirements-html.txt"
printf '%s\n' 'HTML sanitizer installed. Pandoc is also required. The Hub wrapper uses this virtual environment automatically.'
