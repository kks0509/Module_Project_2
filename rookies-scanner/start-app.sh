#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ! -x .venv/bin/python ]]; then
  echo "Ubuntu에서 먼저 bash setup-ubuntu.sh 를 실행하세요." >&2
  exit 1
fi
.venv/bin/python doctor.py
exec .venv/bin/python -m rookies_scanner
