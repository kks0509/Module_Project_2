#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [[ ! -r /etc/os-release ]]; then
  echo "Ubuntu 시스템에서 실행하세요." >&2
  exit 1
fi
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "이 설치 스크립트는 Ubuntu 전용입니다 (현재: ${ID:-unknown})." >&2
  exit 1
fi
if [[ "${EUID}" -eq 0 ]]; then
  echo "일반 사용자로 실행하세요. 시스템 패키지 설치에만 sudo를 사용합니다." >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y python3 python3-venv
python3 -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10 이상이 필요합니다."'

if [[ -e .venv && ! -x .venv/bin/python ]]; then
  echo "다른 OS의 .venv가 있습니다. 이 폴더에는 소스만 복사하고 다시 설치하세요." >&2
  exit 1
fi
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python doctor.py
echo "설치 완료. bash start-app.sh 실행 후 http://127.0.0.1:8501 에 접속하세요."
