#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ! -x .venv/bin/python ]]; then
  echo "먼저 bash setup-ubuntu.sh로 기본 앱을 설치하세요." >&2
  exit 1
fi
if [[ "${EUID}" -eq 0 ]]; then
  echo "일반 사용자로 실행하세요. 패키지 설치에만 sudo를 사용합니다." >&2
  exit 1
fi
sudo apt-get update
sudo apt-get install -y tshark libpcap-dev
.venv/bin/python -m pip install -r requirements-external.txt
.venv/bin/python -c 'from external.network import load_model; m=load_model(); print("ML 모델 준비:", list(m.classes_), "· 특징", len(m.feature_names_))'
echo "외부 모듈 설치 완료. 캡처 권한과 인터페이스는 EXTERNAL_INTEGRATION.md를 확인하세요."
