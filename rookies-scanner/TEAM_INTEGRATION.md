# 로그팀 원본 통합

`vendor/log_team_optimization/log_team/pipeline/`에는 전달받은
`log_team_optimization.zip`의 Python 소스 9개와 requirements.txt가 바이트 단위로
그대로 보존되어 있습니다. manifest.json은 ZIP 이름/해시와 각 원본 파일 해시를
기록합니다. 배포 ZIP에서도 원본 줄바꿈을 변환하지 않습니다.
실제 .env, 가상환경, 기존 PCAP, 과거 리포트는 복사하지 않습니다.

## 실제 연결 위치

`external/team_adapter.py`가 해시를 검증하고 원본 함수 본문을 변경 없이 실행합니다.
원본의 고정 경로 초기화, 대화형 input, 무한 루프, 파일 삭제 및 자동 API 호출은
실행하지 않습니다. AST에서 필요한 함수와 상수를 선택하고 실행 환경을 공급합니다.
이는 신뢰한 번들 소스를 연결하는 방식이며 외부 임의 코드를 격리하는 sandbox는 아닙니다.

| 원본 | Scanner에서 사용하는 기능 |
| --- | --- |
| tools/get_PacketLog.py | start_pcap_dumper_once로 유한 수집 명령 생성 |
| tools/final_test.py | pcap_to_csv, rename_columns, predict |
| tools/result_exporter.py | save_prediction_json의 원본 ML 집계/JSON 생성 |
| tools/parser.py | get_WebLog_pipeline으로 유한 웹 로그 snapshot 재생 |
| tools/regex_filter.py | load_logs, filter_logs로 원본 규칙 검사 |

수집 실행은 Scanner가 감독하며 웹 UI의 사용자 인터페이스 입력/검증, BPF,
시간/패킷/파일 크기 상한, 취소, returncode 확인을 연결 코드에서 적용합니다.
원본 get_PacketLog_pipeline의 무한 수집/폴더 삭제는 호출하지 않습니다.
빈 Flow skip 및 다음 입력 계속 처리, 변환 subprocess 시간 제한은 유지합니다.

원본 PCAP 변환 함수와 GC 동작을 그대로 사용합니다. Raw CICFlowMeter CSV에서는
원본 컬럼 선택/순서/rename을 적용하고 predict 및 predict_proba를 원본과 동일하게
호출합니다. 이미 정규화된 CSV 업로드는 입력 형식 호환 경로를 지원합니다.
NaN/inf/필수 feature 누락은 임의 보정하지 않고 오류로 기록합니다.
BRUTE FORCE를 DOS로 치환하는 후처리는 없습니다.

원본의 파일 출력은 parser/regex/exporter 실행 환경에서 메모리로 연결하며
Scanner가 허용한 JSON만 저장합니다. 로그 snapshot은 시작 위치를 처음으로 맞추고
EOF에서 종료합니다. 마지막 정상 응답을 마무리할 구분선만 덧붙입니다.
비밀번호/쿠키/응답 원문은 결과 JSON 및 LLM 입력에서 제외합니다.
원본 디버깅 print는 연결 환경에서 억제합니다.

원본 pipeline.py 및 report_generator_v2.py도 보존하되 실행하지 않습니다.
기존 Scanner의 별도 AI 리포트 생성 버튼, Scan ID 연결, 원본 판정 보존 및
사용자용 문서 보고서 출력을 유지합니다. 내부 취약점 진단은 변경하지 않습니다.

## 모델과 실행

원본 소스 내부의 final3.pkl 경로 문자열은 수정하지 않습니다. Scanner는 연결 코드에서
체크섬 검증한 `external/models/final4.pkl`을 공급합니다. CBM 변환은 수행하지 않습니다.
Ubuntu 설치/실행 방법은 기존 README.md 및 setup-external-ubuntu.sh를 사용합니다.

PCAP은 기존대로 `reports/<Scan ID>/work-<임의값>/`에 임시 저장되고 종료 시 삭제됩니다.
원본 로그팀의 pcap_buffer 폴더를 삭제하거나 변경하지 않습니다.

실제 Ubuntu의 수집 권한 및 실제 Slowloris 분류는 서버에서 별도 확인해야 합니다.
동일 PCAP 비교 도구는 ML_REGRESSION.md를 참고하세요.
