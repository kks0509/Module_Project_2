# 외부 공격 진단 통합

로그팀 원본 파일은 `vendor/log_team_optimization/log_team/pipeline/`에 수정 없이 보존하고
`external/team_adapter.py`에서 호출합니다. 원본 보존 및 연결 범위는
[TEAM_INTEGRATION.md](TEAM_INTEGRATION.md)를 참고하세요.

`log_team_optimization.zip`의 웹 로그 파서/정규식, CICFlowMeter 특징 매핑, CatBoost 모델과 NETWORK JSON 구조를 외부 영역에 통합했습니다. 내부 `engine.py`, 인증 및 취약점 판정 모듈은 수정하지 않습니다.

## Ubuntu 설치 및 실행

```bash
unzip rookies-scanner-ubuntu.zip
cd rookies-scanner
bash setup-ubuntu.sh
bash setup-external-ubuntu.sh
cp .env.example .env  # 처음 설치할 때만. 기존 .env는 덮어쓰지 않습니다.
# .env의 OPENAI_API_KEY 및 아래 외부 설정을 서버에서 편집
bash start-app.sh
```

`http://127.0.0.1:8501` → **외부 공격 진단**을 엽니다. 네트워크 모듈은 `catboost==1.2.10`, `cicflowmeter==0.5.0`, `scapy==2.7.0`을 별도로 설치합니다. 팀 가상환경 전체 freeze를 앱 requirements에 합치지 않았으며, 기존 내부 실행 의존성을 유지합니다. Python 3.10 이상이 필요합니다.

## 입력 방식

**기존 파일 분석**: PCAP/PCAPNG, Flow CSV, 웹 로그 JSON/JSONL 또는 Burp HTTP `.log/.txt`, 팀에서 이미 생성한 `*_network_input.json`을 올립니다. PCAP은 Flow로 변환한 후 제공 모델로 분류하고, CSV도 기존 Predicted_Label을 신뢰하지 않고 다시 분류합니다. 기존 NETWORK JSON은 클래스별 수/확률을 검증해 가져오며 `classification_origin: imported_team_json`으로 구분합니다.

웹 로그 JSON에는 `method`, `url_path`가 필요합니다. 선택 필드는 `timestamp`, `query_params`, `request_body`, `status_code`입니다. 팀 Burp HTTP 로그의 요청/응답·구분선 파서를 유한 입력 방식으로 이식했습니다. Nginx combined 텍스트는 이 버전의 입력 형식이 아니므로 팀 파서의 JSON/Burp HTTP 로그를 사용합니다. 정규식은 팀의 SQL Injection, XSS, Path Traversal 패턴을 유지합니다. 외부 로그에서 이 패턴을 관찰하며 내부 능동 취약점 모듈을 추가하지 않습니다.

**서버에서 제한 시간 수집**: 웹 앱을 LMS 서버와 같은 Ubuntu VM에서 실행합니다. 브라우저가 아닌 **앱 서버**의 로그 파일/인터페이스를 수집합니다. 원격 SSH 수집은 구현하지 않았습니다. 설정 예:

```dotenv
EXTERNAL_WEB_LOG_PATH=/home/lms/burp_share/burp_live.log
EXTERNAL_ZEROTIER_INTERFACE=
EXTERNAL_ZEROTIER_PORT=5000
EXTERNAL_DOCKER_NETWORK=lms-security-lab_lms-network
EXTERNAL_LMS_CONTAINER=lms-web
EXTERNAL_LMS_PORT=5000
EXTERNAL_INTERFACE=
EXTERNAL_DUMPCAP=/usr/bin/dumpcap
EXTERNAL_TIMEZONE=Asia/Seoul
EXTERNAL_OPENAI_MODEL=
```

### 수집 인터페이스 직접 입력

외부 진단 화면의 **수집 인터페이스 직접 입력**에 `ztxooopmrp`, `enp0s3`,
`br-...`, `lo` 등 실제 수집할 인터페이스를 입력합니다. 편집 가능한 입력란은 항상 표시합니다.
`EXTERNAL_INTERFACE`는 선택적 초기값이며, 제출한 값은 현재 앱 세션에서 보관합니다.
앱은 입력값을 ZeroTier/Docker 자동 감지 결과로 덮어쓰지 않습니다.

서버에서 제한 시간 수집을 선택한 뒤 **외부 진단 시작**을 누릅니다.
작업 생성 시와 실제 dumpcap 실행 직전 모두 Linux 인터페이스 존재 여부를 확인합니다.
인터페이스가 없으면 이름을 확인하도록 오류를 표시하고 수집기를 실행하지 않습니다.
파일 분석 및 웹 로그만 수집하는 경우에는 인터페이스가 필요하지 않습니다.

필터는 `tcp port <대상 origin의 포트>`를 사용합니다. 기본 LMS 대상은 5000 포트이며,
Docker 내부 IP로 필터를 제한하지 않습니다. 입력한 인터페이스는 앱 서버의 인터페이스입니다.

```bash
/usr/bin/dumpcap -i ztxooopmrp -f 'tcp port 5000' \
  -a duration:30 -a filesize:16000 -c 20000 -P -w capture.pcap -q
```

실제 사용한 인터페이스, 필터, `selection: manual` 및 확인 시각을 `collection.capture`에
기록합니다. 자동 감지 함수는 기존 CLI/API의 명시적 auto 모드 지원용으로 보존하지만
웹 UI의 수집에서는 호출하지 않습니다. CLI에 `--interface 실제이름`을 지정하면 동일한
수동 검증 및 포트 필터를 사용합니다. CLI에서 생략하면 기존 자동 감지 모드가 유지됩니다.

웹 수집은 버튼을 누른 뒤 파일에 **새로 추가되는** 데이터를 읽습니다. 이전 로그를 분석하려면 파일 분석 방식을 사용하세요. 파일 회전/잘림은 offset을 다시 잡습니다. Burp 원시 텍스트에는 원래 타임스탬프가 없으므로 `timestamp_basis: collection_time`으로 표시합니다. JSON에 있는 시각은 보존합니다. 시간대가 없는 Flow 시각은 `EXTERNAL_TIMEZONE`으로 해석하고, 이미 offset이 있는 시각은 유지합니다.

### 패킷 수집 권한

설치 중 tshark의 비관리자 패킷 수집 질문에 허용을 선택하고, 필요한 경우 관리자와 함께 다음을 설정합니다.

```bash
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark "$USER"
# 로그아웃/로그인 후 권한 반영
dumpcap -D
```

앱 전체를 sudo/root로 실행하지 않습니다. 앱은 권한 상승을 시도하거나 sudo 비밀번호를 받지 않습니다. dumpcap 권한이 없으면 네트워크 수집 실패를 기록하고, 웹 수집 결과는 별도로 유지합니다. 웹 로그 파일도 앱 사용자가 읽을 수 있어야 합니다.

수집은 5~120초(기본 30초), 웹 UI 수동 입력의 대상 TCP 포트 필터, 20,000패킷, 16 MB 상한으로 종료합니다. Ubuntu에서는 `/usr/bin/dumpcap` 절대경로를 사용합니다. `EXTERNAL_DUMPCAP`은 다른 플랫폼에서만 사용합니다. 인수는 shell 없이 리스트로 넘기며 BPF 문자열에 따옴표를 넣지 않습니다. PCAP 저장은 기존 버전에도 있는 `-P`를 사용하고 `-F pcap`에 의존하지 않습니다. 옵션 참고: [Wireshark dumpcap 매뉴얼](https://www.wireshark.org/docs/man-pages/dumpcap.html).

정상적인 진행 문구가 stderr에 있어도 실패로 취급하지 않습니다. 종료 코드 0, 출력 파일 존재 여부, 크기 제한 및 실제 PCAP 레코드를 확인합니다. 0개 패킷(헤더만 있는 PCAP 또는 0 byte 출력)은 **NETWORK 수집 완료 · 분석 가능한 패킷 없음**으로 저장하며 ML 추론을 건너뜁니다. 유효하지 않거나 잘린 PCAP, 크기 초과, 파일 없음, 비정상 종료와 실행 예외는 수집 실패로 구분합니다. 중지된 수집은 별도 상태를 기록합니다.

**NETWORK 수집 상세 기술 근거** 및 결과 JSON의 `collection.capture`에서 실행 경로, 인터페이스, 필터, 임시 PCAP 경로, `return_code`, `stderr`, `exception_type`, 파일 존재 여부·크기·패킷 수를 확인합니다. 실패 결과에도 같은 근거를 연결합니다. stderr/예외 문구는 길이를 제한하고 환경변수의 비밀값 및 비밀번호·API 키 표기를 마스킹합니다. stderr나 서버 경로는 AI 입력으로 보내지 않고 수집 상태/종료 코드/패킷 수 등의 요약만 보냅니다. 임시 PCAP 경로는 수집 당시 위치이며 파이프라인 종료 후 원시 파일은 정리합니다.

실제 공격 요청은 전송하지 않습니다. 수집 중 중지 버튼을 누르면 프로세스 종료와 작업 폴더 정리를 수행합니다. PCAP→Flow 변환도 별도 프로세스로 실행하며 60초 제한과 중지 처리가 있습니다. HTTPS 패킷은 암호화되어 웹 본문 패턴을 복구하지 못하므로 별도 웹 로그가 필요합니다.

## 결과와 AI 분석

```text
WEB 로그 → 팀 정규식 선별 ───────────────┐
PCAP → CICFlowMeter → 62 특징 → CatBoost ├→ pipeline_input.json
기존 Flow CSV / NETWORK JSON ────────────┘   → external_report.json
                                            → [AI 리포트 생성] → ai_report.json
```

모든 결과는 `source: external`이며 동일한 Scan ID를 공유합니다. 개별 원천은 `evidence.source: WEB / NETWORK`로 구분합니다. 네트워크 JSON의 클래스 평균 점수, 클래스별 Flow 수, 공격 의심 여부, 시간과 모델 출처를 보존합니다. 모델의 `BENIGN / BRUTE FORCE / DOS` 분류는 **공격 성공이나 취약점 확인을 확정하지 않습니다**. 판정은 공격 의심/의심 패턴 미탐지/판정 불가/분석 자료 없음으로 표시하고, 위험도 MEDIUM은 의심 신호의 검토 우선순위입니다. 전체 Flow의 평균 모델 점수는 보정된 침해 성공 확률이 아닙니다.

빈 CSV·Flow 없음은 분석 자료 없음으로 표시합니다. 누락 컬럼, 비수치/NaN/무한대 특징, 손상 PCAP, 모델 오류는 판정 불가입니다. 임의로 0을 채워 BENIGN으로 판정하지 않습니다. 한 파일 실패가 다른 파일의 성공 결과를 지우지 않습니다.

입력은 파일당 16 MB·전체 32 MB·최대 10개, 파일당 20,000개 요청/Flow까지 처리합니다. 웹 결과는 파일·공격 유형별로 묶어 전체 일치 요청 수와 최대 5개 대표 요청을 보관합니다. 분류 입력의 개별 이벤트 표본은 최대 500개이며 네트워크 모델 요약은 항상 보관합니다. 전체 웹 요청/Flow/의심 이벤트 수와 생략 수는 `collection`에 기록하며 표본 제한을 UI에 표시합니다. 오류/자료 없음 상태 항목도 별도로 보존합니다.

API 보고서는 기존처럼 별도 **AI 리포트 생성** 버튼 또는 명시적 CLI `--ai`로만 실행합니다. `OPENAI_API_KEY`를 기존 서버 `.env`/환경변수에서 읽습니다. 기본적으로 `OPENAI_MODEL`을 사용하고, 팀 모델을 사용할 수 있는 계정이면 `EXTERNAL_OPENAI_MODEL`에 따로 지정합니다. 입력 항목을 최대 12개씩 묶어 엄격한 JSON Schema로 생성하며 대량 결과도 모든 finding_id를 유지합니다. LLM은 기존 분류/위험도를 바꾸지 않고 근거·영향·대응을 설명합니다. API 오류는 원본 ML/웹 JSON을 변경하지 않습니다. 구현 참고: [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses).

```text
reports/SCAN-<uuid>/
  external_report.json   # source=external, collection, results, pipeline_inputs
  pipeline_input.json    # 팀 WEB / NETWORK 구조 + scan_id
  ai_report.json         # 버튼 실행 시 생성; source=external
```

통합 Dashboard는 내부와 외부 요약을 각각 표시합니다. 이력과 AI 문서는 source/Scan ID를 검증하며 내부 결과와 섞지 않습니다. 원시 PCAP/CSV와 수집 임시 파일은 이 Scan의 작업 폴더에만 만들고 실행 후 정리합니다. 원본 업로드 파일/서버 로그와 기존 팀 수집 폴더는 수정·삭제하지 않습니다. 쿠키·Authorization·헤더·비밀번호·원시 응답/요청 본문은 리포트와 LLM 입력에서 제외합니다. WEB 근거는 일치한 짧은 패턴과 Method/경로/상태만 보존합니다.

## 서버 CLI

```bash
.venv/bin/python -m external.cli --target http://10.163.130.121:5000 \
  --input /home/lms/log_team/pipeline/test_prediction.csv --authorized

.venv/bin/python -m external.cli --target http://10.163.130.121:5000 \
  --collect --duration 30 --network --web --authorized
# 위 명령은 ZeroTier → Docker bridge 자동 감지. 둘 다 실패하면 --interface 실제이름 추가
# AI 보고서를 함께 요청할 때만 --ai 추가
```

CLI와 웹은 같은 파이프라인을 사용합니다. CLI 결과도 웹 진단 이력에 나타납니다.

## 모델과 배포

제공된 **원본 `final4.pkl`** 파일을 바이트 변경 없이 `external/models/final4.pkl`로 배포합니다. `external/config.py`의 `MODEL_PATH` 한 곳에서 경로를 관리하고, manifest의 파일명과 원본 SHA-256을 확인한 바이트만 pickle로 직접 복원합니다. 모델 파일 업로드/임의 경로 선택 UI는 제공하지 않습니다. 런타임에는 CBM 변환이나 다른 모델 fallback이 없으며 62개 입력 Feature·BENIGN / BRUTE FORCE / DOS 클래스·predict/predict_proba와 label mapping을 유지합니다. NETWORK JSON의 `model_file`, `model_sha256`, `model_format: pickle`에 실제 출처를 기록합니다. 모델 재학습/후처리 없이 저장 형식 로딩만 원본으로 복원했습니다. 검증 범위는 [MODEL_VALIDATION.md](MODEL_VALIDATION.md), 원본 입력 비교는 [ML_REGRESSION.md](ML_REGRESSION.md)를 확인하세요.

ZIP에 실제 `.env` 및 수집 PCAP/기존 보고서가 포함되어 있었으나 이를 배포하지 않습니다. `.venv`, `.env`, 실제 로그/PCAP, 기존 AI 보고서, 테스트 작업 폴더는 통합 ZIP에서 제외됩니다. Docker 기본 구성은 기존 내부 앱을 유지합니다. 외부 모델/파일 분석 패키지는 `INSTALL_EXTERNAL=1` build arg로 설치하며, 기본 비특권 Docker에서 호스트 패킷을 수집하는 기능은 제공하지 않습니다. 실시간 수집은 위 Ubuntu 호스트 설치를 사용합니다.

## 검증

내부 판정 회귀와 외부 검증:

```bash
.venv/bin/python -m unittest discover -v
```

외부 패키지를 설치한 환경에서 실행합니다. 제공 ZIP의 CSV를 현재 모델로 재분류한 표본 결과는 MODEL_VALIDATION.md에 기록했습니다. 제공 PCAP의 실제 Flow 추출/ML 분류, JSON 저장, 이력, 웹 메뉴, 빈 CSV/입력 오류/중지, 개인정보 제외 및 모의 OpenAI 응답을 검사합니다. `test_zerotier_capture.py`는 ZeroTier 우선 선택·이름 변경·복수 NIC·Docker/수동 fallback·UI·실제 BPF·빈 PCAP 메타데이터와 pkl/native 예측 일치를 확인합니다. `test_docker_discovery.py`는 Docker 응답을 모의해 네트워크 재생성·IP 변경·bridge 부재·조회 실패·수동 fallback·화면 표시·시작 전 재조회·캡처 필터·JSON 메타데이터 보존을 검증합니다. `test_network_capture.py`는 정상 stderr·0패킷·시작 예외·비정상 종료·PCAP 검증·비밀값 마스킹·UI와 저장을 확인하고, 캡처 실행을 흉내 내는 실제 자식 프로세스 → PCAP → Flow → 현재 모델 → JSON worker 경로도 검사합니다. 실제 Ubuntu dumpcap/Docker 실행, 정상 LMS/Hydra/DoS 트래픽 실험 및 실제 OpenAI 호출을 수행한 것은 아닙니다.
