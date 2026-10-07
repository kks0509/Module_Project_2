# Ubuntu에서 ROOKIES Scanner Web 실행

## 설치 및 웹 실행

배포 ZIP에는 소스, 설치/실행 파일과 외부 진단용 원본 CatBoost `final4.pkl` 모델이 포함됩니다. 다른 OS의 `.venv`를 복사하지 마세요.

```bash
unzip rookies-scanner-ubuntu.zip
cd rookies-scanner
bash setup-ubuntu.sh
bash start-app.sh
```

Ubuntu 22.04/24.04, Python 3.10 이상을 대상으로 합니다. 설치는 일반 사용자로 실행하고 시스템 패키지 설치만 sudo를 사용합니다. pip는 웹 앱 및 OpenAI SDK 의존성을 인터넷에서 내려받으므로 해당 서버에 PyPI 접근이 필요합니다. API 키가 없어도 진단·결과·이력 기능은 사용할 수 있습니다.

접속 주소: `http://127.0.0.1:8501`. 기본 서버는 Loopback에만 바인딩합니다. 작은 VM 화면에서는 브라우저 크기를 조절하거나 스크롤해 모든 설정과 결과를 확인할 수 있습니다. Tkinter 설치는 웹 실행에 필요하지 않습니다.

## 서버/SSH 환경

서버에 브라우저가 없어도 실행할 수 있습니다.

```bash
bash start-app.sh --server.headless=true
```

별도 PC에서는 SSH 포워딩으로 접속합니다.

```bash
ssh -L 8501:127.0.0.1:8501 USER@SERVER_IP
```

PC 브라우저에서 `http://127.0.0.1:8501`에 접속하세요. 진단 HTTP 요청은 서버에서 발생하므로 서버가 대상 LMS IP/포트에 접근할 수 있어야 합니다. Streamlit에는 사용자 인증을 별도로 구현하지 않았으므로 현재 실행 가이드는 로컬/SSH 접근을 사용합니다.

## OpenAI API 키

서버 프로세스 환경변수로 주입합니다. Bash에서 키를 화면이나 명령 기록에 직접 출력하지 않고 입력하려면:

```bash
read -rsp 'OpenAI API key: ' OPENAI_API_KEY
printf '\n'
export OPENAI_API_KEY
export OPENAI_MODEL=gpt-4o-mini
bash start-app.sh
```

또는 `cp .env.example .env`, `chmod 600 .env` 후 서버 편집기에서 값을 입력합니다. `.env`는 로컬 전용이며 Git/ZIP/Docker 이미지에 포함하지 않습니다. 기존 환경변수가 있으면 `.env` 값으로 덮어쓰지 않습니다. 브라우저에 키 입력란은 없습니다.

진단 완료 뒤 **AI 리포트 생성**을 눌러야만 Responses API를 호출합니다. 키 없음·접근 불가·호출 오류는 AI 영역에 표시하고 원본 결과는 유지합니다. 모델은 해당 API 계정에서 사용할 수 있는 Structured Outputs 지원 모델이어야 합니다.

## LMS 설정

- LMS가 별도 VM 또는 ZeroTier 경로에 있을 때: `http://10.163.130.121:5000`.
- Scanner와 LMS가 동일한 네이티브 호스트에 있을 때: `http://127.0.0.1:5000`.
- 관리자 및 학생 A/B 각각 입력, 비밀번호는 파일로 저장하지 않습니다.
- IDOR Query 기본 `/student/grades`, `student_id`, A=2/B=3, 마커 `CSE101`/`DB202`. 실제 환경의 GUI 입력값으로 바꿀 수 있습니다.
- 정상 검색어는 자동 추출 우선, 예비 검색어는 자동 추출 실패 시에만 사용합니다.
- 반복 인증/가용성 검사는 선택 및 별도 동의가 필요합니다.

입력 후 **대상 연결 확인** 또는 **진단 시작**으로 계정/설정을 일괄 제출하세요. 적용된 비밀번호는 현재 세션에서 메뉴를 바꾸거나 진단이 종료되어도 유지되며, 결과 JSON에는 저장되지 않습니다. 버튼 제출 전에 메뉴를 바꾸면 아직 제출하지 않은 수정값은 적용되지 않습니다.

로그인 Endpoint의 GET 응답이 `405`여도 `Allow: POST`가 있으면 정상입니다. 연결 확인의 일반 안내에는 `✓ 로그인 Endpoint 확인 · POST /login`만 표시하고 GET Status/Allow는 **연결 확인 · 상세 기술 데이터**에 보관합니다. 이 확인 과정에서 실제 비밀번호나 실패 로그인 요청은 전송하지 않습니다.

Endpoint/Marker의 진단 규칙 JSON은 사용자 화면에서 숨기고 내부 설정을 그대로 사용합니다. 결과 표의 파라미터는 자동 줄바꿈되며 작은 VM 화면에서는 표를 가로로 스크롤할 수 있습니다. AI 보고서의 DBMS 표시는 **MySQL 8.4**, 취약점 이름은 **SQL Injection**으로 구분됩니다. 기존 판정과 HTTP 요청 데이터는 유지합니다.

## 외부 공격 진단

기본 설치 후 `bash setup-external-ubuntu.sh`로 팀 모델 및 Flow 변환 패키지와 dumpcap을 설치합니다. 서버 실시간 수집에는 올바른 인터페이스와 비관리자 캡처 권한, `EXTERNAL_WEB_LOG_PATH` 설정이 필요합니다. 설치·권한·업로드/서버 수집·JSON 계약은 [EXTERNAL_INTEGRATION.md](EXTERNAL_INTEGRATION.md)를 확인하세요. API 키 없이도 외부 분류와 결과 저장을 사용할 수 있습니다.

## Docker (선택)

```bash
docker compose up --build
```

호스트 환경변수나 Git에서 제외한 `.env`를 Compose가 주입합니다. Dockerfile에는 키 값을 기록하지 않으며 `.dockerignore`가 `.env`를 빌드 컨텍스트에서 제외합니다. 호스트 접속 포트는 `127.0.0.1:8501`입니다. 보고서는 `scanner-reports` 볼륨에 저장됩니다.

컨테이너의 `127.0.0.1`은 컨테이너 자신입니다. LMS 대상에는 ZeroTier 또는 호스트의 실제 사설 IPv4 주소를 사용하세요. 이 MVP는 DNS 대상 진단을 받지 않습니다. 대상 네트워크 경로를 단순하게 유지하려면 네이티브 Ubuntu 실행을 권장합니다.

## 이력과 백업

`reports/SCAN-<uuid>/internal_report.json`에 각 진단을 저장하고 `ai_report.json`을 별도로 저장합니다. 진단 이력 메뉴에서 이전 결과와 AI 보고서를 볼 수 있습니다. 저장 실패 시 화면에서 JSON 다운로드를 제공하며 저장 오류를 표시합니다.

## 환경 확인과 테스트

```bash
.venv/bin/python doctor.py
.venv/bin/python -m unittest test_scanner test_idor_auth test_profile_identity test_web_reports test_web_inputs_connection test_ai_document test_lms_ui_polish -v
```

테스트는 외부 LMS나 유료 API를 호출하지 않습니다. 전체 GUI 회귀에는 `python3-tk` 및 디스플레이/Xvfb가 필요합니다. 실제 Ubuntu/Docker/LMS 및 OpenAI 라이브 호출은 별도 실습 환경에서 확인해야 합니다.
