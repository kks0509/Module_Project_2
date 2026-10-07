# ROOKIES Scanner

LMS Security Assessment Platform — Streamlit 기반 통합 웹 앱.

로그팀 원본 소스는 `vendor/log_team_optimization/`에 수정 없이 보존하고 별도 연결 코드에서 실행합니다. 연결 범위와 파일 위치는 [TEAM_INTEGRATION.md](TEAM_INTEGRATION.md)를 확인하세요.

제공된 `streamlit_app.py`는 수정 없이 **웹·네트워크 Dashboard** 메뉴에 연결했습니다.
사용법과 원본 위치는 [STREAMLIT_DASHBOARD_INTEGRATION.md](STREAMLIT_DASHBOARD_INTEGRATION.md)를 확인하세요.

외부 진단의 서버 수집은 **수집 인터페이스 직접 입력**에 원하는 이름을 입력합니다.
입력값을 자동 감지 값으로 덮어쓰지 않으며, 시작 전 존재 여부를 확인합니다.

허가된 LMS 실습 서버를 실제 HTTP 요청으로 진단하고, 같은 화면에서 규칙 기반 결과·상세 근거·검사 이력을 확인합니다. 진단이 완료된 뒤 **AI 리포트 생성**을 누르면 정제된 요약으로 한국어 보고서를 작성합니다. Scanner 판정과 AI 설명은 별도로 저장합니다.

## Ubuntu 빠른 시작

```bash
unzip rookies-scanner-ubuntu.zip
cd rookies-scanner
bash setup-ubuntu.sh
bash start-app.sh
```

브라우저에서 `http://127.0.0.1:8501`에 접속하세요. Python 3.10 이상, Ubuntu 22.04/24.04 기준 설치 스크립트를 제공합니다. 웹 실행에는 Tkinter나 그래픽 세션이 필요하지 않습니다. 자세한 서버/VM 실행과 API 설정은 [UBUNTU.md](UBUNTU.md)를 확인하세요.

Windows 개발 환경에서는 `python -m venv .venv`, `.venv\Scripts\python -m pip install -r requirements.txt`, `start-app.cmd` 순서로 실행합니다.

## 사용 흐름

1. **내부 취약점 진단**에서 대상 Origin, 관리자·학생 A/B 계정, 검사 항목과 IDOR 조건을 입력합니다.
2. 진단 권한 확인을 체크하고 **대상 연결 확인**으로 TCP/HTTP, 상태 코드, 응답시간, 로그인 Endpoint를 확인합니다.
3. **진단 시작**을 누릅니다. 초록색 진행률, 현재 모듈·세부 요청 번호를 표시하고 중지할 수 있습니다.
4. 결과 표와 확장 항목에서 요청/응답 근거, 원인, 대응 방안, OWASP를 확인하고 JSON을 다운로드합니다.
5. 필요할 때 **AI 리포트 생성**을 누릅니다. API 실패는 AI 영역에만 표시하고 원본 결과는 유지합니다.
6. **통합 Dashboard / AI 분석 리포트 / 진단 이력**에서 실행 결과를 확인합니다. **외부 공격 진단**은 로그/패킷을 수집하거나 업로드해 팀 정규식·CatBoost 모델로 분석합니다. Ubuntu 설치와 사용법은 [EXTERNAL_INTEGRATION.md](EXTERNAL_INTEGRATION.md)를 확인하세요.

외부 ML 분류가 팀 원본과 다를 때는 [ML_REGRESSION.md](ML_REGRESSION.md)의 오프라인 비교 도구로 동일 PCAP·동일 모델의 실제 Feature와 Flow별 예측을 비교합니다. 모델이나 라벨을 변경하지 않으며 기술 비교 파일을 LLM에 자동 전송하지 않습니다.

외부 패킷 수집은 **ZeroTier 인터페이스를 우선 자동 감지**하고 `tcp port 5000`으로 외부 접속 구간을 관찰합니다. ZeroTier 탐지 실패 시 Docker bridge와 `lms-web` IP를 보조 감지하며 둘 다 실패하면 수동 입력을 표시합니다. 화면과 진단 시작/캡처 직전에 재확인합니다. 원본 `external/models/final4.pkl`의 파일명·SHA-256을 검증한 뒤 직접 로딩하며 CBM으로 변환해 읽지 않습니다. Ubuntu 호스트의 dumpcap 권한이 필요하고 Docker 조회 권한은 보조 감지에서만 필요합니다.

웹 앱에는 설정 프로파일 저장/불러오기 기능을 제공하지 않습니다. 비밀번호는 브라우저의 비밀번호 입력 및 해당 서버 세션의 메모리에만 유지하며 설정·리포트 파일에 저장하지 않습니다.

계정·진단 설정은 **대상 연결 확인 / 진단 시작** 버튼으로 한 번에 제출합니다. 제출된 값은 메뉴 전환과 진단 중/완료 후에도 같은 Streamlit 세션에서 유지됩니다. 제출하지 않은 입력은 메뉴 전환 전에 위 버튼으로 적용하세요. 계정 검증과 Scanner는 동일한 제출 설정을 사용하며 누락된 경우 계정 역할과 필드명을 표시합니다. 비밀번호의 공백은 변경하지 않습니다.

연결 확인은 인증/실패 로그인 요청을 보내지 않습니다. `GET /login`의 `405` 응답에 `Allow: POST`가 있으면 POST 기반 로그인 Endpoint로 정상 처리하고 `✓ 로그인 Endpoint 확인 · POST /login`만 표시합니다. 원래 GET Status Code와 Allow는 **연결 확인 · 상세 기술 데이터**에 남기며 정상 결과의 일반 안내에는 노출하지 않습니다. 404/500, POST를 허용하지 않는 Allow, Allow 없는 405는 실패로 표시합니다. 일반적인 GET 200 로그인 페이지도 기존처럼 접근 가능한 Endpoint로 처리하며, POST 허용 여부를 헤더로 확인했는지는 별도 metadata에 기록합니다.

LMS 전용 웹 입력 화면에서는 Endpoint/Marker 규칙 편집과 진단 규칙 JSON을 숨깁니다. 내부 `profiles.py` 및 세션의 기존 규칙 설정은 그대로 엔진에 전달됩니다. 결과 표는 자동 줄바꿈을 지원하며 파라미터를 한 줄씩 표시합니다. 작은 화면에서는 표를 가로로 스크롤할 수 있고 파라미터/URL을 생략하지 않습니다.

내부 로그인 설정은 `POST /login`, `username_field: username`, `password_field: password`, 관리자 성공 경로 `/admin` 및 `LMS 관리자`/`ADMIN` 마커를 사용합니다. 구버전 프로파일에 빠진 로그인 설정만 기본값으로 보충하며, 명시적으로 지정한 경로와 마커는 유지합니다. 관리자·학생 A/B는 각각 독립 Session을 사용하며 입력 비밀번호는 마스킹하기 전 원래 값으로 해당 Session에 전달됩니다. 어떤 로그인 필드명에서도 저장 근거의 계정 값은 마스킹합니다.

학생 검색 SQL Injection 상세 결과에는 **Admin Authentication** 표와 `evidence.admin_authentication`이 포함됩니다. 로그인 Request URL/Method/Status/Redirect History/Final URL, 인증 성공 여부, 일치한 경로/마커 및 계정 입력 여부를 기록하며 비밀번호 값은 남기지 않습니다. `HTTP 200 → /login`이면 "로그인 페이지에 남아 있습니다"로 표시하고, 관리자가 인증되지 않으면 검색 요청을 보내거나 취약 판정을 강제로 올리지 않습니다. 이때 검색 HTTP/객체 수의 `None`은 미실행이며 로그인 Status와 구분해서 읽어야 합니다. 정상 인증 뒤에는 기존 Baseline/Attack 객체 집합 비교를 그대로 수행합니다.

입력 처리 방식 참고: [Streamlit forms](https://docs.streamlit.io/develop/concepts/architecture/forms), [위젯 값 유지](https://docs.streamlit.io/develop/concepts/multipage-apps/widgets).

## 기존 진단 범위

| 항목 | 방법 및 근거 | OWASP |
|---|---|---|
| SQL Injection 로그인 우회 | 실패 Baseline과 비교, `/admin` 이동 또는 관리자 마커 | A03:2021 Injection |
| SQL Injection 학생 검색 | 학생 A 본인 정보의 학번/이름 자동 추출 → 예비 검색어, 정상 객체 집합의 엄격한 확장 | A03:2021 Injection |
| Broken Access Control | 학생 A 세션으로 `/admin`, `/admin/students`, `/admin/grades`, `/admin/courses` 각각 검사 | A01:2021 Broken Access Control |
| IDOR | A/B 독립 세션, Query/Path 객체, 소유자 Baseline과 교차 접근의 마커/응답 비교 | A01:2021 Broken Access Control |
| 반복 인증 관찰 | 동일 계정 최대 5회 실패, 429/잠금/지연 및 정상 재로그인 확인 | A07:2021 Identification and Authentication Failures |
| 가용성 관찰 | 기준 3회 + 표본 12회, 동시성 2, 응답시간 통계 | 가용성 관련 관찰 항목 |

반복 인증·가용성은 기본 OFF, 별도 제한 검사 동의가 필요합니다. 가용성 판정은 항상 **관찰 필요 / INFO**입니다. 전체 요청 상한 100, 요청 간 간격, 연결/응답 시간 제한, 응답 표본 크기 제한, 동일 Origin 리다이렉트 검증을 유지합니다. 외부 영역은 수동적 로그/네트워크 관측이며 추가 능동 취약점 모듈이나 공격 프록시는 구현하지 않습니다.

대상은 숫자 형식 Loopback/RFC1918 IPv4만 받으며 `localhost`를 `127.0.0.1`로 정규화합니다. 예: `http://10.163.130.121:5000`, 같은 호스트에서 `http://127.0.0.1:5000`. 임시 Cloudflare Tunnel 및 공인 서버 주소는 진단 대상으로 사용하지 않습니다. 요청은 Streamlit **서버**에서 전송됩니다.

## AI 보고서 설정

서버 환경변수 `OPENAI_API_KEY`가 필요합니다. 선택적으로 `.env.example`을 `.env`로 복사하여 서버에서만 편집할 수 있습니다. 실제 키를 코드·JSON·화면·로그에 넣지 마세요. `.env`는 Git 및 Docker 빌드/배포 ZIP에서 제외됩니다.

```dotenv
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
```

`OPENAI_MODEL`은 Structured Outputs를 지원하며 계정에서 접근 가능한 모델로 바꿀 수 있습니다. API 호출은 명시적인 생성 버튼으로만 실행됩니다. `store=False`, 자동 재시도 없음, 요청 시간 제한 60초를 사용합니다. 요약 전송에 따른 API 비용이 발생할 수 있습니다.

LLM 입력은 URL/Method/파라미터명/원본 판정/위험도/OWASP와 상태·마커·객체 수·가용성 통계 등 선택한 근거입니다. 전체 디버깅 로그, 원시 응답 본문, 실제 계정 비밀번호·쿠키·토큰·Authorization·API Key는 전송하지 않습니다. 필드 마스킹과 실제 입력 비밀번호 마스킹을 적용합니다.

Responses API의 엄격한 JSON Schema로 `summary`, `findings`, `overall_assessment`를 요청하며 finding_id를 원본 항목과 연결합니다. AI 파일에는 설명만 추가합니다. 표의 판정·위험도·URL·Method 등은 항상 Scanner 원본에서 렌더링합니다. AI 설명의 사실 적합성은 원본 근거와 함께 검토하세요.

공식 API 구현 근거: [Responses Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses).

### AI 보고서 문서 화면

현재 LMS의 **DBMS는 MySQL 8.4**이며, 취약점 이름은 **SQL Injection**입니다. 새 Scanner/AI JSON과 문서 헤더에 `dbms: MySQL 8.4`를 기록합니다. 프롬프트는 이 구분을 명시하며, 저장/표시 단계에서도 설명 필드의 약어를 풀어 씁니다. 원본 요청 URL·Payload·Marker·파라미터·HTTP 상태·판정·위험도 및 호환용 모듈 식별자 `sqli`는 문자열 치환 대상이 아닙니다. 과거 JSON 파일은 화면을 열었다고 덮어쓰지 않습니다. 외부 source에 DBMS 정보가 없으면 미제공으로 표시합니다.

프롬프트 지침 참고: [OpenAI 공식 Prompt engineering](https://developers.openai.com/api/docs/guides/prompt-engineering).

AI 분석 리포트는 흰색 문서 영역에서 **진단 개요 → 결과 요약 → 번호가 있는 상세 결과 → 종합 분석 → 종합 대응 권고** 순서로 연속해서 읽습니다. 상단 목차를 누르면 해당 Section 또는 `3.1`, `3.2` 항목으로 이동합니다. 좁은 VM 화면에서는 여백이 줄어들고 본문이 화면 폭에 맞춰 표시됩니다.

상단 Scan ID/대상/시각/요청 수, 집계, 항목의 제목·위험도·OWASP·판정·URL·Method·파라미터·진단 결과·HTTP 근거는 Scanner 원본에서 가져옵니다. AI 설명과 종합 의견은 별도로 표시하며 원본을 덮어쓰지 않습니다. Scan ID 또는 source가 다르면 서로 다른 보고서를 섞어 표시하지 않습니다.

종합 대응 권고는 기존 AI `remediation`의 줄 단위 문구를 공백·목록 기호·대소문자를 정규화해 중복 제거하고 관련 항목 번호를 함께 표시합니다. 취약 확인된 항목을 원본 위험도 순으로 먼저 배치한 뒤 관찰/기타 항목을 표시합니다. 의미가 비슷하지만 문구가 다른 권고는 임의로 합치지 않습니다. 추가 API 요청이나 분석 규칙/프롬프트 변경은 없습니다.

본문은 펼쳐진 문서이며 **상세 기술 데이터**만 expander로 표시합니다. JSON 다운로드와 기존 생성/실패 처리도 유지합니다. Scanner와 AI 문자열은 HTML로 해석하지 않고 이스케이프하며 JavaScript는 사용하지 않습니다. 렌더링 API 참고: [Streamlit st.html](https://docs.streamlit.io/develop/api-reference/text/st.html).

외부 보고서의 **⑤ 진단 근거**는 원본 Flow 수·분류별 수·평균 모델 점수 또는 웹 패턴 일치 요청을 짧은 자연어 문장으로 표시합니다. 웹 로그가 없거나 교차 검증 결과가 기록되지 않은 경우도 구분합니다. 본문에서는 내부 식별자/원문 key=value 나열과 클래스별 JSON 객체를 숨기고, **상세 기술 데이터**에 원본 근거와 AI JSON을 유지합니다. 이전 AI 설명에 섞인 메타데이터 나열도 표시 단계에서 숨기므로 API 재생성 없이 기존 이력에 적용됩니다. 상단 Scan ID와 원본 판정·위험도·JSON 다운로드는 유지합니다.

ML이 공격 클래스로 분류한 Flow는 해당 유형의 **공격 패턴이 관찰됨**으로 설명하며, 실제 분류 비율과 평균 모델 점수를 함께 표시합니다. 예를 들어 339개 중 281개 BRUTE FORCE는 82.9%로 표현합니다. 다수 Flow와 높은 점수는 해당 공격 유형일 가능성을 뒷받침하는 근거로 해석하지만 모델 점수를 공격 성공 확률로 바꾸지 않습니다. 적은 Flow/낮은 점수는 높은 가능성으로 과장하지 않습니다. BENIGN만 있거나 분석 자료가 없는 경우 공격 패턴을 만들어내지 않습니다.

외부 LLM 프롬프트의 **4. 종합 분석**은 탐지된 공격 유형과 관찰 규모를 분명하게 설명하도록 하고, **5. 종합 대응 권고**는 BRUTE FORCE의 Rate Limiting·계정 잠금·인증 실패 모니터링, DOS의 요청/동시 연결 제한·가용성 모니터링 등 유형별 조치를 권고하도록 했습니다. 실제 공격 성공은 웹 인증 로그·성공 응답·세션 발급 등의 추가 근거로 판단합니다. 이러한 근거가 없으면 계정 탈취·비밀번호 유출·시스템 침해가 확인되었다고 서술하거나 비밀번호 변경/침해 대응이 반드시 필요하다고 단정하지 않도록 지시합니다. 출력 지침과 예시는 [OpenAI 공식 Prompt engineering](https://developers.openai.com/api/docs/guides/prompt-engineering)에 따라 명확하게 구분했습니다.

기존 AI 보고서의 원문은 덮어쓰지 않습니다. ⑤의 자연어 표시와 메타데이터 숨김은 기존 보고서에도 바로 적용됩니다. **4·5의 새로운 LLM 해석은 AI 리포트 생성 버튼으로 다시 생성할 때 적용**됩니다. Scanner/ML 원본 판정·모델 점수·모델 파일·수집 파이프라인·내부 진단 로직은 변경하지 않습니다. LLM 지침 전달과 화면 출력은 모의 Responses API로 검증하며 실제 모델의 문장 준수는 생성된 보고서와 원본 근거를 함께 검토하세요.

## 결과 파일과 연동 계약

```text
reports/
  SCAN-<uuid>/
    internal_report.json
    ai_report.json            # 생성 또는 오류 상태
```

원본 결과 상단과 각 finding에 동일한 `scan_id`, `source: internal`을 기록합니다. JSON의 UTC 시간은 화면에서 KST로 표시합니다. AI 보고서는 같은 Scan ID를 가지는 별도 파일이며 원본을 덮어쓰지 않습니다. 중지된 진단도 부분 결과와 종료 상태로 저장합니다.

외부 파이프라인은 `source: external` 원본을 `reports/SCAN-<id>/external_report.json`에, WEB/NETWORK 분류 입력을 `pipeline_input.json`에 저장합니다. 별도 버튼으로 같은 Scan ID의 `ai_report.json`을 생성합니다. 공통 이력 및 AI 문서는 외부 source도 지원합니다. Dashboard는 내부와 외부를 각각 집계하며 내부 화면에 외부 결과를 섞지 않습니다. 이전 데스크톱 Scan JSON도 이력에서 읽을 수 있습니다.

## 코드 구조

- `app.py`, `ui/`: 통합 화면, 입력, 결과/AI 렌더링.
- `external/`, `ui/external_scan.py`: 팀 수집/파싱, Flow 변환, 제공 모델 분류, 외부 JSON 및 별도 LLM 설명. 설치는 `setup-external-ubuntu.sh`.
- `ui/ai_document.py`, `ui/ai_document.css`: 원본 Scan에 연결된 연속 문서, 목차, 중복 권고 정리와 보고서 스타일.
- `web_tasks.py`: 사용자 세션별 worker·queue·중지 제어. worker에서 Streamlit UI 호출 없음.
- `engine.py`, `auth.py`, `sqli_checks.py`, `scanner_checks.py`: 기존 실제 진단 엔진 및 규칙.
- `profile_identity.py`, `student_objects.py`, `profiles.py`: 자동 검색어 획득, 객체 추출, 설정 가능한 조건.
- `connection_check.py`: 진단과 분리된 제한된 연결 확인.
- `report_store.py`, `sanitizing.py`: 정규화, Scan별 저장, 이력, 민감정보 제거.
- `llm/client.py`, `llm/report_generator.py`, `llm/prompts.py`: 서버 SDK, 요약/Schema/API, 보고서 원칙.

이전 `desktop_app.py`, `report_app.py`, `server.py`는 호환 및 기존 회귀 확인을 위해 남겼습니다. 기본 실행 파일과 설치 가이드는 **통합 웹 앱**을 실행합니다. 웹에서는 이전 프로파일 기능을 사용하지 않습니다.

## 검증

```bash
.venv/bin/python -m unittest test_scanner test_idor_auth test_profile_identity test_web_reports test_web_inputs_connection test_ai_document test_lms_ui_polish test_admin_search_auth -v
# 외부 모듈 설치 후 로그/ML/JSON/AI 통합 검사
.venv/bin/python -m unittest test_external test_docker_discovery test_network_capture -v
```

전체 이전 GUI 회귀 테스트도 실행하려면 Tkinter와 디스플레이가 필요합니다. Ubuntu에서는 `sudo apt-get install python3-tk xvfb` 후 `xvfb-run .venv/bin/python -m unittest -v`를 사용할 수 있습니다.

회귀 테스트는 로컬 HTTP fixture, Streamlit AppTest와 모의 Responses API를 이용합니다. 2026-10-06에는 웹 입력 → worker → 실제 LMS `10.163.130.121:5000`의 SQL Injection 두 항목을 17개 요청으로 추가 확인했습니다. 관리자 로그인은 `302 → /admin`, 인증 성공 True이며 학생 검색은 HTTP 200, 정상/공격/추가 객체 수 1/2/1, 두 항목 모두 취약 확인/HIGH였습니다. 사용자가 보고한 `200 → /login` 관리자 거부는 이 실행에서는 재현되지 않았습니다. 이 확인은 Ubuntu 브라우저/Docker 실행이나 유료 OpenAI API 호출 성공을 의미하지 않습니다.
