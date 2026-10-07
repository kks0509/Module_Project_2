# streamlit_app.py 원본 UI 통합

전달받은 `streamlit_app.py`는 아래에 바이트 단위로 그대로 보관합니다.

`vendor/streamlit_dashboard/streamlit_app.py`

원본 Downloads 파일 및 위 복사본을 수정하지 않습니다. `manifest.json`의 SHA256을
실행 및 배포 시 확인하며, ZIP에도 원본의 줄바꿈을 그대로 유지합니다.

## 앱에서 열기

기존처럼 `bash start-app.sh`로 앱을 실행한 뒤 **웹·네트워크 Dashboard** 메뉴를 선택합니다.
외부 진단의 현재 결과 또는 저장된 검사 이력을 Scan ID로 선택할 수 있습니다.

결과 화면은 다음과 같습니다.

- 통합 Dashboard
- 웹 공격 진단
- 네트워크 공격 진단
- 분석 결과 문서
- 진단 이력

외부 진단 결과가 없으면 기존 **외부 공격 진단** 메뉴에서 파일을 업로드하거나
수집을 실행합니다. 화면의 **원본 진단 JSON 다운로드**로 기존 원본 결과를 저장하고,
**상세 기술 근거 / Raw Evidence**에서 JSON을 확인할 수 있습니다.

## 연결 방식

`ui/team_dashboard.py`가 원본 함수 및 CSS/분류 상수를 읽어 실행합니다.
함수 본문은 변경하지 않습니다. 원본의 독립 실행용 `set_page_config`, Sidebar 메뉴,
고정 JSON 경로 및 최상위 화면 실행은 실행하지 않습니다. 기존 앱의 메뉴와
ReportStore 결과를 연결 코드에서 공급합니다. 환경변수를 세션마다 변경하거나
Downloads의 JSON 파일을 자동으로 읽지 않습니다.

원본 normalize_web, page_dashboard, page_source, page_report, page_history 등을 사용합니다.
NETWORK 결과는 기존 Scanner의 위험도를 명시한 레코드로 공급하므로
원본 normalize_network의 모델 점수 기반 위험도 재계산은 수행하지 않습니다.
클래스별 Flow 수, 모델 점수, 판정, 위험도 및 Scan ID를 변경하지 않습니다.

연결 코드의 렌더링 경계에서 모델 점수 표제와 정적 문서 제목을 표시 용도에 맞춥니다.
이 문서는 원본 템플릿의 분석 결과 문서이며, OpenAI 리포트 생성은 기존
**AI 분석 리포트** 메뉴의 별도 버튼으로 유지합니다. 새 화면을 열어도 API를 호출하지 않습니다.
원본 문서 내용과 원본 파일을 저장하거나 재작성하지 않습니다.

사용자용 진단 근거는 기존 자연어 요약을 공급하고 내부 식별자는 상세 기술 영역에 유지합니다.
민감정보는 기존 sanitize를 적용합니다. 수집 실패/빈 자료는 BENIGN으로 만들지 않습니다.
WEB/NETWORK 탐지 항목 수는 Flow 수와 별개의 화면 레코드 수입니다.

내부 진단, ZeroTier 수집, 원본 로그팀 코드, final4.pkl 모델, JSON/LLM 파이프라인은 유지합니다.
실제 Ubuntu 서버 수집 및 실제 OpenAI API 요청은 이 UI 통합의 로컬 테스트에 포함하지 않습니다.
