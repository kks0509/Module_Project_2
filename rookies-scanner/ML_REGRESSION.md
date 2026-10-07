# 외부 NETWORK 분류 regression 비교

비교 도구는 모델·판정·라벨 매핑을 바꾸지 않고 원본과 이식본의 입력을 비교합니다. 현재 서버 수집은 요청에 따라 ZeroTier를 우선 사용하며, 런타임 모델 로딩은 원본 final4.pkl로 복원했습니다. BRUTE FORCE를 DOS로 치환하거나 Feature를 임의 보정하지 않습니다. 내부 취약점 진단과 LLM 호출도 변경하지 않습니다.

## 현재 확인 결과

전달된 로그팀 ZIP의 기존 PCAP 표본을 **같은 파일**로 두 변환 함수에 입력했습니다. 이 파일이 사용자가 언급한 Slowloris 실험 파일이라는 근거는 없습니다. 원본 코드에 예시로 적힌 `capture_00002_20261006104312.pcap`은 제공 ZIP에 포함되어 있지 않습니다.

| 비교 항목 | 원본 코드 | Scanner 코드 | 결과 |
|---|---|---|---|
| PCAP → CSV | create_sniffer / AsyncSniffer | PcapReader / FlowSession | 23 Flow, 82 컬럼; 값·순서·dtype 동일 |
| 컬럼 매핑 | 원본 MAPPING | external.feature_mapping.MAPPING | 동일 |
| CatBoost 실제 입력 | model.feature_names_ 선택 | 같은 목록 선택, numeric 변환 | 23 × 62; 값·순서·dtype 동일 |
| final3 예측 | BENIGN 0 / BRUTE FORCE 18 / DOS 5 | BENIGN 0 / BRUTE FORCE 18 / DOS 5 | Flow별 라벨·확률 동일 |
| final4 예측 | BENIGN 0 / BRUTE FORCE 18 / DOS 5 | BENIGN 0 / BRUTE FORCE 18 / DOS 5 | Flow별 라벨·확률 동일 |

원본 변환 CSV와 Scanner 변환 CSV를 각각 원본/Scanner 예측 함수에 넣는 **2 × 2 교차 비교**도 동일했습니다. 원본 final3.pkl의 CBM1 데이터와 보관된 final3.cbm의 SHA-256은 `8ebcd14290788bd2cad391601a1f42611bf279aa363d86efdd3c0dd817d50985`로 일치합니다.

두 번째 표본 `capture_00151_20261006075340.pcap`도 비교했습니다. 345 패킷 → 22 Flow·82 컬럼 → 22 × 62 Feature이며 두 모델 모두 원본과 Scanner에서 BENIGN 0 / BRUTE FORCE 21 / DOS 1로 일치했습니다. 이 표본 역시 Slowloris 정답 라벨이 제공되지 않았습니다. 첫 표본은 132 패킷입니다.

이 결과는 제공 표본에서의 입력·예측 일치를 확인합니다. 해당 Slowloris PCAP, 실제 Ubuntu 환경, 다른 캡처 위치의 영향까지 확인한 결과는 아닙니다. 현재 프로젝트의 기본 모델은 원본 final4.pkl이며, 비교 도구의 모델 지정은 운영 설정을 바꾸지 않습니다.

## Ubuntu에서 문제가 발생한 동일 PCAP 비교

`ml-regression-toolkit.zip`은 기존 프로젝트 폴더에 압축 해제하는 추가 파일 묶음입니다. `external/compare_pipeline.py`, 이 안내문, 비교 테스트만 들어 있으며 기존 config·manifest·모델·진단 모듈을 덮어쓰지 않습니다.

프로젝트 폴더에서 실행합니다. `--pcap`에는 원본 파이프라인에서 DOS로 분류됐던 파일 하나를 지정하세요. 원본 `final_test.py`는 팀이 제공한 신뢰하는 코드여야 합니다.

```bash
.venv/bin/python -m external.compare_pipeline \
  --pcap /home/lms/slowloris.pcap \
  --team-script /home/lms/log_team/pipeline/tools/final_test.py \
  --team-model /home/lms/log_team/pipeline/final4.pkl \
  --scanner-model /home/lms/rookies-scanner/external/models/final4.pkl \
  --output /home/lms/ml-regression-final4
```

경로는 실제 위치로 바꾸세요. 출력 폴더는 새 폴더를 지정하며 기존 출력은 덮어쓰지 않습니다. final3 비교 시 원본 final3.pkl과 같은 모델 파일을 비교용으로 지정하고 새 출력 폴더를 사용합니다. 원본 pkl은 직접 객체를 복원하며 CBM은 보관된 참조 모델과의 호환성 비교에만 선택할 수 있습니다. **두 모델의 native SHA-256이 같아야 이식 차이를 판단할 수 있습니다.** 두 환경이 다른 서버라면 같은 PCAP·원본 스크립트·모델로 각 서버에서 실행하고 환경 버전과 출력 파일을 비교합니다.

최대 16 MB / 20,000 패킷 및 Flow, 각 자식 프로세스 60초 제한을 유지합니다. 제한 초과 시 기록하고 중단하며 몰래 잘라서 분석하지 않습니다. 빈 CSV는 `empty`로 표시합니다. 네트워크 연결, 공격 생성, 실시간 캡처, API 호출 없이 로컬 파일만 사용합니다.

## 출력 파일

- `comparison.json`: 입력 PCAP hash, 패킷 요약, 현재 패키지 버전, 원본 requirements의 선언 버전, 모델 hash, 변환·입력·예측 비교. `scanner_runtime_model`은 실제 앱 설정의 모델/manifest 일치 여부와 비교용 override 여부를 표시합니다. `primary_inputs`, `primary_predictions`는 원본 전체 경로와 Scanner 전체 경로의 실제 입력/예측 비교이며, `comparison_conclusion`은 확인된 차이의 단계만 요약합니다.
- `original-raw.csv`, `scanner-raw.csv`: 두 변환 함수가 실제 생성한 CSV.
- `original-on-original/`, `scanner-on-original/`, `original-on-scanner/`, `scanner-on-scanner/`: 원본/Scanner 예측 함수를 각각 두 CSV에 적용한 결과.
- 각 폴더의 `trace.json`: 실제 모델 경로와 hash, model feature names, 입력 컬럼·순서·shape·dtype, 첫 Flow의 Feature 값, NaN/inf 수, predict 결과, predict_proba 결과, 클래스 순서, 실제 호출 인자.
- `before-predict.json`: 입력 검증 단계에서 실패해도 확인할 수 있는 원본 컬럼과 Feature 미리보기. 실제 CatBoost 전달값은 `trace.json`으로 확인합니다.
- `renamed.csv`, `features.csv`, `predictions.csv`: 중간 컬럼 매핑, 실제 모델 입력, Flow별 Predicted_Label·클래스 확률.
- `feature-statistics.csv`: 각 Feature의 평균·분포·50/90/95 백분위수. 서로 다른 캡처 위치의 Feature 분포를 비교할 때 사용합니다.
- `*.log`: 변환/추론 자식 프로세스의 원문 기술 로그.

PCAP/Feature에는 네트워크 주소 등이 포함될 수 있으므로 이 파일들은 상세 기술 비교용으로 보관합니다. 일반 보고서 본문이나 LLM에 자동 전송하지 않습니다.

원본 파일 전체를 import하지 않고 MAPPING과 세 helper 함수만 불러 실행하므로 원본 경로 생성·삭제·ML_analyze 호출 등의 최상위 부작용을 실행하지 않습니다. pkl을 선택하면 **원본 pickle 객체를 직접 복원하여** 원본/Scanner 예측 함수에 전달합니다. 전달된 팀의 신뢰하는 모델 파일만 지정하세요. 내부 CBM1 hash 추출은 가중치 일치 확인용이며 런타임 저장 형식을 바꾸지 않습니다. CBM 참조 파일을 명시적으로 선택한 경우에만 네이티브 로더를 사용합니다. 원본이 현재 제공된 CatBoostClassifier 대신 별도 preprocessing wrapper를 사용하도록 바뀌었다면 그 변경도 별도로 확인해야 합니다.

## 원본과 이식본의 코드 차이

1. 원본은 create_sniffer의 주기적 wall-clock GC를 시작하고 종료 시 중단합니다. Scanner는 동일 FlowSession에 파일의 패킷을 순차 전달하며 packet-time 기반 GC와 마지막 flush를 사용합니다. 오래된 PCAP을 처리하는 시간이 GC 주기보다 길면 원본의 GC 타이밍에 따라 Flow 분할이 달라질 여지가 있습니다. 현재 표본에서는 차이가 없었고 Slowloris 원인으로 확정하지 않습니다. 동일 파일 반복 실행에서 raw CSV가 달라지는지 확인합니다.
2. 원본 rename_columns는 timestamp와 MAPPING 키만 유지합니다. Scanner는 다른 컬럼도 정규화 단계까지 유지하지만 모델 직전에는 같은 feature_names_만 선택합니다. 실제 입력에 차이가 있는지는 features.csv로 판단합니다.
3. Scanner는 숫자 변환 후 NaN/inf를 거부합니다. 원본은 추가 변환·fillna·inf 치환 없이 모델에 전달합니다. 둘 다 유효한 숫자인 현재 표본의 dtype와 값은 동일합니다. 오류 값이 있는 파일에서는 판정 실패와 예측 차이를 구분합니다.
4. 원본 predict/predict_proba는 기본 thread 설정, Scanner는 thread_count=2입니다. 현재 표본의 Flow별 확률까지 동일합니다.
5. 두 코드 모두 model.classes_의 순서로 확률을 매핑하고 predict의 라벨을 그대로 사용합니다. BRUTE FORCE↔DOS 치환은 없습니다.
6. 원본 requirements는 pandas 3.0.5이며 이번 비교 환경은 3.0.6입니다. CatBoost 1.2.10, CICFlowMeter 0.5.0, Scapy 2.7.0, NumPy 2.5.3은 선언 버전과 같습니다. 실제 서버 버전은 그 서버의 comparison.json으로 확인해야 합니다.

## 캡처 위치와 구간 비교

동일 PCAP의 raw CSV와 features.csv와 예측이 같다면 다음으로 **동일 시간대의 두 캡처 파일**을 비교합니다. 팀이 정상 DOS 분류를 확인한 ZeroTier 캡처와 기존 Docker bridge 캡처를 각각 위 도구에 입력해 Flow 수, 지속 시간, IAT, 패킷 길이, 방향별 패킷 수, TCP window, 클래스별 수를 비교하세요. 패킷 발생 부하는 새로 생성하지 않아도 기존 허가된 실험의 PCAP을 사용할 수 있습니다.

전달된 ZIP의 자동 수집 코드는 물리 인터페이스를 선택하고 300초 ring-buffer를 기본으로 하지만, 사용자가 정상 분류를 검증한 수집 지점은 ZeroTier입니다. 현재 Scanner도 ZeroTier의 `tcp port 5000`을 우선 사용합니다. ZeroTier가 없을 때만 Docker bridge의 `host <현재 lms-web IP> and tcp port 5000`으로 보조 수집하며 UI와 JSON에 이를 명시합니다. 5–120초·20,000패킷·16MB 조건은 유지됩니다. 실제 사용한 시간은 각 실행의 수집 메타데이터로 확인합니다.

브리지의 proxy→web 연결과 물리 인터페이스의 client→proxy 연결은 별도 TCP 연결일 수 있습니다. Reverse Proxy가 있다면 느린 클라이언트 연결이 backend에 같은 형태로 보이지 않을 수 있고, 짧은 캡처 구간은 긴 연결의 일부만 남길 수 있습니다. 이 경우 Flow 특성이 달라질 가능성이 있지만 **두 PCAP 없이 원인으로 단정하지 않습니다.** PCAP만으로 정확한 캡처 인터페이스/BPF를 항상 복원할 수 없으므로 수집 시 실제 인터페이스·필터·시작/종료·패킷 수·모델 hash도 기록합니다.

판별 순서는 `같은 모델 → 같은 PCAP → raw CSV → 실제 62개 Feature → Flow별 라벨/확률 → 서로 다른 캡처 PCAP`입니다. 단계 중 차이가 생긴 첫 위치를 원인 조사 대상으로 삼습니다.
