# 외부 NETWORK 모델 검증 — final4

현재 런타임 모델은 제공된 **원본 `final4.pkl`**입니다. 원본 바이트를 변경하지 않고 `external/models/final4.pkl`에 배포하며 파일명·SHA-256 확인 후 pickle 객체를 직접 복원합니다. 62개 특징 이름/순서와 BENIGN / BRUTE FORCE / DOS 클래스의 호환성을 확인했습니다. 모델 로딩 경로는 `external/config.py`의 `MODEL_PATH`입니다. 다른 모델/CBM으로 자동 fallback하지 않습니다. 이전 CBM은 런타임 폴더와 배포에서 제외했습니다.

- 원본 SHA-256: `dce2942e13f16e6c761601d6e36348f3398faa5b4287ab8e141eed9dd59ef0e6`
- 현재 런타임 SHA-256도 원본과 동일합니다. 네이티브 형식과의 예측 비교는 모델 내용을 변경하지 않은지 확인하는 오프라인 검증에만 사용합니다.

## 제공 Flow 표본 재분류

기존 로그팀 ZIP의 `test_prediction.csv` 20개 Flow를 현재 모델로 다시 추론했습니다. 표본의 `Predicted_Label`은 이전 모델의 예측값이며 실제 공격 여부의 정답 라벨이 아닙니다.

| 기존 표본 Predicted_Label | 현재 BENIGN | 현재 BRUTE FORCE | 현재 DOS |
|---|---:|---:|---:|
| BENIGN | 1 | 0 | 0 |
| BRUTE FORCE | 0 | 3 | 1 |
| DOS | 0 | 0 | 15 |

현재 출력은 BENIGN 1, BRUTE FORCE 3, DOS 16입니다. 세 클래스의 예측·모델 점수·Flow 집계 출력과 JSON 저장을 확인했습니다. 한 표본은 BRUTE FORCE에서 DOS로 달라졌습니다. 이 표본만으로 정상 트래픽 오탐률 개선이나 실제 Hydra/DoS 탐지 성능을 확정할 수 없습니다.

제공 ZIP의 PCAP도 실제 Flow 변환을 거쳐 23개 Flow를 분류했습니다: BENIGN 0, BRUTE FORCE 18, DOS 5. 빈 CSV → 이 PCAP → 위 CSV 순서로 입력했을 때 빈 CSV만 Skip되고, 두 정상 입력의 43개 Flow와 모델 파일명/hash가 동일 Scan ID의 NETWORK JSON·이력에 보존됐습니다. AI 연동은 실제 API 호출 대신 모의 응답으로 확인했습니다.

## 원본 pkl 복원 및 ZeroTier 수집 변경 검증

배포 pkl 파일은 사용자 Downloads의 원본과 byte-for-byte 동일합니다. 원본 pickle 객체를 직접 로딩한 뒤 기존 네이티브 참조와 Feature 목록·클래스·예측·확률을 비교했습니다. 실제 제공 PCAP 두 개의 모든 Flow에서도 기존 CBM의 라벨/확률과 정확히 일치했습니다: 23 Flow는 BRUTE FORCE 18 / DOS 5, 22 Flow는 BRUTE FORCE 21 / DOS 1입니다. 두 파일은 Slowloris 실험이라고 확인된 파일이 아니므로 실제 공격 유형의 정답 검증에는 사용하지 않습니다.

원본 helper와 Scanner 함수를 같은 pkl·같은 PCAP으로 교차 실행한 결과도 Feature 값·dtype·순서·예측·확률이 같았습니다. 수집 지점은 요청에 따라 ZeroTier 우선 / Docker bridge 보조 / 수동 fallback으로 바꾸었습니다. 모의 Linux 인터페이스로 우선순위·시작 전 재감지·실제 dumpcap BPF·빈 PCAP 처리·UI·저장 metadata를 검증했습니다. 실제 Ubuntu ZeroTier 인터페이스에서의 수집 및 Slowloris DOS 재분류는 이 작업 환경에서 실행하지 않았습니다.

## 서버에서 추가 확인할 항목

허가된 실습 서버에서 정상 LMS 사용, 팀의 기존 반복 로그인 실험, 기존 DoS 실험을 **각각 별도 시간대와 Scan ID**로 수집해 비교합니다. 추가 공격 부하를 Scanner가 자동 발생시키지는 않습니다. 각 실행의 패킷 수·Flow 수가 0보다 큰지, `model_file: final4.pkl`, `model_format: pickle`과 위 원본 hash가 기록됐는지, `class_counts`, `class_probabilities`, `attack_probability`, `detected_types`를 확인합니다. 수집은 ZeroTier의 `tcp port 5000`을 우선 사용하고, Docker bridge fallback이면 관찰 지점 차이를 메타데이터에서 확인합니다.

정상 사용의 BENIGN 분류, 반복 로그인의 BRUTE FORCE 분류, DoS의 DOS 분류가 실제 시간대 로그와 일치하는지 검증해야 합니다. 0개 패킷/빈 Flow는 BENIGN 판정이 아니라 분석 자료 없음입니다. 모델 점수는 전체 Flow의 클래스별 평균이며 공격 성공 확률이 아닙니다.

현재 작업 환경에서는 실제 Ubuntu Docker/dumpcap 수집과 위 세 종류의 실시간 서버 실험을 수행하지 않았습니다. 수집 오류·정상 stderr·빈 패킷의 처리는 모의 캡처와 실제 자식 프로세스/PCAP/Flow/모델/JSON 경로로 검증합니다. 실제 OpenAI API 호출도 수행하지 않았습니다.
