# Module Project 2 — ML팀

네트워크 트래픽 데이터를 분석 => 공격 유형을 탐지하는 머신러닝 모듈

PCAP 파일에서 네트워크 Flow 특성을 추출하고, 학습된 CatBoost 모델로 공격 유형을 예측한 뒤 결과를 JSON 형식으로 저장

## 주요 기능

- PCAP 파일을 CICFlowMeter 형식의 Flow 데이터로 변환
- CICIDS2017 데이터 컬럼 형식으로 전처리
- CatBoost 모델을 이용한 네트워크 공격 유형 예측
- 클래스별 예측 확률 계산
- LLM 연동을 위한 NETWORK JSON 결과 생성

```
## 프로젝트 구조

🌟 - 프로젝트 연결에 필요한 파일
나머지 파일: 데이터 전처리, 모델 실험 및 학습 과정에 사용한 파일
.
├── 🌟final_test.py          # PCAP 변환 및 모델 예측 실행
├── 🌟result_exporter.py     # 예측 결과를 JSON으로 저장
├── 🌟final3.pkl             # 학습된 CatBoost 모델
├── requirements.txt         # Python 패키지 목록
├── apply.ipynb              # 모델 적용 실험
├── convert.ipynb            # 데이터 변환
├── final_merge.ipynb        # 데이터 병합
└── 모델_선정/                # 모델 선정 과정
    ├── feature_selection_pipeline.py
    │   └── 모델 학습에 사용할 주요 특성 선택
    │
    ├── model_selection.ipynb
    │   └── 여러 모델의 성능 비교 및 최종 모델 선정
    │
    └── process_attacks.py
        └── 공격 데이터 전처리 및 학습용 데이터 생성
