# pcap -> cicflowmeter -> CICIDS2017 컬럼명 매핑 -> 모델 예측
import os
import re
import pickle
from pathlib import Path

import pandas as pd
from pandas.errors import EmptyDataError
import scapy.sendrecv as sr

from .result_exporter import save_prediction_json

from cicflowmeter.sniffer import create_sniffer

# Windows에서 외부 tcpdump 호출을 막는 기존 우회 코드
sr.tcpdump = lambda fname, *args, **kwargs: open(fname, "rb")

MAPPING = {
    "dst_port": "Destination Port",
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "cwr_flag_count": "CWE Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",
    "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
}


# pcap 파일을 cicflowmeter로 변환해 원본 flow CSV 생성
def pcap_to_csv(pcap_path, csv_path):
    sniffer, session = create_sniffer(
        input_file=str(pcap_path),
        input_interface=None,
        output_mode="csv",
        output=str(csv_path),
        input_directory=None,
        fields=None,
        verbose=False,
    )

    sniffer.start()
    try:
        sniffer.join()
    finally:
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        sniffer.join()
        session.flush_flows()

# 파일 로드
def load_data(file_path):
    file_path = Path(file_path)

    print("\n========== load_data DEBUG ==========")
    print(f"[DEBUG] CSV 경로: {file_path}")
    print(f"[DEBUG] 파일 존재 여부: {file_path.exists()}")

    if not file_path.exists():
        print(f"[!] CSV 파일이 존재하지 않습니다: {file_path}")
        return None

    file_size = file_path.stat().st_size
    print(f"[DEBUG] 파일 크기: {file_size} bytes")

    if file_size == 0:
        print("[*] CSV 파일이 비어 있습니다.")
        print("[*] 분석 가능한 Flow가 없어 이번 캡처를 건너뜁니다.")
        return None

    try:
        df = pd.read_csv(file_path)

    except EmptyDataError:
        print("[*] CSV에 분석 가능한 데이터가 없습니다.")
        return None

    if df.empty:
        print("[*] Flow 데이터가 없습니다.")
        return None

    df.columns = df.columns.str.strip()

    print(f"[DEBUG] 행 수: {len(df)}")
    print(f"[DEBUG] 컬럼 수: {len(df.columns)}")
    print("=====================================\n")

    return df

# cicflowmeter 컬럼명 -> CICIDS2017 컬럼명
def rename_columns(df):
    # Flow 시작 시간은 모델 입력에는 사용하지 않지만 결과 JSON의 탐지 시간에 사용
    required_columns = ["timestamp", *MAPPING.keys()]
    missing_columns = [column for column in required_columns if column not in df.columns]
    if missing_columns:
        raise ValueError(
            "CICFlowMeter 결과에 필요한 컬럼이 없습니다: "
            + ", ".join(missing_columns)
        )

    df = df[required_columns].rename(columns=MAPPING)
    return df


# 모델 예측 (학습 때와 동일한 컬럼명 정규화 후 모델 피처에 맞춤)
def predict(df, model):
    df_original = df.copy()  # 원본 보존 (예측 결과를 붙이기 위함)

    df.columns = [re.sub(r"[^\w\s]", "", col).strip().replace(" ", "_") for col in df.columns]

    model_features = model.feature_names_
    missing = set(model_features) - set(df.columns)
    if missing:
        print("모델에 필요한데 테스트 데이터에 없는 컬럼:", missing)

    X_test = df[model_features]

    y_pred = model.predict(X_test).ravel()
    y_proba = model.predict_proba(X_test)

    df_original["Predicted_Label"] = y_pred
    for i, cls in enumerate(model.classes_):
        df_original[f"Prob_{cls}"] = y_proba[:, i]

    return df_original


# ===== 경로 설정 =====
# 개인 환경에 맞게 경로 지정해주시면 됩니다!
pcap_path = Path(r"/home/lms/log_team/pipline/pcap_buffer/capture_00002_20261006104312.pcap")  # 입력 PCAP
temp_csv_path = Path(r"/home/lms/log_team/pipeline/test_raw.csv")  #  CSV 경로 -> 정상 처리 후 삭제
model_path = Path(r"/home/lms/log_team/pipeline/final3.pkl")  # 학습된 CatBoost 모델
output_path = Path(r"/home/lms/log_team/pipeline/test_prediction.csv")  # 최종 예측 결과

temp_csv_path.parent.mkdir(parents=True, exist_ok=True)

# ===== 실행 =====
def ML_analyze(pcap_path=pcap_path):
    print(f"[NETWORK] 분석 대상 PCAP: {pcap_path}")

    # 1) pcap -> flow CSV
    pcap_to_csv(pcap_path, temp_csv_path)

    # 2) 컬럼명 매핑
    df = load_data(temp_csv_path)

    if df is None:
        print("[NETWORK] 분석 가능한 Flow 없음 - ML 분석 생략")

        if Path(temp_csv_path).exists():
            Path(temp_csv_path).unlink()

        return None

    df = rename_columns(df)
    os.remove(temp_csv_path)  # 중간 파일 삭제
    print("flow 수:", len(df))

    # 3) 모델 로드 및 예측
    with open(model_path, "rb") as f:
        model = pickle.load(f)

    result = predict(df, model)
    result.to_csv(output_path, index=False)

    print(result["Predicted_Label"].value_counts())
    print(f"결과 저장 완료: {output_path}")

    # 4) CatBoost 예측 결과를 LLM 입력용 NETWORK JSON으로 저장
    json_path = save_prediction_json(
        result=result,
        model=model,
        pcap_path=Path(pcap_path),
        prediction_csv_path=Path(output_path),
    )

    print(f"LLM 입력용 JSON 저장 완료: {json_path}")

    return str(json_path)


if __name__=="__main__":
    a= ML_analyze()
    print(a)
