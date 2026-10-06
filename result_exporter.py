# CatBoost 예측 결과를 LLM 입력용 NETWORK JSON으로 저장
# LLM이 WEB과 NETWORK 데이터를 구분할 수 있도록 NETWORK JSON에 source="NETWORK" 추가 작업 해둠

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

# 개인 환경에 맞게 경로 지정해주시면 됩니다!
# result_exporter.py가 있는 프로젝트 폴더를 기준 경로로 사용
PROJECT_DIR = Path(__file__).parent
OUTPUT_DIR = PROJECT_DIR / "output" / "json"


# 문자열로 입력받는 이유는 Path 객체를 바로 입력받으면, Path 객체가 JSON 직렬화 과정에서 오류가 발생
def save_prediction_json(
    result,
    model,
    pcap_path: str | Path,
    prediction_csv_path: str | Path,
    output_dir: str | Path = OUTPUT_DIR,
) -> Path:
    # final_test의 예측 결과를 집계 => LLM 입력용 JSON으로 저장
    pcap_path = Path(pcap_path)
    prediction_csv_path = Path(prediction_csv_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if result.empty:
        raise ValueError("JSON으로 저장할 예측 결과가 없습니다.")

    classes = [str(label) for label in model.classes_]
    probability_columns = {label: f"Prob_{label}" for label in classes}
    missing_columns = [
        column
        for column in probability_columns.values()
        if column not in result.columns
    ]
    if missing_columns:
        raise ValueError(
            "예측 결과에 클래스 확률 컬럼이 없습니다: " + ", ".join(missing_columns)
        )

    # 각 클래스로 예측된 플로우 개수를 계산
    detected_counts = result["Predicted_Label"].value_counts().to_dict()
    class_counts = {label: int(detected_counts.get(label, 0)) for label in classes}

    # 플로우별 예측 확률 => 클래스별 평균 확률로 집계
    class_probabilities = {
        label: float(result[column].mean())
        for label, column in probability_columns.items()
    }

    benign_probability = next(
        (
            probability
            for label, probability in class_probabilities.items()
            if label.upper() == "BENIGN"
        ),
        None,
    )
    if benign_probability is None:
        raise ValueError("모델 클래스에 BENIGN이 없어 공격 확률을 계산할 수 없습니다.")

    attack_probability = 1.0 - benign_probability
    detected_types = [
        label
        for label in classes
        if label.upper() != "BENIGN" and class_counts[label] > 0
    ]
    detected_types.sort(
        key=lambda label: class_probabilities[label],
        reverse=True,
    )
    suspicious = bool(detected_types)

    if "timestamp" not in result.columns:
        raise ValueError("예측 결과에 Flow 시작 시간(timestamp) 컬럼이 없습니다.")

    # 공격 Flow가 있으면 모든 공격 유형의 시간 범위를 사용하고,
    # 정상 Flow만 있으면 분석된 전체 Flow 시간 범위를 사용한다.
    timestamp_rows = (
        result.loc[result["Predicted_Label"].isin(detected_types), "timestamp"]
        if suspicious
        else result["timestamp"]
    )
    flow_timestamps = pd.to_datetime(timestamp_rows, errors="coerce").dropna()
    if flow_timestamps.empty:
        raise ValueError("유효한 Flow 타임스탬프가 없습니다.")

    local_timezone = datetime.now().astimezone().tzinfo

    def to_local_isoformat(timestamp) -> str:
        flow_time = timestamp.to_pydatetime()
        if flow_time.tzinfo is None:
            flow_time = flow_time.replace(tzinfo=local_timezone)
        else:
            flow_time = flow_time.astimezone(local_timezone)
        return flow_time.isoformat(timespec="seconds")

    first_detected_at = to_local_isoformat(flow_timestamps.min())
    last_detected_at = to_local_isoformat(flow_timestamps.max())

    # WEB와 입력 JSON의 evidence와 키 이름은 통일시키지만 NETWORK에서는 모델 확률과 탐지 플로우 수를 근거로 사용
    evidence: list[dict[str, Any]] = []
    for attack_type in detected_types:
        attack_timestamps = pd.to_datetime(
            result.loc[result["Predicted_Label"] == attack_type, "timestamp"],
            errors="coerce",
        ).dropna()
        evidence.append(
            {
                # 공격별 확률, Flow 개수, 최초·마지막 탐지 시간
                "attack_type": attack_type,
                "attack_probability": round(
                    float(class_probabilities[attack_type]),
                    6,
                ),
                "detected_flow_count": int(class_counts[attack_type]),
                "total_flow_count": int(len(result)),
                "first_detected_at": to_local_isoformat(attack_timestamps.min()),
                "last_detected_at": to_local_isoformat(attack_timestamps.max()),
            }
        )

    # LLM에 전달할 NETWORK 입력 데이터 구성
    network_input: dict[str, Any] = {
        "timestamp": first_detected_at,
        "last_detected_at": last_detected_at,
        "source": "NETWORK",
        "source_file": pcap_path.name,
        "flow_count": int(len(result)),
        "suspicious": suspicious,
        "detected_types": detected_types,
        "evidence": evidence,
        "attack_probability": round(float(attack_probability), 6),
        "class_probabilities": {
            str(label): round(float(probability), 6)
            for label, probability in class_probabilities.items()
        },
        "class_counts": {
            str(label): int(count) for label, count in class_counts.items()
        },
        "prediction_csv": str(prediction_csv_path.resolve()),
    }

    # 원본 PCAP 파일명을 사용해 JSON 파일 경로 생성
    output_path = output_dir / f"{pcap_path.stem}_network_input.json"

    # 한글이 깨지지 않도록 UTF-8 형식으로 JSON 저장
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            network_input,
            file,
            ensure_ascii=False,
            indent=4,
        )

    # 생성된 JSON 파일 경로 반환
    return output_path
