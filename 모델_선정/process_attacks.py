import numpy as np
import pandas as pd


DUPLICATE_COLUMNS_TO_DROP = [
    "Subflow Fwd Packets",
    "Subflow Bwd Packets",
    "Subflow Fwd Bytes",
    "Avg Fwd Segment Size",
    "Fwd Header Length.1",
]


# CSV 파일 불러오기 및 컬럼명 공백 제거
def load_data(file_path):
    df = pd.read_csv(file_path)
    df.columns = df.columns.str.strip()

    return df


# 모든 값이 0인 공통 고정값 컬럼 제거
def remove_constant_columns(df):
    drop_columns = [
        "Bwd PSH Flags",
        "Fwd URG Flags",
        "Bwd URG Flags",
        "CWE Flag Count",
        "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate",
    ]

    # 현재 데이터에 존재하는 컬럼만 제거
    existing_columns = [
        column for column in drop_columns if column in df.columns
    ]

    return df.drop(columns=existing_columns)


# 전체 행의 값이 완전히 동일한 컬럼 쌍 탐색
def find_duplicate_column_pairs(df):
    duplicate_pairs = []

    for index, column1 in enumerate(df.columns):
        for column2 in df.columns[index + 1:]:
            if df[column1].equals(df[column2]):
                duplicate_pairs.append(
                    {
                        "기준 컬럼": column1,
                        "중복 컬럼": column2,
                    }
                )

    return pd.DataFrame(duplicate_pairs)


# 무한대와 결측값이 포함된 행 제거
def handle_missing(df):
    df = df.replace([np.inf, -np.inf], np.nan)

    return df.dropna()


# 공격 종류에 맞게 데이터를 전처리하고 이진 분류용 X, y 생성
def preprocess_attack(file_path, attack_pattern):
    df = load_data(file_path)

    # 공통 고정값 컬럼 및 결측값 제거
    df = remove_constant_columns(df)
    df = handle_missing(df)

    # 정상 데이터와 지정한 공격 데이터만 선택
    attack_mask = df["Label"].str.contains(
        attack_pattern, case=False, na=False
    )
    df = df[(df["Label"] == "BENIGN") | attack_mask].copy()

    # 정상은 0, 공격은 1로 변환
    df["Target"] = (df["Label"] != "BENIGN").astype(int)

    # 입력 데이터와 정답 데이터 분리
    X = df.drop(columns=["Label", "Target"])
    y = df["Target"]

    # 정상 또는 공격 데이터가 없을 경우 학습 전 오류 표시
    if y.nunique() < 2:
        raise ValueError(
            f"'{attack_pattern}' 전처리 결과 Target 값이 하나뿐입니다: "
            f"{y.value_counts().to_dict()}"
        )

    return X, y


# Brute Force 데이터 전처리
def preprocess_bruteforce(file_path):
    return preprocess_attack(
        file_path,
        attack_pattern="Web Attack",
    )


# DoS 데이터 전처리
def preprocess_dos(file_path):
    return preprocess_attack(
        file_path,
        attack_pattern="DoS",
    )
