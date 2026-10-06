import warnings

import numpy as np
import pandas as pd

from catboost import CatBoostClassifier
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import ExtraTreesClassifier

def create_models(include_svc=True):
    # 기존 프로젝트와 같은 설정으로 비교 모델을 생성
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=3,
            random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=100,
            random_state=42),
        "Extra Trees": ExtraTreesClassifier(
            n_estimators=100,
            random_state=42
        ),
        "CatBoost": CatBoostClassifier(
            iterations=1000,
            random_state=42,
            verbose=0,
        ),
    }
    if include_svc:
        models["SVC"] = SVC()
    return models


def split_data(X, y):
    return train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )


def compare_models(X, y, dataset_name, include_svc=True):
    # 한 데이터셋에서 모델별 F1을 측정
    X_train, X_test, y_train, y_test = split_data(X, y)
    results = []

    for model_name, model in create_models(include_svc).items():
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", ConvergenceWarning)
                model.fit(X_train, y_train)
            y_pred = np.asarray(model.predict(X_test)).reshape(-1)
            score = f1_score(y_test, y_pred, zero_division=0)
            results.append(
                {
                    "Dataset": dataset_name,
                    "Model": model_name,
                    "F1": score,
                    "Status": "성공",
                }
            )
        except Exception as error:
            results.append(
                {
                    "Dataset": dataset_name,
                    "Model": model_name,
                    "F1": np.nan,
                    "Status": type(error).__name__,
                }
            )

    return pd.DataFrame(results)


def build_comparison_table(brute_results, dos_results, stage):
    # 두 공격 데이터의 F1과 평균 F1을 하나의 표로 생성
    all_results = pd.concat([brute_results, dos_results], ignore_index=True)
    success = all_results[all_results["Status"] == "성공"]
    table = success.pivot(index="Model", columns="Dataset", values="F1")
    table = table.rename(
        columns={"Brute Force": "Brute Force F1", "DoS": "DoS F1"}
    ).reset_index()

    required = ["Brute Force F1", "DoS F1"]
    for column in required:
        if column not in table.columns:
            table[column] = np.nan

    table["Average F1"] = table[required].mean(axis=1, skipna=False)
    table["Stage"] = stage
    return table.sort_values("Average F1", ascending=False).reset_index(drop=True)


def select_best_model(comparison_table):
    # 두 데이터의 평균 F1이 가장 높은 공통 모델을 선정
    candidates = comparison_table.dropna(subset=["Average F1"])
    if candidates.empty:
        raise ValueError("두 데이터셋에서 모두 성공한 모델이 없습니다.")
    return candidates.iloc[0]["Model"]


def calculate_feature_importance(X, y, model):
    # 선정 모델을 학습하고 컬럼별 중요도 계산
    X_train, X_test, y_train, y_test = split_data(X, y)
    fitted_model = clone(model)
    fitted_model.fit(X_train, y_train)

    if hasattr(fitted_model, "feature_importances_"):
        values = np.asarray(fitted_model.feature_importances_, dtype=float)
    elif hasattr(fitted_model, "coef_"):
        values = np.abs(np.asarray(fitted_model.coef_, dtype=float)).mean(axis=0)
    else:
        result = permutation_importance(
            fitted_model,
            X_test,
            y_test,
            scoring="f1",
            n_repeats=3,
            random_state=42,
            n_jobs=-1,
        )
        values = np.maximum(result.importances_mean, 0)

    return (
        pd.DataFrame({"Feature": X.columns, "Importance": values})
        .sort_values("Importance", ascending=False)
        .reset_index(drop=True)
    )


def evaluate_model(X, y, model):
    # 동일한 분할 조건으로 하나의 모델을 학습하고 F1 반환
    X_train, X_test, y_train, y_test = split_data(X, y)
    fitted_model = clone(model)
    fitted_model.fit(X_train, y_train)
    y_pred = np.asarray(fitted_model.predict(X_test)).reshape(-1)

    return f1_score(y_test, y_pred, zero_division=0)


def find_common_low_importance_columns(
    brute_importance,
    dos_importance,
    threshold=0.1,
):
    # 두 데이터 모두에서 기준 이하인 공통 컬럼 반환
    brute_low = set(
        brute_importance.loc[brute_importance["Importance"] <= threshold, "Feature"]
    )
    dos_low = set(
        dos_importance.loc[dos_importance["Importance"] <= threshold, "Feature"]
    )
    return sorted(brute_low & dos_low)


def create_selected_model(model_name):
    # 모델 비교와 동일한 설정으로 중요도 계산 모델 생성
    models = create_models(include_svc=True)
    if model_name not in models:
        raise KeyError(f"지원하지 않는 모델입니다: {model_name}")
    return models[model_name]
