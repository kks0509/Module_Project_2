"""Team feature mapping and inference using the checksum-verified original pickle."""
import hashlib
import json
import os
import pickle
from pathlib import Path
import re
from zoneinfo import ZoneInfo
from external.config import MODEL_PATH, MAX_RECORDS
from external.feature_mapping import MAPPING

MODEL_DIR = MODEL_PATH.parent


def load_model():
    try:
        from catboost import CatBoostClassifier
    except ImportError:
        raise ValueError('네트워크 ML 패키지가 없습니다. bash setup-external-ubuntu.sh로 설치하세요.') from None
    manifest = json.loads((MODEL_DIR / 'manifest.json').read_text(encoding='utf-8'))
    path = MODEL_PATH
    if manifest.get('file') != path.name:
        raise ValueError('현재 ML 모델과 manifest의 파일명이 일치하지 않습니다.')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['sha256']:
        raise ValueError('제공된 ML 모델의 무결성 확인에 실패했습니다.')
    model = pickle.loads(raw)
    if not isinstance(model, CatBoostClassifier):
        raise ValueError('원본 pkl 파일의 CatBoostClassifier 모델을 확인하세요.')
    return model


def predict_csv(path, source_file, model=None):
    import numpy as np
    import pandas as pd
    from pandas.errors import EmptyDataError
    if Path(path).stat().st_size == 0:
        return None
    try:
        df = pd.read_csv(path, nrows=MAX_RECORDS + 1)
    except EmptyDataError:
        return None
    if df.empty:
        return None
    if len(df) > MAX_RECORDS:
        raise ValueError('Flow 제한(20,000개)을 초과했습니다.')
    df.columns = df.columns.str.strip()
    if 'timestamp' not in df:
        raise ValueError('Flow CSV에 timestamp 컬럼이 없습니다.')
    timestamp_values = pd.to_datetime(df['timestamp'], errors='coerce')
    if timestamp_values.isna().any():
        raise ValueError('Flow CSV에 유효하지 않은 timestamp가 있습니다.')
    from external.team_adapter import ml_functions, export_network
    team = ml_functions()
    # Raw CICFlowMeter uses the exact original selection/rename function.
    # Already-normalized CSV uploads remain supported as an input-format adapter.
    columns = (team['rename_columns'](df) if set(team['MAPPING']).issubset(df.columns)
               else df.rename(columns=team['MAPPING']).copy())
    original_columns = columns.copy()
    columns.columns = [re.sub(r'[^\w\s]', '', col).strip().replace(' ', '_') for col in columns.columns]
    if columns.columns.duplicated().any():
        raise ValueError('정규화 후 중복된 Flow 컬럼이 있습니다.')
    model = load_model() if model is None else model
    features = list(model.feature_names_)
    missing = [name for name in features if name not in columns]
    if missing:
        raise ValueError('모델 입력 컬럼 누락: ' + ', '.join(missing[:12]))
    inputs = columns[features].apply(pd.to_numeric, errors='coerce')
    if not np.isfinite(inputs.to_numpy()).all():
        raise ValueError('모델 입력에 NaN/무한대/숫자가 아닌 값이 있습니다. 임의 보정 없이 분석을 중단했습니다.')
    # Preserve original feature order, dtypes and predict/predict_proba calls.
    # Numeric coercion above is validation only; no values are imputed or changed.
    result = team['predict'](original_columns, model)
    value = export_network(result, model, source_file)
    value.update(classification_origin='bundled_catboost',
                 model_sha256=json.loads((MODEL_DIR / 'manifest.json').read_text(encoding='utf-8'))['sha256'],
                 model_file=MODEL_PATH.name, model_format='pickle',
                 probability_basis='all_flow_mean_not_attack_success_probability',
                 pipeline_origin='log_team_optimization_original')
    return value



def import_network(value, source_file):
    """Allowlisted adapter for the team's existing NETWORK input JSON."""
    import math
    counts, probabilities = value.get('class_counts'), value.get('class_probabilities')
    if not isinstance(counts, dict) or not isinstance(probabilities, dict) or not counts or len(counts) > 20:
        raise ValueError('NETWORK JSON의 클래스별 수/확률을 확인하세요.')
    if set(counts) != set(probabilities) or set(counts) != {'BENIGN', 'BRUTE FORCE', 'DOS'}:
        raise ValueError('NETWORK JSON 클래스 매핑이 올바르지 않습니다.')
    if any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in counts.values()):
        raise ValueError('Flow 수는 0 이상의 정수여야 합니다.')
    if any(not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v) or not 0 <= v <= 1 for v in probabilities.values()):
        raise ValueError('클래스 확률은 0~1의 유한한 숫자여야 합니다.')
    total = value.get('flow_count')
    if not isinstance(total, int) or isinstance(total, bool) or not 0 <= total <= MAX_RECORDS or sum(counts.values()) != total:
        raise ValueError('NETWORK JSON의 전체 Flow 수가 일치하지 않습니다.')
    if abs(sum(probabilities.values()) - 1) > .001:
        raise ValueError('NETWORK JSON의 클래스 확률 합이 올바르지 않습니다.')
    labels = sorted([label for label, count in counts.items() if label != 'BENIGN' and count],
                    key=lambda c: probabilities[c], reverse=True)
    # Derive suspicious/types/probability from the counts; ignore supplied LLM claims.
    return {'source': 'NETWORK', 'source_file': source_file,
            'timestamp': str(value.get('timestamp') or '')[:100],
            'last_detected_at': str(value.get('last_detected_at') or '')[:100],
            'flow_count': total, 'suspicious': bool(labels), 'detected_types': labels,
            'class_counts': counts, 'class_probabilities': probabilities,
            'attack_probability': round(1 - probabilities['BENIGN'], 6),
            'evidence': [{'attack_type': c, 'attack_probability': probabilities[c],
                          'detected_flow_count': counts[c], 'total_flow_count': total} for c in labels],
            'classification_origin': 'imported_team_json',
            'probability_basis': 'all_flow_mean_not_attack_success_probability'}
