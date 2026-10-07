"""Offline, opt-in comparison against the team's supplied final_test.py.

No capture, traffic generation, model update, LLM call or label rewriting.
Run with: python -m external.compare_pipeline --help
"""
import argparse
import ast
from collections import Counter
import hashlib
from importlib.metadata import version, PackageNotFoundError
import json
import math
import os
import pickle
from pathlib import Path
import pickletools
import re
import subprocess
import sys
import uuid

from external.config import ROOT, MODEL_PATH, MAX_FILE_BYTES, MAX_RECORDS


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def json_value(value):
    """Keep non-finite diagnostic values explicit, never silently impute them."""
    if isinstance(value, dict):
        return {str(k): json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(v) for v in value]
    if hasattr(value, 'item'):
        value = value.item()
    if isinstance(value, float) and not math.isfinite(value):
        return 'NaN' if math.isnan(value) else ('+inf' if value > 0 else '-inf')
    return value


def save_json(path, value):
    Path(path).write_text(json.dumps(json_value(value), ensure_ascii=False, indent=2,
                                    allow_nan=False), encoding='utf-8')


def team_functions(path):
    """Execute only reviewed helper definitions, not imports/main/path side effects.

    The caller supplies their trusted pipeline source. Its Python function bodies
    execute as code, just as when running that pipeline; this is not a code sandbox.
    """
    import pandas as pd
    from cicflowmeter.sniffer import create_sniffer
    tree = ast.parse(Path(path).read_text(encoding='utf-8-sig'), filename=str(path))
    mapping = next(n for n in tree.body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'MAPPING' for t in n.targets))
    namespace = {'pd': pd, 're': re, 'create_sniffer': create_sniffer,
                 'MAPPING': ast.literal_eval(mapping.value)}
    names = {'pcap_to_csv', 'rename_columns', 'predict'}
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    if {n.name for n in nodes} != names:
        raise ValueError('원본 final_test.py에 필요한 세 함수가 없습니다.')
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


def native_model(source, destination):
    """Extract the exact embedded CBM, without pickle.load or pickle code execution."""
    source = Path(source)
    if source.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('비교 모델 파일은 32 MB 이하이어야 합니다.')
    data = source.read_bytes()
    if data.startswith(b'CBM1'):
        native = data
        loading = 'CatBoost native CBM'
    else:
        blobs = [arg for _, arg, _ in pickletools.genops(data)
                 if isinstance(arg, bytes) and arg.startswith(b'CBM1')]
        if len(blobs) != 1:
            raise ValueError('pickle에서 단일 CatBoost CBM1 모델을 확인하지 못했습니다.')
        native = blobs[0]
        loading = 'embedded CBM extracted; pickle wrapper was not executed'
    Path(destination).write_bytes(native)
    return {'model_path': str(source.resolve()), 'source_sha256': hashlib.sha256(data).hexdigest(),
            'native_sha256': hashlib.sha256(native).hexdigest(), 'loading': loading,
            'native_load_call': 'CatBoostClassifier.load_model(format="cbm")'}


class RecordingModel:
    """Record exactly what each engine passes into CatBoost, without changing it."""
    def __init__(self, model):
        self.model = model
        self.feature_names_ = model.feature_names_
        self.classes_ = model.classes_
        self.inputs = None
        self.predict_inputs = None
        self.labels = None
        self.probabilities = None
        self.calls = {}

    def predict(self, inputs, **kwargs):
        self.predict_inputs = inputs.copy()
        self.inputs = inputs.copy()
        self.calls['predict'] = kwargs
        result = self.model.predict(inputs, **kwargs)
        self.labels = result.copy().ravel()
        return result

    def predict_proba(self, inputs, **kwargs):
        self.inputs = inputs.copy()
        self.calls['predict_proba'] = kwargs
        result = self.model.predict_proba(inputs, **kwargs)
        self.probabilities = result.copy()
        return result


def inference(engine, raw_csv, team_script, model_path, directory):
    import numpy as np
    import pandas as pd
    from pandas.errors import EmptyDataError
    from catboost import CatBoostClassifier
    from external.feature_mapping import MAPPING
    from external.network import predict_csv
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    provenance = native_model(model_path, directory / 'model.cbm')
    model = CatBoostClassifier()
    if Path(model_path).read_bytes().startswith(b'CBM1'):
        model.load_model(str(directory / 'model.cbm'), format='cbm')
        provenance['pickle_wrapper_executed'] = False
    else:
        model = pickle.loads(Path(model_path).read_bytes())
        if not isinstance(model, CatBoostClassifier):
            raise ValueError('비교 pkl은 원본 CatBoostClassifier 객체여야 합니다.')
        provenance.update(loading='original pickle object loaded directly',
                          native_load_call=None, pickle_wrapper_executed=True)
    recorder = RecordingModel(model)
    try:
        df = pd.read_csv(raw_csv, nrows=MAX_RECORDS + 1)
    except EmptyDataError:
        save_json(directory / 'trace.json', {'state': 'empty', **provenance})
        return
    if len(df) > MAX_RECORDS:
        raise ValueError('비교 Flow 제한(20,000개)을 초과했습니다.')
    if df.empty:
        save_json(directory / 'trace.json', {'state': 'empty', **provenance})
        return
    raw_columns = list(df.columns)
    df.columns = df.columns.str.strip()
    mapping = team_functions(team_script)['MAPPING'] if engine == 'original' else MAPPING
    preview = df.rename(columns=mapping).copy()
    preview.columns = [re.sub(r'[^\w\s]', '', col).strip().replace(' ', '_') for col in preview.columns]
    selected = [name for name in model.feature_names_ if name in preview]
    save_json(directory / 'before-predict.json', {
        **provenance, 'model_feature_names': list(model.feature_names_),
        'raw_columns': raw_columns, 'raw_shape': list(df.shape),
        'normalized_columns': list(preview.columns),
        'missing_features': [name for name in model.feature_names_ if name not in preview],
        'selected_raw_dtypes': {c: str(t) for c, t in preview[selected].dtypes.items()},
        'first_flow_raw_feature_values': preview[selected].iloc[0].to_dict(),
        'note': 'Diagnostic preview only; trace.json records the actual CatBoost arguments.'})
    if engine == 'original':
        functions = team_functions(team_script)
        renamed = functions['rename_columns'](df.copy())
        result = functions['predict'](renamed.copy(), recorder)
    else:
        from external.team_adapter import ml_functions
        helpers = ml_functions()
        renamed = (helpers['rename_columns'](df.copy()) if set(helpers['MAPPING']).issubset(df.columns)
                   else df.rename(columns=helpers['MAPPING']).copy())
        # Calls the production scanner function, with a transparent recorder.
        event = predict_csv(raw_csv, Path(raw_csv).name, recorder)
        result = df[['timestamp']].copy()
        result['Predicted_Label'] = recorder.labels
        for i, cls in enumerate(model.classes_):
            result[f'Prob_{cls}'] = recorder.probabilities[:, i]
        save_json(directory / 'network_summary.json', {
            k: event[k] for k in ('class_counts', 'class_probabilities', 'flow_count')})
    normalized = [re.sub(r'[^\w\s]', '', col).strip().replace(' ', '_') for col in renamed.columns]
    inputs = recorder.inputs
    values = inputs.to_numpy(dtype=float)
    classes = [str(c) for c in model.classes_]
    trace = {'state': 'completed', 'engine': engine, **provenance,
             'team_script_sha256': digest(team_script), 'raw_csv_sha256': digest(raw_csv),
             'raw_columns': raw_columns, 'raw_column_count': len(raw_columns),
             'raw_shape': list(df.shape), 'raw_dtypes': {c: str(t) for c, t in df.dtypes.items()},
             'rename_columns_result': list(renamed.columns), 'normalized_columns': normalized,
             'excluded_raw_columns': [c for c in df.columns if c not in ['timestamp', *mapping]],
             'unused_model_columns': [c for c in normalized if c not in model.feature_names_],
             'model_feature_names': list(model.feature_names_), 'model_classes': classes,
             'input_dataframe_columns': list(inputs.columns), 'input_shape': list(inputs.shape),
             'input_dtypes': {c: str(t) for c, t in inputs.dtypes.items()},
             'first_flow_feature_values': inputs.iloc[0].to_dict(),
             'nan_count': int(np.isnan(values).sum()), 'inf_count': int(np.isinf(values).sum()),
             'preprocessing': ('original: no numeric coercion or NaN/inf replacement' if engine == 'original'
                               else 'scanner adapter: validate finite numeric inputs; original predict receives unchanged dtypes/values'),
             'calls': recorder.calls,
             'predict_and_proba_inputs_equal': recorder.predict_inputs.equals(recorder.inputs),
             'predict': [str(v) for v in recorder.labels],
             'predict_proba': recorder.probabilities.tolist(),
             'class_counts': {c: int((recorder.labels.astype(str) == c).sum()) for c in classes},
             'class_probabilities': {c: float(recorder.probabilities[:, i].mean())
                                     for i, c in enumerate(classes)}}
    renamed.to_csv(directory / 'renamed.csv', index=False)
    inputs.to_csv(directory / 'features.csv', index=False)
    inputs.describe(percentiles=[.5, .9, .95]).transpose().to_csv(directory / 'feature-statistics.csv')
    result[['timestamp', 'Predicted_Label', *[f'Prob_{c}' for c in classes]]].to_csv(
        directory / 'predictions.csv', index=False)
    save_json(directory / 'trace.json', trace)


def convert_original(pcap, csv_path, team_script):
    from unittest.mock import patch
    # Exact shim present in the supplied original final_test.py; only in this child.
    with patch('scapy.sendrecv.tcpdump', lambda fname, *a, **k: open(fname, 'rb')):
        team_functions(team_script)['pcap_to_csv'](Path(pcap), Path(csv_path))


def packet_summary(path):
    from scapy.all import PcapReader, IP, TCP, UDP
    count, selected, lengths, first, last = 0, 0, [], None, None
    endpoints, ports = Counter(), Counter()
    with PcapReader(str(path)) as reader:
        linktype = getattr(reader, 'linktype', None)
        for packet in reader:
            count += 1
            if count > MAX_RECORDS:
                raise ValueError('비교 PCAP 패킷 제한(20,000개)을 초과했습니다.')
            timestamp = float(packet.time)
            first = timestamp if first is None else min(first, timestamp)
            last = timestamp if last is None else max(last, timestamp)
            lengths.append(len(packet))
            if IP in packet and (TCP in packet or UDP in packet):
                selected += 1
                endpoints.update([packet[IP].src, packet[IP].dst])
                transport = packet[TCP] if TCP in packet else packet[UDP]
                ports.update([str(transport.sport), str(transport.dport)])
    return {'sha256': digest(path), 'size_bytes': Path(path).stat().st_size,
            'linktype': linktype, 'packet_count': count, 'ipv4_tcp_udp_count': selected,
            'first_packet_epoch': first, 'last_packet_epoch': last,
            'duration_seconds': last - first if count else 0,
            'mean_packet_bytes': sum(lengths) / count if count else 0,
            'top_endpoints': endpoints.most_common(10), 'top_ports': ports.most_common(10)}


def compare_frames(left_path, right_path):
    import numpy as np
    import pandas as pd
    from pandas.errors import EmptyDataError
    try:
        left, right = pd.read_csv(left_path), pd.read_csv(right_path)
    except EmptyDataError:
        return {'state': 'empty', 'equal': Path(left_path).read_bytes() == Path(right_path).read_bytes()}
    result = {'state': 'completed', 'left_shape': list(left.shape), 'right_shape': list(right.shape),
              'column_order_equal': list(left.columns) == list(right.columns),
              'dtype_equal': left.dtypes.astype(str).to_dict() == right.dtypes.astype(str).to_dict(),
              'exact_equal': left.equals(right)}
    shared = [c for c in left if c in right]
    if len(left) == len(right):
        differing = [c for c in shared if not left[c].equals(right[c])]
        result['different_columns'] = differing
        result['first_row_differences'] = {
            c: {'original': json_value(left[c].iloc[0]), 'scanner': json_value(right[c].iloc[0])}
            for c in differing if len(left) and str(left[c].iloc[0]) != str(right[c].iloc[0])}
        # Detect reordered identical flows; ordered equality remains separately visible.
        hashes_a = pd.util.hash_pandas_object(left[shared], index=False).tolist()
        hashes_b = pd.util.hash_pandas_object(right[shared], index=False).tolist()
        result['row_multiset_equal'] = Counter(hashes_a) == Counter(hashes_b)
        numeric = [c for c in shared if pd.api.types.is_numeric_dtype(left[c])
                   and pd.api.types.is_numeric_dtype(right[c])]
        if numeric:
            a, b = left[numeric].to_numpy(float), right[numeric].to_numpy(float)
            result['numeric_values_close'] = bool(np.allclose(a, b, rtol=1e-12, atol=1e-12, equal_nan=True))
    return result


def run_child(arguments, log_path, timeout=60):
    with Path(log_path).open('wb') as log:
        proc = subprocess.run([sys.executable, '-m', 'external.compare_pipeline', *arguments],
                              cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, shell=False,
                              timeout=timeout, creationflags=(
                                  subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0))
    if proc.returncode:
        raise ValueError(f'비교 단계 실패(exit {proc.returncode}). 기술 로그: {log_path}')


def run_comparison(pcap, team_script, team_model, scanner_model, output):
    from external.feature_mapping import MAPPING
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    report = {'state': 'running', 'pcap': str(Path(pcap).resolve()),
              'team_script': str(Path(team_script).resolve()),
              'scanner_default_model': str(MODEL_PATH), 'scanner_selected_model': str(scanner_model),
              'environment': {'python': sys.version, 'platform': sys.platform},
              'capture_context': {
                  'original': 'validated capture point: ZeroTier (user-reported); supplied auto-capture source selects physical NIC, no BPF, 300s ring buffer',
                  'scanner': 'Web UI manual interface: tcp port <target port>; optional CLI/API ZeroTier/Docker auto discovery; 5-120s; 20000 packets; 16MB',
                  'note': 'Actual interface/BPF cannot be inferred from a PCAP. Same PCAP isolates collection differences.'},
              'stages': {}}
    try:
        if Path(pcap).stat().st_size > MAX_FILE_BYTES:
            raise ValueError('비교 PCAP은 16 MB 이하이어야 합니다.')
        manifest_path = MODEL_PATH.parent / 'manifest.json'
        if manifest_path.is_file() and MODEL_PATH.is_file():
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            actual = digest(MODEL_PATH)
            report['scanner_runtime_model'] = {
                'configured_path': str(MODEL_PATH), 'actual_sha256': actual,
                'manifest_file': manifest.get('file'), 'manifest_sha256': manifest.get('sha256'),
                'manifest_matches': manifest.get('file') == MODEL_PATH.name and manifest.get('sha256') == actual,
                'override_for_comparison': Path(scanner_model).resolve() != MODEL_PATH.resolve()}
        report['packets'] = packet_summary(pcap)
        for package in ('catboost', 'cicflowmeter', 'scapy', 'pandas', 'numpy'):
            try:
                report['environment'][package] = version(package)
            except PackageNotFoundError:
                report['environment'][package] = 'not installed'
        requirements = Path(team_script).parent.parent / 'requirements.txt'
        if requirements.is_file():
            report['team_declared_versions'] = {}
            for line in requirements.read_text(encoding='utf-8-sig').splitlines():
                name, separator, declared = line.partition('==')
                if separator and name in ('catboost', 'cicflowmeter', 'scapy', 'pandas', 'numpy'):
                    report['team_declared_versions'][name] = declared
        report['mapping_equal'] = team_functions(team_script)['MAPPING'] == MAPPING
        for engine in ('original', 'scanner'):
            raw = output / f'{engine}-raw.csv'
            run_child(['--stage', 'convert', '--engine', engine, '--pcap', str(pcap),
                       '--team-script', str(team_script), '--output', str(raw)],
                      output / f'{engine}-convert.log')
        report['flow_conversion'] = compare_frames(output / 'original-raw.csv', output / 'scanner-raw.csv')
        # 2x2 matrix distinguishes conversion from preprocessing/inference regressions.
        for csv_origin in ('original', 'scanner'):
            for engine in ('original', 'scanner'):
                name = f'{engine}-on-{csv_origin}'
                destination = output / name
                model = team_model if engine == 'original' else scanner_model
                try:
                    run_child(['--stage', 'infer', '--engine', engine,
                               '--raw-csv', str(output / f'{csv_origin}-raw.csv'),
                               '--team-script', str(team_script), '--model', str(model),
                               '--output', str(destination)], output / f'{name}.log')
                    trace = json.loads((destination / 'trace.json').read_text(encoding='utf-8'))
                    report['stages'][name] = {k: trace.get(k) for k in (
                        'state', 'model_path', 'source_sha256', 'native_sha256', 'input_shape',
                        'model_classes', 'class_counts', 'class_probabilities', 'calls')}
                except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
                    report['stages'][name] = {'state': 'failed', 'reason': str(exc)}
        for csv_origin in ('original', 'scanner'):
            a, b = output / f'original-on-{csv_origin}', output / f'scanner-on-{csv_origin}'
            if (a / 'features.csv').exists() and (b / 'features.csv').exists():
                report[f'inputs_on_{csv_origin}'] = compare_frames(a / 'features.csv', b / 'features.csv')
                report[f'predictions_on_{csv_origin}'] = compare_frames(a / 'predictions.csv', b / 'predictions.csv')
        a = report['stages'].get('original-on-original', {})
        b = report['stages'].get('scanner-on-scanner', {})
        report['same_native_model'] = bool(a.get('native_sha256') and a.get('native_sha256') == b.get('native_sha256'))
        original, scanner = output / 'original-on-original', output / 'scanner-on-scanner'
        if (original / 'features.csv').exists() and (scanner / 'features.csv').exists():
            report['primary_inputs'] = compare_frames(original / 'features.csv', scanner / 'features.csv')
            report['primary_predictions'] = compare_frames(original / 'predictions.csv', scanner / 'predictions.csv')
        report['state'] = 'completed' if all(s['state'] in ('completed', 'empty')
                                            for s in report['stages'].values()) else 'partial'
        if all(s.get('state') == 'empty' for s in report['stages'].values()):
            report['comparison_conclusion'] = 'no_flows_available_no_classification'
        elif not report['same_native_model']:
            report['comparison_conclusion'] = 'different_models_repeat_with_same_native_model'
        elif report.get('primary_inputs', {}).get('exact_equal') and report.get('primary_predictions', {}).get('exact_equal'):
            report['comparison_conclusion'] = 'no_regression_reproduced_on_this_pcap'
        elif not report.get('flow_conversion', {}).get('exact_equal'):
            report['comparison_conclusion'] = 'flow_conversion_difference_check_values_and_row_order'
        elif not report.get('primary_inputs', {}).get('exact_equal'):
            report['comparison_conclusion'] = 'preprocessing_difference_or_failed_inference_check_traces'
        else:
            report['comparison_conclusion'] = 'inference_difference_check_model_loading_and_calls'
        report['interpretation'] = (
            'Different native models: repeat with the same model before attributing differences to migration.'
            if not report['same_native_model'] else
            'Same native model. Compare raw CSV, then features.csv, then per-flow predictions.csv; no label substitution applied.')
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        report.update(state='failed', reason=str(exc))
    finally:
        save_json(output / 'comparison.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description='동일 PCAP의 원본/Scanner ML 입력·예측 비교 (오프라인 전용)')
    parser.add_argument('--pcap', type=Path)
    parser.add_argument('--team-script', type=Path, required=True, help='원본 tools/final_test.py')
    parser.add_argument('--team-model', type=Path, help='원본 final3.pkl/final4.pkl 또는 CBM')
    parser.add_argument('--scanner-model', type=Path, default=MODEL_PATH)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--stage', choices=('convert', 'infer'), help=argparse.SUPPRESS)
    parser.add_argument('--engine', choices=('original', 'scanner'), help=argparse.SUPPRESS)
    parser.add_argument('--raw-csv', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--model', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.stage == 'convert':
        if args.engine == 'original':
            convert_original(args.pcap, args.output, args.team_script)
        else:
            from external.flow_worker import convert
            convert(args.pcap, args.output)
        return
    if args.stage == 'infer':
        inference(args.engine, args.raw_csv, args.team_script, args.model, args.output)
        return
    if args.pcap is None or args.team_model is None:
        parser.error('--pcap과 --team-model을 지정하세요.')
    output = args.output or ROOT / 'reports' / ('ml-comparison-' + uuid.uuid4().hex[:12])
    report = run_comparison(args.pcap.resolve(), args.team_script.resolve(),
                            args.team_model.resolve(), args.scanner_model.resolve(), output.resolve())
    print(f'Comparison: {report["state"]}; {output.resolve() / "comparison.json"}')
    for name, stage in report['stages'].items():
        print(f'{name}: {stage.get("class_counts", stage.get("state"))}')
    if report['state'] not in ('completed',):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
