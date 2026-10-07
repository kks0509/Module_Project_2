"""Collection -> WEB regex / NETWORK ML -> source=external JSON. No LLM calls."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from external.collection import collect
from external.config import ROOT, MAX_FILE_BYTES
from external.contract import finding, status_finding, group_web
from external.network import predict_csv, import_network
from external.web_logs import load_records, detect_web
from report_store import normalize_report, write_json


def now():
    return datetime.now(timezone.utc).isoformat()


class Cancelled(Exception):
    pass


def convert_pcap(path, csv_path, cancel):
    proc = subprocess.Popen([sys.executable, '-m', 'external.flow_worker', str(path), str(csv_path)],
                            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            shell=False, creationflags=(subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0))
    start = time.monotonic()
    try:
        while proc.poll() is None:
            if cancel.wait(.1):
                raise Cancelled()
            if time.monotonic() - start > 60:
                raise ValueError('PCAP Flow 변환 시간 제한(60초)을 초과했습니다.')
        if proc.returncode != 0:
            raise ValueError('PCAP Flow 변환 실패: 파일 형식·CICFlowMeter 설치·패킷 수 제한을 확인하세요.')
    finally:
        if proc.poll() is None:
            proc.kill(); proc.wait(timeout=3)


def analyze_input(name, data, work, index, cancel):
    suffix = Path(name).suffix.lower()
    source_file = Path(name.replace('\\', '/')).name[:160]
    if suffix in ('.pcap', '.pcapng'):
        path, csv = work / f'input-{index}{suffix}', work / f'flows-{index}.csv'
        path.write_bytes(data)
        convert_pcap(path, csv, cancel)
        event = predict_csv(csv, source_file)
        return ([event] if event else []), {'kind': 'NETWORK', 'flow_count': event['flow_count'] if event else 0}
    if suffix == '.csv':
        path = work / f'input-{index}.csv'; path.write_bytes(data)
        event = predict_csv(path, source_file)
        return ([event] if event else []), {'kind': 'NETWORK', 'flow_count': event['flow_count'] if event else 0}
    if suffix not in ('.json', '.jsonl', '.log', '.txt'):
        raise ValueError('지원 형식: PCAP/PCAPNG, Flow CSV, 웹 로그 JSON/JSONL/Burp .log/.txt')
    if suffix == '.json':
        try:
            value = json.loads(data.decode('utf-8-sig'))
        except (ValueError, UnicodeError):
            value = None
        if isinstance(value, dict) and ('class_counts' in value or value.get('source') == 'NETWORK'):
            event = import_network(value, source_file)
            return [event], {'kind': 'NETWORK', 'flow_count': event['flow_count']}
    records = load_records(data)
    events = detect_web(records, source_file)
    return events, {'kind': 'WEB', 'record_count': len(records), 'suspicious_record_count': len(events)}


def run_pipeline(config, identity, store, cancel, emit):
    config.validate()
    job = {'schema_version': 1, 'source': 'external', 'scan_id': identity, 'target': config.target,
           'state': 'running', 'started_at': now(), 'finished_at': None,
           'modules': ['external_web', 'external_network'], 'requests': 0, 'total': 3, 'completed': 0,
           'results': [], 'collection': {'mode': config.mode, 'duration_seconds': config.duration if config.mode == 'live' else 0,
                                       'input_count': 0, 'web_record_count': 0, 'flow_count': 0},
           'pipeline_inputs': []}
    directory = store.directory(identity)
    work = directory / ('work-' + os.urandom(8).hex())
    work.mkdir(parents=True, mode=0o700 if os.name != 'nt' else 0o777)
    events = []

    def progress(current, module):
        emit({'type': 'progress', 'current': current, 'completed': current, 'total': 3,
              'module': module, 'state': 'running', 'scan_id': identity})

    try:
        progress(0, '로그·네트워크 입력 준비')
        errors = []
        if config.mode == 'live':
            inputs, errors = collect(config, work, cancel, lambda label: progress(0, label))
            if config.capture_info:
                job['collection']['capture'] = config.capture_info
        else:
            inputs = config.uploads
        job['collection']['input_count'] = len(inputs)
        for kind, error in errors:
            evidence = config.capture_info if kind == 'NETWORK' else None
            job['results'].append(status_finding(identity, config.target, kind + ' 수집 실패', error, evidence=evidence))
        if config.mode == 'live' and config.capture_info.get('state') == 'empty':
            job['results'].append(status_finding(identity, config.target,
                'NETWORK 수집 완료 · 분석 가능한 패킷 없음',
                '수집은 정상 완료되었으며 해당 시간 동안 분석 가능한 패킷이 없습니다.',
                'skipped', config.capture_info))
        progress(1, '웹 로그 선별 · 네트워크 ML 분류')
        for index, (name, data) in enumerate(inputs):
            if cancel.is_set():
                raise Cancelled()
            progress(1, f'웹 로그 선별 · 네트워크 ML 분류 · 파일 {index + 1}/{len(inputs)}')
            try:
                if len(data) > MAX_FILE_BYTES:
                    raise ValueError('입력 크기 제한 초과')
                found, counts = analyze_input(name, data, work, index, cancel)
                # Bound retained evidence independently of the input/flow limits.
                # Full counts remain in collection metadata even if samples are capped.
                if counts['kind'] == 'NETWORK':
                    # Never let an earlier busy web log displace a model summary.
                    events.extend(found)
                    while len(events) > 500:
                        victim = next(i for i, e in enumerate(events) if e['source'] == 'WEB')
                        events.pop(victim)
                else:
                    available = max(0, 500 - len(events))
                    events.extend(found[:available])
                job['collection']['observed_event_count'] = job['collection'].get('observed_event_count', 0) + len(found)
                job['collection']['web_record_count'] += counts.get('record_count', 0)
                job['collection']['flow_count'] += counts.get('flow_count', 0)
                display = group_web(found) if counts['kind'] == 'WEB' else found
                job['results'].extend(finding(identity, e, config.target) for e in display)
                if not found:
                    empty = not counts.get('record_count', counts.get('flow_count', 0))
                    job['results'].append(status_finding(identity, config.target,
                        counts['kind'] + (' · 분석 자료 없음' if empty else ' · 의심 패턴 미탐지'),
                        '분석 가능한 요청/Flow가 없습니다.' if empty else '수집한 웹 로그에서 팀 정규식에 해당하는 패턴을 찾지 못했습니다.',
                        'skipped' if empty else 'not_detected', counts))
            except Cancelled:
                raise
            except (ValueError, OSError, ImportError) as exc:
                # Known errors are safe messages; never return parser/SDK dumps.
                reason = str(exc)[:500] if isinstance(exc, ValueError) else '입력 파일·설치 패키지·읽기 권한을 확인하세요.'
                job['results'].append(status_finding(identity, config.target,
                    '입력 분석 실패 · ' + Path(name.replace('\\', '/')).name[:100], reason))
            except Exception:
                job['results'].append(status_finding(identity, config.target, '입력 분석 실패',
                    'Flow 입력 형식 또는 모델 호환성을 확인하세요. 내부 진단과 무관한 외부 분석 오류입니다.'))
        if cancel.is_set():
            raise Cancelled()
        progress(2, '외부 진단 JSON 저장')
        job['state'], job['completed'] = 'done', 3
    except Cancelled:
        job['state'], job['completed'] = 'cancelled', 1
    finally:
        # Delete only this run's private work directory. Never touch original files.
        resolved = work.resolve()
        if resolved.is_relative_to(directory.resolve()) and resolved != directory.resolve():
            shutil.rmtree(resolved)
    job['finished_at'] = now()
    job['collection']['retained_event_count'] = len(events)
    job['collection']['omitted_event_count'] = job['collection'].get('observed_event_count', 0) - len(events)
    job['collection']['web_examples_per_group'] = 5
    job['pipeline_inputs'] = [{'scan_id': identity, **event} for event in events]
    job = normalize_report(job)
    # The shared contract retains the pipeline JSON alongside display findings.
    store.save(job)
    write_json(directory / 'pipeline_input.json', {'scan_id': identity, 'source': 'external',
                                                  'target': config.target, 'inputs': job['pipeline_inputs']})
    progress(job['completed'], '외부 진단 완료' if job['state'] == 'done' else '외부 진단 중지')
    return job
