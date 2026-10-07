"""Reusable rule-based job runner, independent of UI and LLM."""
from copy import deepcopy
from datetime import datetime, timezone
import uuid
from core import Context, finding
from modules import REGISTRY
from classification import owasp_for
from terminology import DBMS

MODULE_NAMES = {'sqli': 'SQL Injection', 'access': 'Broken Access Control', 'idor': 'IDOR 검사',
                'brute': '반복 인증 관찰', 'availability': '가용성 관찰'}


def new_scan_id():
    return 'SCAN-' + uuid.uuid4().hex


def scan(config, cancel, progress=lambda value: None, *, scan_id=None):
    ctx = Context(config, cancel)
    selected = config.get('modules', [])
    if not selected or len(selected) != len(set(selected)) or any(m not in REGISTRY for m in selected):
        raise ValueError('진단 모듈을 선택하세요.')
    if config.get('authorized') is not True:
        raise ValueError('대상 진단 권한 확인이 필요합니다.')
    if any(m in selected for m in ('brute', 'availability')) and not config.get('active_opt_in'):
        raise ValueError('반복 인증/가용성 검사 동의가 필요합니다.')
    job = {'schema_version': 6, 'source': 'internal', 'scan_id': scan_id or new_scan_id(), 'target': ctx.base, 'modules': list(selected),
           'dbms': DBMS, 'started_at': datetime.now(timezone.utc).isoformat(), 'state': 'running',
           'completed': 0, 'total': len(selected), 'requests': 0, 'results': []}
    for index, module in enumerate(selected, 1):
        if cancel.is_set():
            break
        def emit(name, finished=False):
            progress({**deepcopy(job), 'type': 'progress', 'current': job['completed'],
                      'module': name, 'current_module': module, 'module_index': index,
                      'module_finished': finished, 'requests': ctx.count})
        ctx.progress = emit
        emit(MODULE_NAMES[module])
        trace_start = len(ctx.traces)
        try:
            results = REGISTRY[module](ctx)
        except Exception as exc:
            results = [finding(ctx, module, MODULE_NAMES[module], '', 'inconclusive',
                {'reason': '연결·인증·설정 또는 요청 한도 문제로 규칙 검사를 완료할 수 없습니다.',
                 'error_type': type(exc).__name__,
                 'detail': str(exc)[:300] if isinstance(exc, ValueError) else '대상 연결 및 계정 설정을 확인하세요.'},
                '조건을 확인한 뒤 다시 진단하세요.', traces=ctx.traces[trace_start:])]
        for result in results:
            result.update(scan_id=job['scan_id'], source='internal', owasp=owasp_for(module))
            result.setdefault('vulnerability', result['name'])
        job['results'].extend(results)
        if not cancel.is_set():
            job['completed'] += 1
        job['requests'] = ctx.count
        emit(MODULE_NAMES[module], finished=True)
    job.update(state='cancelled' if cancel.is_set() else 'done', requests=ctx.count,
               finished_at=datetime.now(timezone.utc).isoformat())
    return job


def summary(job):
    return {state: sum(r['state'] == state for r in job.get('results', []))
            for state in ('vulnerable', 'not_detected', 'inconclusive', 'skipped', 'observation_required')}
