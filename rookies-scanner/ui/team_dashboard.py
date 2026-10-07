"""Read-only integration of the user's original Streamlit report UI.

Execute original functions unchanged, with per-rerun data and render bindings.
Never run its standalone navigation or mutate process-global environment values.
"""
import ast
from collections import Counter
from datetime import datetime
import hashlib
import html
import json
import os
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st

from external.contract import VERDICTS
from sanitizing import sanitize
from ui.evidence_summary import external_evidence, readable_text

VENDOR = Path(__file__).resolve().parents[1] / 'vendor' / 'streamlit_dashboard'
MENU = '웹·네트워크 Dashboard'
SCREENS = ('통합 Dashboard', '웹 공격 진단', '네트워크 공격 진단', '분석 결과 문서', '진단 이력')


def load_template():
    path = VENDOR / 'streamlit_app.py'
    raw = path.read_bytes()
    manifest = json.loads((VENDOR / 'manifest.json').read_text(encoding='utf-8'))
    if hashlib.sha256(raw).hexdigest() != manifest['files'][path.name]:
        raise ValueError('원본 streamlit_app.py의 무결성 확인에 실패했습니다.')
    tree = ast.parse(raw, filename=str(path))
    constants = {'SEVERITY_ORDER', 'SEVERITY_KO', 'CSS'}
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) or
             isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in node.targets)]
    namespace = {'__file__': str(path), 'APP_DIR': VENDOR, 'html': html, 'json': json, 'os': os,
                 'Counter': Counter, 'datetime': datetime, 'Path': Path, 'Any': Any, 'pd': pd, 'st': st,
                 'WEB_REPORT_PATH': Path('external_report.json'),
                 'NETWORK_REPORT_PATH': Path('pipeline_input.json')}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    # Presentation terms only: retain every original score and assigned severity.
    # Static template output must not masquerade as an OpenAI-generated report.
    def render(markup):
        for old, new in (
            ('AI 기반 LMS 보안 분석 리포트', 'LMS 보안 분석 리포트'),
            ('<th>공격 확률</th>', '<th>클래스 평균 모델 점수</th>'),
            ('현재 입력된 결과에서는 웹 공격', '현재 입력된 결과에서는 웹 탐지'),
            ('건과 네트워크 공격', '건과 네트워크 탐지'),
        ):
            markup = markup.replace(old, new)
        st.markdown(markup, unsafe_allow_html=True)
    namespace['render'] = render
    return namespace


def adapt_results(job, template):
    """One display record per observed class, preserving Scanner facts."""
    web, network = [], []
    for finding_index, finding in enumerate(job.get('results', [])):
        evidence = finding.get('evidence', {})
        source = evidence.get('source')
        if source not in ('WEB', 'NETWORK') or finding.get('state') not in ('suspicious', 'not_detected'):
            continue
        labels = evidence.get('detected_types') or (['BENIGN'] if source == 'NETWORK' and evidence.get('flow_count') else [])
        for label in labels:
            probabilities, counts = evidence.get('class_probabilities', {}), evidence.get('class_counts', {})
            score = probabilities.get(label, 0) if source == 'NETWORK' else 0
            paragraphs = external_evidence(finding, job)
            record = {
                'source': source, 'attack_type': str(label),
                'severity': str(finding.get('severity', 'unknown')).upper(),
                'timestamp': evidence.get('timestamp', job.get('started_at')),
                'last_detected_at': evidence.get('last_detected_at', job.get('finished_at')),
                'summary': VERDICTS.get(finding.get('state'), finding.get('state', '')) + ' · ' + readable_text(finding.get('reason')),
                'evidence': '\n'.join(paragraphs),
                'impact': '공격 패턴 관찰과 실제 공격 성공은 구분하며, 성공 여부는 인증·응답·세션 발급 등 추가 근거로 판단합니다.',
                'recommendation': [readable_text(finding.get('remedy'))],
                'method': finding.get('method', ''), 'url_path': evidence.get('url_path', ''),
                'status_code': evidence.get('status_code'), 'source_file': evidence.get('source_file', ''),
                'attack_probability': score, 'flow_count': evidence.get('flow_count'),
                'detected_flow_count': counts.get(label), 'class_probabilities': probabilities, 'class_counts': counts,
            }
            # normalize_network would infer a new severity from a probability.
            # Supplying explicit records to normalize_web avoids changing Scanner facts.
            normalized = template['normalize_web']([sanitize(record)])[0]
            normalized.update(scan_id=job['scan_id'], state=finding.get('state'),
                              finding_index=finding_index, owasp=finding.get('owasp'))
            (web if source == 'WEB' else network).append(normalized)
    return web, network


def dashboard_page(store):
    try:
        template = load_template()
    except (OSError, ValueError, KeyError, SyntaxError):
        st.error('통합 Dashboard 원본 파일을 확인할 수 없습니다. 배포 파일을 확인하세요.')
        return
    history = {job['scan_id']: job for job in store.history() if job.get('source') == 'external'}
    for key in ('current_report', 'external_report'):
        job = st.session_state.get(key)
        if job and job.get('source') == 'external':
            history[job['scan_id']] = job
    if not history:
        st.subheader(MENU)
        st.info('외부 공격 진단을 실행하거나 분석 파일을 업로드하면 웹·네트워크 결과를 확인할 수 있습니다.')
        return
    choices = sorted(history, key=lambda identity: history[identity].get('started_at', ''), reverse=True)
    identity = st.selectbox('분석 실행 선택 · Scan ID', choices, key='team_dashboard_scan')
    job = history[identity]
    st.caption(f"Scan ID: {identity} · 대상: {job.get('target', '—')}")
    screen = st.selectbox('결과 화면', SCREENS, key='team_dashboard_screen')
    for finding in job.get('results', []):
        if finding.get('state') in ('inconclusive', 'skipped'):
            st.warning(readable_text(finding.get('reason')) or '일부 자료를 수집하거나 분석하지 못했습니다. 상세 기술 근거를 확인하세요.')
    try:
        web, network = adapt_results(job, template)
    except (TypeError, ValueError, KeyError):
        st.error('선택한 결과의 웹·네트워크 데이터 형식을 확인하세요.')
        return
    if not web:
        st.info('이번 분석에서는 분석 가능한 웹 탐지 결과가 없습니다. 네트워크 분류와 웹 인증 로그의 교차 검증 여부는 상세 근거를 확인하세요.')
    if not network:
        st.info('이번 분석에서는 분석 가능한 네트워크 분류 결과가 없습니다.')
    # Both display sources come from this real unified Scanner snapshot.
    snapshot = store.directory(identity) / 'external_report.json'
    template['WEB_REPORT_PATH'] = snapshot
    template['NETWORK_REPORT_PATH'] = snapshot
    template['render'](template['CSS'])
    try:
        modified = datetime.fromisoformat(job.get('finished_at') or job['started_at']).astimezone(ZoneInfo('Asia/Seoul'))
    except (ValueError, KeyError, TypeError):
        modified = None
    if screen == '통합 Dashboard':
        template['page_dashboard'](web, network)
    elif screen in ('웹 공격 진단', '네트워크 공격 진단'):
        source = 'WEB' if screen == '웹 공격 진단' else 'NETWORK'
        template['page_source'](web if source == 'WEB' else network, source, modified)
    elif screen == '분석 결과 문서':
        template['page_report'](web, network, datetime.now(ZoneInfo('Asia/Seoul')))
    else:
        template['page_history'](web + network)
    st.download_button('원본 진단 JSON 다운로드', json.dumps(sanitize(job), ensure_ascii=False, indent=2),
                       identity + '_external_report.json', 'application/json', key='team_dashboard_download')
    with st.expander('상세 기술 근거 / Raw Evidence'):
        st.json(sanitize(job))
