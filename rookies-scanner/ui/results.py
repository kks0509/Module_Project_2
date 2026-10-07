from datetime import datetime
import json
from zoneinfo import ZoneInfo
import streamlit as st
from engine import summary
from llm.report_generator import VERDICTS
from sanitizing import sanitize
from ui.ai_document import build_document
from ui.result_table import result_table
from terminology import report_text


def local_time(value):
    try:
        return datetime.fromisoformat(value).astimezone(ZoneInfo('Asia/Seoul')).strftime('%Y-%m-%d %H:%M:%S KST')
    except (ValueError, TypeError):
        return value or '—'


def render_summary(job):
    st.subheader('진단 결과')
    st.write('Scan ID:', job['scan_id'])
    st.write('대상:', job.get('target', ''), '· Source:', job.get('source', 'internal'))
    st.caption(f"시작 {local_time(job.get('started_at'))} · 종료 {local_time(job.get('finished_at'))} · 총 요청 {job.get('requests', 0)}회")
    counts = summary(job)
    for col, (key, label) in zip(st.columns(5), VERDICTS.items()):
        col.metric(label, counts[key])
    for col, severity in zip(st.columns(3), ('high', 'medium', 'info')):
        col.metric(severity.upper(), sum(r.get('severity') == severity for r in job.get('results', [])))


def render_results(job, key='results'):
    if job.get('source') == 'external':
        from ui.external_scan import render_external
        render_external(job, key)
        return
    job = sanitize(report_text(job))
    render_summary(job)
    items = job.get('results', [])
    states = st.multiselect('판정 필터', list(VERDICTS.values()), key=key + '_states')
    selected = [r for r in items if not states or VERDICTS.get(r.get('state'), '판정 불가') in states]
    st.html(result_table(selected))
    for index, result in enumerate(selected):
        title = result.get('name', result.get('vulnerability', '진단'))
        with st.expander(f"{title} · {VERDICTS.get(result.get('state'), '판정 불가')} · {result.get('severity', 'info').upper()}"):
            e = result.get('evidence', {})
            st.write('대상 URL:', result.get('url'), '· Method:', result.get('method'))
            st.write('파라미터:', ', '.join(result.get('parameters', [])) or '없음')
            st.write('OWASP:', result.get('owasp', ''))
            st.write('판정 이유:', result.get('reason', e.get('reason', '')))
            admin = e.get('admin_authentication', e.get('authentication', {}).get('admin', {}))
            if admin:
                st.write('Admin Authentication · 관리자 인증')
                st.table([{'항목': label, '값': str(admin.get(field, '—'))}
                          for field, label in [('login_request_url', 'Login Request URL'), ('login_method', 'HTTP Method'),
                                               ('login_status', 'HTTP Status'), ('login_redirect_history', 'Redirect History'),
                                               ('login_final_url', 'Final URL'), ('authenticated', 'Authenticated'),
                                               ('form_fields', '로그인 Form Fields'),
                                               ('matched_success_path', 'Matched Success Path'),
                                               ('matched_success_markers', 'Matched Success Marker'),
                                               ('username_present', 'ID 입력 여부'), ('password_present', '비밀번호 입력 여부'),
                                               ('reason', '실패 사유')]])
            labels = {'request_url': 'Request URL', 'payload': 'Payload', 'http_status': 'HTTP Status',
                      'redirect_history': 'Redirect History', 'final_url': 'Final URL',
                      'detected_markers': '탐지된 Marker', 'marker_detected': 'Marker 탐지 여부',
                      'baseline_object_count': 'Baseline 결과 수', 'attack_object_count': 'Attack 결과 수',
                      'extra_object_count': '추가 객체 수', 'inconclusive_reason': '판정 불가 사유'}
            for field, label in labels.items():
                if field in e:
                    st.write(label + ':', e[field])
            traces = result.get('requests', [])
            if traces:
                st.caption('실제 요청·응답 요약 · 리다이렉트 후 GET과 최초 진단 Method는 구분됩니다.')
                st.dataframe([{'URL': t.get('url', ''), 'Method': t.get('method', ''), 'Status': t.get('status'),
                               '응답시간(ms)': t.get('elapsed_ms'), 'Final URL': t.get('final_url', '')}
                              for t in traces], hide_index=True, width='stretch')
            st.write('대응 방안:', result.get('remedy', ''))
            with st.expander('상세 디버깅 근거 · Baseline / Attack / 인증 / 관찰'):
                st.json(e)
                st.json(traces)
    st.download_button('리포트 JSON 다운로드', json.dumps(job, ensure_ascii=False, indent=2),
                       file_name='internal_report.json' if job.get('source', 'internal') == 'internal' else 'external_report.json',
                       mime='application/json', key=key + '_download')


def render_ai(value, job):
    if not value:
        st.info('진단 완료 후 AI 리포트 생성 버튼으로 보고서를 작성할 수 있습니다.')
        return
    if value.get('state') != 'done':
        st.warning(value.get('error', 'AI 리포트를 생성하지 못했습니다.'))
        return
    value, job = report_text(value), report_text(job)
    try:
        document = build_document(value, job)
    except ValueError as exc:
        st.warning(str(exc))
        return
    # One continuous, escaped document. JavaScript remains disabled.
    st.html(document)
    with st.expander('상세 기술 데이터'):
        st.caption('민감정보를 제거한 Scanner 원본 및 AI JSON')
        st.json(sanitize(job))
        st.json(sanitize(value))
    st.download_button('AI 리포트 JSON 다운로드', json.dumps(sanitize(value), ensure_ascii=False, indent=2),
                       file_name='ai_report.json', mime='application/json', key='ai_download_' + value['scan_id'])
