import importlib.util
import json
import os
import shutil
import streamlit as st
from external.config import ExternalConfig, web_log_path, dumpcap_path
from external.contract import VERDICTS
from external.task import ExternalTask
from sanitizing import sanitize


def external_inputs(store):
    st.subheader('외부 공격 진단')
    st.caption('로그·네트워크 수집 → 웹 패턴 선별 / ML 분류 → JSON → AI 분석 리포트')
    st.info('관측한 공격 의심 신호를 분석합니다. 패턴·ML 분류만으로 공격 성공을 확정하지 않습니다.')
    task = st.session_state.get('external_task')
    busy = bool(task and not task.finished)
    if 'external_interface' not in st.session_state:
        st.session_state.external_interface = st.session_state.get(
            'external_interface_value', os.environ.get('EXTERNAL_INTERFACE', ''))
    with st.form('external_inputs'):
        target = st.text_input('외부 진단 대상 origin', value='http://10.163.130.121:5000', key='external_target', disabled=busy)
        mode = st.radio('입력 방식', ('기존 파일 분석', '서버에서 제한 시간 수집'), key='external_mode', disabled=busy)
        uploads = st.file_uploader('분석 파일 · PCAP / Flow CSV / 웹 로그 / 팀 NETWORK JSON',
            type=['pcap', 'pcapng', 'csv', 'json', 'jsonl', 'log', 'txt'], accept_multiple_files=True,
            max_upload_size=16, disabled=busy, key='external_files')
        st.caption('파일당 16 MB · 전체 32 MB · 최대 10개. 서버 수집을 선택하면 업로드 파일은 사용하지 않습니다.')
        a, b = st.columns(2)
        network = a.checkbox('네트워크 수집', value=True, key='external_network', disabled=busy)
        web = b.checkbox('웹 로그 수집', value=True, key='external_web', disabled=busy)
        interface = a.text_input('수집 인터페이스 직접 입력',
            key='external_interface', disabled=busy,
            placeholder='예: ztxooopmrp / enp0s3 / br-... / lo')
        a.caption('입력한 인터페이스를 그대로 사용합니다. 자동 감지 값으로 변경하지 않습니다.')
        duration = b.number_input('수집 시간(초)', min_value=5, max_value=120, value=30, step=5, disabled=busy)
        st.caption('서버 수집 시 사용할 인터페이스를 직접 입력하세요. 시작 직전 존재 여부를 확인하며 대상 origin의 TCP 포트로 수집합니다. WEB 로그 경로는 서버 환경변수로 설정합니다.')
        authorized = st.checkbox('이 실습 대상의 로그·네트워크를 분석할 권한이 있습니다.', key='external_authorized', disabled=busy)
        started = st.form_submit_button('외부 진단 시작', type='primary', disabled=busy)
    st.session_state.external_interface_value = interface
    if started:
        try:
            config = ExternalConfig(target=target, authorized=authorized,
                mode='files' if mode == '기존 파일 분석' else 'live',
                uploads=[(f.name, f.getvalue()) for f in uploads] if mode == '기존 파일 분석' else [],
                duration=int(duration), network=network, web=web, interface=interface.strip(),
                auto_capture=False, capture_port_only=True)
            st.session_state.external_task = ExternalTask(config, store)
            st.session_state.pop('ai_report', None)
        except ValueError as exc:
            st.error(str(exc))
    with st.expander('수집 준비 상태'):
        for name in ('catboost', 'cicflowmeter', 'scapy'):
            st.write(('✓ ' if importlib.util.find_spec(name) else '✕ ') + name)
        st.write(('✓ ' if shutil.which(dumpcap_path()) else '✕ ') + '패킷 수집기 dumpcap')
        st.write(('✓ ' if web_log_path().is_file() else '✕ ') + '서버 웹 로그 파일')
        st.caption('네트워크 분석 패키지: bash setup-external-ubuntu.sh · 웹 로그: EXTERNAL_WEB_LOG_PATH')


@st.fragment(run_every=.5)
def external_progress():
    task = st.session_state.get('external_task')
    if not task:
        return
    was_finished = task.finished
    value = task.poll()
    percent = min(100, int(value.get('completed', 0) / 3 * 100))
    if task.error:
        st.error(task.error)
    else:
        label = value.get('module', '외부 진단 준비')
        if task.finished:
            label = '외부 진단 완료' if value.get('state') == 'done' else '외부 진단 중지'
        st.progress(percent, text=f'{label} · {percent}%')
        st.caption('Scan ID: ' + task.scan_id)
    if not task.finished and st.button('외부 진단 중지', key='external_cancel'):
        task.cancel.set()
    if task.finished and not was_finished:
        if task.job:
            st.session_state.external_report = task.job
            st.session_state.current_report = task.job
        st.rerun()


def render_external(job, key):
    from html import escape
    from ui.ai_document import facts_table
    job = sanitize(job)
    st.subheader('외부 공격 관찰 결과')
    st.write('Scan ID:', job['scan_id'], '· Source: external')
    st.write('대상:', job.get('target', ''))
    c = job.get('collection', {})
    capture = c.get('capture', {})
    if capture:
        st.write('사용한 수집 인터페이스:', capture.get('interface', ''))
        if capture.get('capture_filter'):
            st.caption('Capture Filter: ' + capture['capture_filter'])
        if 'packet_count' in capture:
            labels = {'completed': 'NETWORK 수집 완료', 'empty': 'NETWORK 수집 완료 · 분석 가능한 패킷 없음',
                      'failed': 'NETWORK 수집 실패', 'cancelled': 'NETWORK 수집 중지', 'starting': 'NETWORK 수집 준비'}
            st.caption(f"{labels.get(capture.get('state'), 'NETWORK 수집 상태')} · PCAP {capture.get('pcap_size_bytes', 0)} bytes · 패킷 수: {capture.get('packet_count')}")
            with st.expander('NETWORK 수집 상세 기술 근거'):
                st.json(capture)
    for col, label, number in zip(st.columns(4), ('웹 요청', '네트워크 Flow', '공격 의심 항목', '판정 불가'),
                                 (c.get('web_record_count', 0), c.get('flow_count', 0),
                                  sum(r['state'] == 'suspicious' for r in job['results']),
                                  sum(r['state'] == 'inconclusive' for r in job['results']))):
        col.metric(label, number)
    st.caption(f"시작 {job.get('started_at', '')} · 종료 {job.get('finished_at', '')} · 능동 공격 요청 0회")
    st.caption('웹 패턴은 파일·공격 유형별로 묶고 전체 일치 요청 수와 최대 5개 대표 요청을 보관합니다.')
    if c.get('omitted_event_count', 0):
        st.info(f"관측 이벤트 {c['observed_event_count']}개 중 JSON은 {c['retained_event_count']}개 표본을 보관합니다. 전체 요청·Flow·패턴별 집계는 유지됩니다.")
    for index, result in enumerate(job.get('results', []), 1):
        e = result.get('evidence', {})
        st.markdown(f"#### {index}. {result.get('name', '외부 관찰')}")
        st.write(VERDICTS.get(result['state'], '판정 불가'), '·', result['severity'].upper(), '·', e.get('source', '수집/분석 상태'))
        st.write(result['reason'])
        if e.get('source') == 'NETWORK':
            st.caption('모델 점수는 전체 Flow의 클래스별 평균입니다. 공격 성공 확률을 의미하지 않습니다.')
            st.table([{'Predicted_Label': label, 'Flow 수': e['class_counts'][label], '평균 모델 점수': probability}
                      for label, probability in e.get('class_probabilities', {}).items()])
            st.write('관측 시간:', e.get('timestamp'), '~', e.get('last_detected_at'))
            st.caption('기존 팀 JSON 분류 가져오기' if e.get('classification_origin') == 'imported_team_json' else '제공된 CatBoost 모델로 분류')
        elif e.get('source') == 'WEB':
            st.html(facts_table([('일치한 요청 수', e.get('event_count', 1)),
                                 ('대표 요청', f"{e.get('method')} {e.get('url_path')}"),
                                 ('HTTP Status', e.get('status_code')), ('관측 시간', e.get('timestamp')),
                                 ('일치 패턴', ', '.join(item.get('matched_pattern', '') for item in e.get('evidence', [])))]))
        with st.expander('상세 기술 근거'):
            st.json(e)
    st.download_button('외부 진단 JSON 다운로드', json.dumps(job, ensure_ascii=False, indent=2),
                       file_name='external_report.json', mime='application/json', key=key + '_external_json')
    st.download_button('ML·웹 로그 분류 JSON 다운로드', json.dumps({'source': 'external', 'scan_id': job['scan_id'],
                       'inputs': job.get('pipeline_inputs', [])}, ensure_ascii=False, indent=2),
                       file_name='pipeline_input.json', mime='application/json', key=key + '_pipeline_json')
