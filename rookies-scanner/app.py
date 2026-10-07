"""Single web application. Run: python -m streamlit run app.py."""
from pathlib import Path
import streamlit as st
from engine import summary
from llm.client import ReportGenerationError
from llm.report_generator import generate_report
from report_store import ReportStore, ai_failure
from ui.internal_scan import input_config
from ui.scan_inputs import retain_input_values, session_passwords
from ui.results import render_results, render_ai, local_time
from ui.external_scan import external_inputs, external_progress
from external.llm_report import generate_report as generate_external_report
from ui.team_dashboard import dashboard_page, MENU as TEAM_DASHBOARD_MENU

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / '.env', override=False)
except ImportError:
    pass

st.set_page_config(page_title='ROOKIES Scanner', page_icon='🛡️', layout='wide')
# Preserve submitted inputs even when a different menu stops rendering widgets.
retain_input_values(st.session_state)
if 'report_store' not in st.session_state:
    st.session_state.report_store = ReportStore()
store = st.session_state.report_store
page = st.sidebar.radio('메뉴', ('통합 Dashboard', '내부 취약점 진단', '외부 공격 진단', 'AI 분석 리포트', '진단 이력', TEAM_DASHBOARD_MENU))
if page != TEAM_DASHBOARD_MENU:
    st.title('ROOKIES Scanner')
    st.caption('LMS Security Assessment Platform')
st.sidebar.caption('규칙 기반 진단 · 허가된 실습 환경')


@st.fragment(run_every=0.5)
def live_progress():
    task = st.session_state.get('scan_task')
    if not task:
        if page == '내부 취약점 진단':
            st.progress(0, text='진단 시작 전 · 0%')
        return
    was_finished = task.finished
    value = task.poll()
    total, completed = value.get('total', 0), value.get('completed', 0)
    percent = min(100, int(completed / total * 100)) if total else 0
    if task.error:
        st.error(task.error)
    elif task.finished:
        done = value.get('state') == 'done'
        st.progress(100 if done else percent, text=f"{'진단 완료' if done else '진단 중지'} · {completed}/{total} · {100 if done else percent}%")
        if task.save_error:
            st.error(task.save_error)
        if not was_finished:
            st.session_state.current_report = task.job
    else:
        name = value.get('module', '진단 준비')
        st.progress(percent, text=f"진단 진행 중 · {name} ({value.get('module_index', 1)}/{total}) · {percent}%")
        st.caption('Scan ID: ' + task.scan_id)
        if st.button('진단 중지', key='stop_scan'):
            task.cancel.set()
            st.info('현재 요청이 끝나면 중지합니다.')
    if not was_finished and task.finished:
        # Full rerun also re-enables settings/buttons and renders the final report.
        st.rerun()


def ai_controls(job, key):
    if job.get('state') != 'done' or not job.get('results'):
        st.info('AI 보고서는 진단을 완료한 뒤 생성할 수 있습니다.')
        return
    if st.button('AI 리포트 생성', key=key, type='primary'):
        st.session_state.current_report = job
        # Persist rule evidence first. API failures never change this snapshot.
        try:
            store.save(job)
        except (OSError, ValueError):
            st.error('기존 진단 결과를 저장하지 못했습니다. reports 폴더 권한을 확인하세요.')
            return
        with st.spinner('AI 리포트를 생성하고 있습니다...'):
            try:
                secrets = session_passwords(st.session_state)
                generator = generate_external_report if job.get('source') == 'external' else generate_report
                result = generator(job, secrets=secrets)
            except ReportGenerationError as exc:
                result = ai_failure(job['scan_id'], str(exc))
                result['source'] = job.get('source', 'internal')
            try:
                store.save_ai(job['scan_id'], result)
            except (OSError, ValueError):
                st.error('AI 결과를 파일로 저장하지 못했습니다. 기존 진단 결과는 저장되어 있습니다.')
        st.session_state.ai_report = result
    st.caption('진단 결과를 기반으로 AI 보안 진단 리포트를 생성합니다.')
    current = st.session_state.get('ai_report')
    if not current or current.get('scan_id') != job['scan_id']:
        try:
            current = store.load_ai(job['scan_id'])
        except (OSError, ValueError):
            current = None
    if current and current.get('state') == 'failed':
        st.warning('AI 리포트를 생성하지 못했습니다. 기존 진단 결과는 정상적으로 저장되었습니다.')
        st.caption(current.get('error', '서버 설정을 확인하세요.'))
    else:
        render_ai(current, job)


if page == '내부 취약점 진단':
    input_config()
elif page == '외부 공격 진단':
    external_inputs(store)
live_progress()
external_progress()
job = st.session_state.get('current_report')
if job and job.get('source', 'internal') == 'internal':
    st.session_state.internal_report = job
if page == '통합 Dashboard':
    st.subheader('LMS 통합 보안 Dashboard')
    history = store.history()
    internal = job if job and job.get('source', 'internal') == 'internal' else next((j for j in history if j.get('source') == 'internal'), None)
    a, b = st.columns(2)
    with a:
        st.subheader('내부 취약점 진단')
        if internal:
            count = summary(internal)
            st.metric('취약 확인', count['vulnerable'])
            st.write('HIGH:', sum(r.get('severity') == 'high' for r in internal['results']),
                     '· MEDIUM:', sum(r.get('severity') == 'medium' for r in internal['results']))
            st.caption('Scan ID: ' + internal['scan_id'])
        else:
            st.info('내부 취약점 진단 메뉴에서 새 진단을 시작하세요.')
    with b:
        st.subheader('외부 공격 진단')
        external = st.session_state.get('external_report') or next((j for j in history if j.get('source') == 'external'), None)
        if external:
            st.metric('공격 의심', sum(r.get('state') == 'suspicious' for r in external['results']))
            st.write('Flow:', external.get('collection', {}).get('flow_count', 0))
            st.caption('Scan ID: ' + external['scan_id'])
        else:
            st.info('외부 공격 진단 메뉴에서 로그·네트워크를 분석하세요.')
    if internal:
        render_results(internal, 'dashboard')
elif page == '내부 취약점 진단':
    internal = (job if job.get('source', 'internal') == 'internal' else st.session_state.get('internal_report')) if job else None
    if internal:
        render_results(internal, 'internal')
        ai_controls(internal, 'internal_ai')
elif page == '외부 공격 진단':
    external = st.session_state.get('external_report') or next((j for j in store.history() if j.get('source') == 'external'), None)
    if external:
        render_results(external, 'external')
        ai_controls(external, 'external_ai')
elif page == 'AI 분석 리포트':
    if job:
        ai_controls(job, 'ai_page')
    else:
        st.info('현재 진단이 없습니다. 내부 취약점 진단을 실행하거나 진단 이력에서 결과를 열어주세요.')
elif page == TEAM_DASHBOARD_MENU:
    dashboard_page(store)
elif page == '진단 이력':
    st.subheader('진단 이력')
    history = store.history()
    if not history:
        st.info('저장된 진단이 없습니다.')
    else:
        choices = {f"{j['scan_id']} · {j.get('source', 'internal')} · {local_time(j.get('started_at'))}": j for j in history}
        selected = st.selectbox('저장된 진단', list(choices))
        selected_job = choices[selected]
        render_results(selected_job, 'history')
        if st.button('이 진단을 AI 분석 화면에서 열기'):
            st.session_state.current_report = selected_job
            st.session_state.pop('ai_report', None)
            st.success('AI 분석 리포트 메뉴에서 확인할 수 있습니다.')
        try:
            render_ai(store.load_ai(selected_job['scan_id']), selected_job)
        except (OSError, ValueError):
            st.warning('저장된 AI 보고서를 읽지 못했습니다. 원본 진단 결과는 위에서 확인할 수 있습니다.')
