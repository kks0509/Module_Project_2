from copy import deepcopy
import streamlit as st
from connection_check import check_connection, connection_message
from web_tasks import ScanTask
from ui.scan_inputs import (restore_input_values, retain_input_values,
                            config_from_input_values, missing_account_fields)


def submit_inputs():
    # Streamlit runs this after receiving all form fields, before the rerun.
    retain_input_values(st.session_state, submitted=True)


def input_config():
    restore_input_values(st.session_state)
    task = st.session_state.get('scan_task')
    busy = bool(task and not task.finished)
    st.subheader('내부 취약점 진단')
    with st.form('internal_scan_inputs', clear_on_submit=False, enter_to_submit=False):
        st.caption('입력 후 대상 연결 확인 또는 진단 시작을 눌러주세요. 입력값은 현재 세션에서 유지됩니다.')
        st.text_input('대상 Origin', key='target_origin', disabled=busy)
        for col, role, title in zip(st.columns(3), ('admin', 'student_a', 'student_b'), ('관리자', '학생 A', '학생 B')):
            with col:
                st.text_input(title + ' ID', key=role + '_id', disabled=busy)
                st.text_input(title + ' 비밀번호', type='password', key=role + '_password', disabled=busy)
        for col, code, label in zip(st.columns(5), ('sqli', 'access', 'idor', 'brute', 'availability'),
                                    ('SQL Injection', '접근 제어', 'IDOR', '반복 인증 관찰', '가용성 관찰')):
            col.checkbox(label, key='check_' + code, disabled=busy)
        with st.expander('IDOR 설정', expanded=True):
            a, b, c = st.columns(3)
            a.selectbox('요청 방식', ('query', 'path'), key='idor_mode', disabled=busy)
            b.text_input('IDOR 경로', key='idor_path', disabled=busy,
                         help='path 방식은 /objects/{id}처럼 {id}를 사용하세요.')
            c.text_input('객체 파라미터', key='idor_parameter', disabled=busy)
            a, b, c = st.columns(3)
            a.text_input('A 객체 ID', key='idor_a_id', disabled=busy)
            b.text_input('B 객체 ID', key='idor_b_id', disabled=busy)
            c.selectbox('비교 방식', ('markers', 'response'), key='idor_comparison', disabled=busy)
            a, b = st.columns(2)
            a.text_input('A 식별 문자열', key='idor_a_marker', disabled=busy)
            b.text_input('B 식별 문자열', key='idor_b_marker', disabled=busy)
        st.text_input('정상 검색어 · 예비값 (선택)', key='normal_keyword', disabled=busy,
                      help='학생 A 본인 정보에서 학번·이름 자동 추출을 먼저 시도합니다.')
        # Endpoint/marker rules remain in the RAM snapshot and engine profile.
        # LMS users do not edit diagnostic_rules through a widget.
        st.checkbox('이 대상은 제가 진단 권한을 가진 실습 환경입니다.', key='authorized', disabled=busy)
        st.checkbox('반복 인증 최대 5회 / 가용성 동시 2개·12개 표본 검사를 선택해 실행합니다.',
                     key='active_opt_in', disabled=busy)
        a, b = st.columns(2)
        with a:
            connected = st.form_submit_button('대상 연결 확인', disabled=busy, width='stretch',
                                               on_click=submit_inputs, key='connect_submit')
        with b:
            started = st.form_submit_button('진단 시작', type='primary', disabled=busy, width='stretch',
                                             on_click=submit_inputs, key='scan_submit')
    retain_input_values(st.session_state)
    try:
        config = config_from_input_values(st.session_state)
    except ValueError as exc:
        st.error(str(exc))
        return None
    if connected:
        with st.spinner('대상 서버 연결을 확인하고 있습니다...'):
            # Only the origin and rules are needed; do not pass account credentials.
            result = check_connection({'target': config['target'], 'authorized': config['authorized'],
                                       'profile': deepcopy(config['profile'])})
        st.session_state.connection = result
    if started:
        missing = missing_account_fields(config)
        if config['authorized'] is not True:
            st.error('이 대상에 대한 진단 권한 확인을 체크하세요.')
        elif missing:
            st.error('선택한 검사에 필요한 실습 계정 ID와 비밀번호를 입력하세요. 누락: ' + ', '.join(missing))
        else:
            try:
                st.session_state.scan_task = ScanTask(config, st.session_state.report_store)
                st.session_state.pop('current_report', None)
                st.session_state.pop('ai_report', None)
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    if st.session_state.get('connection'):
        st.text(connection_message(st.session_state.connection))
        with st.expander('연결 확인 · 상세 기술 데이터'):
            st.json(st.session_state.connection)
    return config
