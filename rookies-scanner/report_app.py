"""Read-only Streamlit report; never executes scans."""
import json
import os
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import streamlit as st
from engine import summary
from classification import owasp_for

LABELS = {'vulnerable': '취약 확인', 'not_detected': '이번 검사에서 미탐지',
          'inconclusive': '판정 불가', 'skipped': '미실행', 'observation_required': '관찰 필요'}
st.set_page_config(page_title='ROOKIES Scanner · 진단 리포트', page_icon='🛡️', layout='wide')
st.title('ROOKIES Scanner')
st.caption('LMS Security Assessment Tool')
st.subheader('LMS 취약점 진단 리포트')
path = os.environ.get('ROOKIES_REPORT_FILE')
if not path:
    st.info('데스크톱 앱에서 진단 후 「리포트 작성」을 눌러주세요.')
    st.stop()
try:
    job = json.loads(Path(path).read_text(encoding='utf-8'))
except (OSError, ValueError):
    st.error('리포트 파일을 읽을 수 없습니다. 앱에서 다시 작성하세요.')
    st.stop()
st.caption('SK 쉴더스 루키즈 · 허가된 LMS 실습 환경')
st.write('Scan ID:', job.get('scan_id', '이전 리포트 · 식별자 없음'))
st.write('대상:', job['target'])
for key, label in (('started_at', '시작'), ('finished_at', '종료')):
    if job.get(key):
        dt = datetime.fromisoformat(job[key]).astimezone(ZoneInfo('Asia/Seoul'))
        st.write(f'{label}: {dt:%Y-%m-%d %H:%M:%S} KST')
if job['state'] == 'cancelled':
    st.warning('중지된 진단의 부분 리포트입니다. 실행하지 않은 검사는 평가하지 않았습니다.')
st.write(f"완료 모듈 {job['completed']}/{job['total']} · 요청 {job['requests']}회")
counts = summary(job)
for col, (key, label) in zip(st.columns(len(LABELS)), LABELS.items()):
    col.metric(label, counts[key])
st.info('미탐지는 검사 범위 내 결과입니다. 반복 인증은 실패 5회 범위의 방어 평가이며 가용성은 관찰 필요로 기록합니다.')
selected = st.multiselect('표시할 판정', list(LABELS.values()), default=list(LABELS.values()))
rows = [r for r in job['results'] if LABELS[r['state']] in selected]
st.dataframe([{'취약점': r['name'], '대상 URL': r['url'], 'Method': r.get('method', ''), '파라미터': ', '.join(r.get('parameters', [])), '판정': LABELS[r['state']], '위험도': r['severity'].upper(), 'OWASP': r.get('owasp', owasp_for(r['module']))} for r in rows], hide_index=True, width='stretch')
st.subheader('상세 근거 및 대응 방안')
for index, r in enumerate(rows, 1):
    with st.expander(f"{index}. {r['name']} · {LABELS[r['state']]} · {r['severity'].upper()}"):
        st.write('대상 URL:', r['url'])
        st.write('위험도:', r['severity'].upper(), 'OWASP:', r.get('owasp', owasp_for(r['module'])))
        st.write('Scan ID:', r.get('scan_id', job.get('scan_id', '이전 리포트 · 식별자 없음')))
        st.write('HTTP Method:', r.get('method', ''), '사용한 파라미터:', ', '.join(r.get('parameters', [])))
        st.write('판정 이유:', r.get('reason', '기존 버전 결과: 근거 항목을 확인하세요.'))
        if r['module'] == 'idor':
            st.markdown('**학생 로그인 / IDOR 객체 요청 근거**')
            for role, label in (('student_a', '학생 A'), ('student_b', '학생 B')):
                login = r['evidence'].get('authentication', {}).get(role, {})
                st.write(label, '인증 성공:', login.get('authenticated'), 'login POST status:', login.get('login_post_status'))
                st.write('login final URL:', login.get('login_final_url'), 'student marker detected:', login.get('student_markers_detected', []),
                         'session cookie 존재:', login.get('session_cookie_present'))
                st.write('login redirect history:', login.get('login_redirect_history', []))
                if login.get('reason'):
                    st.write('인증 검증 사유:', login['reason'])
            for phase, obj in r['evidence'].get('idor_requests', {}).items():
                st.write(phase, 'IDOR 요청 URL:', obj.get('request_url'), 'IDOR 요청 status:', obj.get('http_status'),
                         '최종 status:', obj.get('final_status'), 'IDOR final URL:', obj.get('final_url'))
                st.write('객체 marker:', obj.get('detected_markers', []), '루트/로그인 이동:', obj.get('redirected_to_root_or_login'),
                         '객체 redirect history:', obj.get('redirect_history', []))
            if r['evidence'].get('session_rechecks'):
                st.write('객체 요청 후 Dashboard 세션 재확인:', r['evidence']['session_rechecks'])
        if r['module'] == 'sqli' or r['state'] == 'inconclusive':
            e = r['evidence']
            st.markdown('**진단 디버깅 근거**')
            st.write('요청 URL:', e.get('request_url', r['url']))
            st.write('Method:', e.get('method', r.get('method', '')),
                     'HTTP Status:', e.get('http_status'))
            st.write('Parameters:', r.get('parameters', []), 'Payload:', e.get('payload', {}))
            st.write('Final URL:', e.get('final_url', ''))
            st.write('Redirect History:', e.get('redirect_history', []))
            st.write('Baseline marker:', e.get('baseline_marker', []),
                     'Attack marker:', e.get('attack_marker', []))
            st.write('관리자 marker 탐지 여부:', e.get('admin_marker_detected', False))
            st.write('Marker 탐지 여부:', e.get('marker_detected', False))
            st.write('Baseline object count:', e.get('baseline_object_count'),
                     'Attack object count:', e.get('attack_object_count'),
                     'Extra object count:', e.get('extra_object_count'))
            acquisition = e.get('normal_keyword_acquisition', {})
            if acquisition:
                sources = {'student_profile': '학생 A 본인 정보에서 자동 추출', 'manual_input': '사용자 예비 입력값',
                           'profile_fallback': '프로파일 예비 입력값', 'unavailable': '검색어 획득 실패'}
                st.write('정상 검색어 획득:', sources.get(acquisition.get('source'), '확인 불가'))
                if acquisition.get('source_url'):
                    st.write('본인 정보 URL:', acquisition['source_url'], '추출 필드:', acquisition.get('field'))
                if acquisition.get('automatic_failure_reason'):
                    st.write('자동 추출 실패 사유:', acquisition['automatic_failure_reason'])
                st.json(acquisition)
            if r['state'] == 'inconclusive':
                st.warning('판정 불가 사유: ' + e.get('inconclusive_reason', r.get('reason', '근거 부족')))
        left, right = st.columns(2)
        with left:
            st.markdown('**판정 근거**')
            st.json(r['evidence'])
        with right:
            st.markdown('**요청 / 응답 요약**')
            st.dataframe([{'Method': t['method'], '실제 요청 URL': t['url'],
                           'Payload': json.dumps(t.get('payload', {}), ensure_ascii=False),
                           'Status Code': t['status'], 'Redirect URL': t.get('redirect_url', ''),
                           'Redirect History': json.dumps(t.get('redirect_history', []), ensure_ascii=False),
                           'Final URL': t.get('final_url', t['url']),
                           '탐지 marker': ', '.join(t.get('detected_markers', []))}
                          for t in r['requests']], hide_index=True, width='stretch')
            st.json(r['requests'])
        st.markdown('**대응 방안**')
        st.write(r['remedy'])
st.download_button('리포트 JSON 다운로드', json.dumps(job, ensure_ascii=False, indent=2),
                   file_name='rookies-scanner-report.json', mime='application/json')
