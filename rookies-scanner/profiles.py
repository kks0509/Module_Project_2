"""Declarative LMS endpoints and success conditions; credentials stay in UI memory."""
from copy import deepcopy

DEFAULT = {
    'name': 'rookies-docker-lms',
    'student_identity': {'paths': ['/student/profile', '/student/mypage', '/student/info'],
                         'fields': {'student_number': ['student_no', 'student_number', 'student_num', '학번', '학적번호', 'student number'],
                                    'name': ['student_name', 'full_name', 'name', '이름', '성명', '학생명']}},
    'login': {'path': '/login', 'method': 'POST', 'username_field': 'username', 'password_field': 'password',
              'success_paths': ['/admin', '/home', '/student', '/student/dashboard', '/student/grades'],
              'admin_success_paths': ['/admin'], 'student_success_paths': ['/student'],
              'student_dashboard_path': '/student',
              'admin_markers': ['LMS 관리자', 'ADMIN'], 'student_markers': ['STUDENT', 'Dashboard', '성적 조회'],
              'admin': {'path': '/admin', 'marker': 'LMS 관리자'},
              'student_a': {'path': '/student', 'marker': 'STUDENT'},
              'student_b': {'path': '/student', 'marker': 'STUDENT'}},
    'sqli': [
        {'name': 'SQL Injection · 로그인 우회', 'method': 'POST', 'path': '/login', 'parameter': 'username',
         'payload': "' OR 1=1#", 'data': {'password': 'random'},
         'baseline_data': {'password': 'definitely_wrong_password'},
         'success_condition': {'kind': 'authenticated_page', 'path': '/admin', 'marker': 'LMS 관리자', 'redirect_path': '/admin'}},
        {'name': 'SQL Injection · 학생 검색 조건 우회', 'method': 'GET', 'path': '/admin/students',
         'parameter': 'keyword', 'baseline_value': '', 'payload': "' OR 1=1#", 'role': 'admin',
         'success_condition': {'kind': 'object_expansion', 'max_baseline_objects': 5,
                               'link_pattern': r'^/admin/students/([^/]+)/?$'}},
    ],
    'access': [
        {'path': '/admin', 'markers': ['관리자 대시보드', 'LMS 관리자', 'ADMIN']},
        {'path': '/admin/students', 'marker': '학생 관리'},
        {'path': '/admin/grades', 'marker': '성적 관리'},
        {'path': '/admin/courses', 'marker': '강의 관리'},
    ],
    'idor': {'mode': 'query', 'path': '/student/grades', 'parameter': 'student_id',
             'a_id': '2', 'b_id': '3', 'comparison': 'markers', 'a_marker': 'CSE101', 'b_marker': 'DB202'},
    'brute': {'path': '/login', 'role': 'student_a', 'delay_threshold_ms': 1000, 'delay_ratio': 3,
              'lock_markers': ['계정 잠금', '계정이 잠겼', 'account locked']},
    'availability': {'path': '/login'},
}


def profile(config):
    return deepcopy(config.get('profile', DEFAULT))


def login_settings(config):
    """Fill absent login defaults in old/partial profiles, preserve explicit rules."""
    provided = profile(config).get('login', {})
    if not isinstance(provided, dict):
        raise ValueError('내부 로그인 설정을 확인하세요.')
    settings = {**deepcopy(DEFAULT['login']), **deepcopy(provided)}
    for role in ('admin', 'student_a', 'student_b'):
        settings[role] = {**deepcopy(DEFAULT['login'][role]), **deepcopy(provided.get(role, {}))}
    return settings
