"""RAM-only input snapshot, independent of Streamlit widget lifecycle."""
from copy import deepcopy
import json
from profiles import DEFAULT

INPUT_STATE = '_scan_input_values'
ROLE_LABELS = {'admin': '관리자', 'student_a': '학생 A', 'student_b': '학생 B'}
DEFAULT_INPUTS = {
    'target_origin': 'http://10.163.130.121:5000',
    'admin_id': 'admin', 'student_a_id': 'student01', 'student_b_id': 'student02',
    'admin_password': '', 'student_a_password': '', 'student_b_password': '',
    'check_sqli': True, 'check_access': True, 'check_idor': True,
    'check_brute': False, 'check_availability': False,
    'idor_mode': 'query', 'idor_path': '/student/grades', 'idor_parameter': 'student_id',
    'idor_a_id': '2', 'idor_b_id': '3', 'idor_comparison': 'markers',
    'idor_a_marker': 'CSE101', 'idor_b_marker': 'DB202', 'normal_keyword': '',
    'diagnostic_rules': json.dumps(DEFAULT, ensure_ascii=False, indent=2),
    'authorized': False, 'active_opt_in': False,
}


def retain_input_values(state, *, submitted=False):
    """Only a submitted form may replace the RAM snapshot, never a stale widget."""
    values = {**deepcopy(DEFAULT_INPUTS), **deepcopy(state.get(INPUT_STATE, {}))}
    if submitted:
        for key in DEFAULT_INPUTS:
            if key in state:
                values[key] = deepcopy(state[key])
    state[INPUT_STATE] = values
    return values


def restore_input_values(state):
    values = retain_input_values(state)
    for key in DEFAULT_INPUTS:
        # Before widget construction, also repair defaults resurrected by a rerun.
        state[key] = deepcopy(values[key])


def config_from_input_values(state):
    """Validation and worker receive the same newly submitted immutable snapshot."""
    v = deepcopy(state[INPUT_STATE])
    try:
        rules = json.loads(v['diagnostic_rules'])
        if not isinstance(rules, dict):
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('진단 규칙 JSON 형식을 확인하세요.') from None
    config = {'target': v['target_origin'].strip(), 'profile': rules,
              'modules': [m for m in ('sqli', 'access', 'idor', 'brute', 'availability') if v['check_' + m]],
              'normal_keyword': v['normal_keyword'], 'authorized': v['authorized'], 'active_opt_in': v['active_opt_in'],
              'idor': {'mode': v['idor_mode'], 'path': v['idor_path'], 'parameter': v['idor_parameter'],
                       'a_id': v['idor_a_id'], 'b_id': v['idor_b_id'], 'comparison': v['idor_comparison'],
                       'a_marker': v['idor_a_marker'], 'b_marker': v['idor_b_marker']}}
    for role in ROLE_LABELS:
        # ID whitespace is accidental; password whitespace may be intentional.
        config[role] = {'username': v[role + '_id'].strip(), 'password': v[role + '_password']}
    return config


def missing_account_fields(config):
    required = set()
    if 'sqli' in config['modules']:
        required.update(('admin', 'student_a'))
    if 'access' in config['modules'] or 'brute' in config['modules']:
        required.add('student_a')
    if 'idor' in config['modules']:
        required.update(('student_a', 'student_b'))
    return [ROLE_LABELS[role] + ' ' + label for role in ROLE_LABELS if role in required
            for field, label in (('username', 'ID'), ('password', '비밀번호')) if not config[role][field]]


def session_passwords(state):
    return tuple(state.get(INPUT_STATE, {}).get(role + '_password', '') for role in ROLE_LABELS)
