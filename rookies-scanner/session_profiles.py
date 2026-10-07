"""Versioned reusable settings; account passwords and consent are never saved."""
from copy import deepcopy
import json
import os
from pathlib import Path
import uuid
from core import validate_target
from profiles import DEFAULT

CHECKS = {'sqli': 'sqli', 'access_control': 'access', 'idor': 'idor',
          'auth_observation': 'brute', 'availability_observation': 'availability'}
IDOR_KEYS = {'request_type': 'mode', 'path': 'path', 'parameter': 'parameter', 'comparison': 'comparison',
             'object_a': 'a_id', 'object_b': 'b_id', 'marker_a': 'a_marker', 'marker_b': 'b_marker'}
MAX_BYTES = 262144
# These are fixed, invalid diagnostic payloads, not reusable account credentials.
PROBE_PASSWORDS = {'random', 'definitely_wrong_password'}
PASSWORD_FIELD_NAMES = {'password', 'passwd', 'passphrase', 'user_password', 'login_password'}


def _text(value, label, limit=4096):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f'{label}: 문자열 형식/길이를 확인하세요.')
    return value


def validate_rules(rules):
    if not isinstance(rules, dict) or not all(k in rules for k in ('login', 'sqli', 'access', 'idor', 'brute', 'availability')):
        raise ValueError('진단 규칙의 필수 항목이 누락됐습니다.')
    if not isinstance(rules['sqli'], list) or not isinstance(rules['access'], list) or any(
            not isinstance(rules[k], dict) for k in ('login', 'idor', 'brute', 'availability')):
        raise ValueError('진단 규칙 형식을 확인하세요.')
    def walk(value, path=()):
        if isinstance(value, dict):
            for key, item in value.items():
                folded = str(key).casefold()
                if any(s in folded for s in ('password', 'passwd', 'secret', 'token', 'cookie', 'authorization')):
                    fixed_probe = (folded == 'password' and len(path) == 3 and path[0] == 'sqli'
                                   and path[2] in ('data', 'baseline_data') and isinstance(item, str) and item in PROBE_PASSWORDS)
                    field_name = (path == ('login',) and folded == 'password_field' and
                                  isinstance(item, str) and item in PASSWORD_FIELD_NAMES)
                    if not (fixed_probe or field_name):
                        raise ValueError('진단 규칙에 비밀번호/토큰이 포함되어 있습니다. 계정 비밀번호는 메인 입력란만 사용하세요.')
                walk(item, path + (key,))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, path + (index,))
    walk(rules)
    return deepcopy(rules)


def export_profile(config, name='LMS Lab'):
    rules = validate_rules(config.get('profile', DEFAULT))
    saved = {'schema_version': 1, 'profile_name': _text(name, '프로파일 이름', 256),
             'target_origin': validate_target(config['target']),
             'admin_id': config.get('admin', {}).get('username', ''),
             'student_a_id': config.get('student_a', {}).get('username', ''),
             'student_b_id': config.get('student_b', {}).get('username', ''),
             'normal_keyword': config.get('normal_keyword', ''),
             'checks': {key: module in config.get('modules', []) for key, module in CHECKS.items()},
             'idor': {key: config.get('idor', {}).get(field, DEFAULT['idor'][field]) for key, field in IDOR_KEYS.items()},
             'rules': rules}
    import_profile(saved)  # Validate before touching a destination file.
    return saved


def import_profile(saved):
    if not isinstance(saved, dict) or saved.get('schema_version', 1) != 1:
        raise ValueError('지원하지 않는 프로파일 형식입니다.')
    name = _text(saved.get('profile_name', 'LMS Lab'), '프로파일 이름', 256)
    target = validate_target(_text(saved.get('target_origin'), '대상 origin'))
    checks, objects = saved.get('checks', {}), saved.get('idor', {})
    if not isinstance(checks, dict) or not isinstance(objects, dict):
        raise ValueError('검사 선택/IDOR 형식을 확인하세요.')
    if any(type(v) is not bool for v in checks.values()) or set(checks) - set(CHECKS):
        raise ValueError('검사 선택은 지원하는 모듈의 true/false 값이어야 합니다.')
    idor = {field: _text(objects.get(key, DEFAULT['idor'][field]), 'IDOR ' + key)
            for key, field in IDOR_KEYS.items()}
    if idor['mode'] not in ('query', 'path') or idor['comparison'] not in ('markers', 'response'):
        raise ValueError('IDOR 요청 방식/비교 방식을 확인하세요.')
    config = {'target': target, 'normal_keyword': _text(saved.get('normal_keyword', ''), '예비 검색어'),
              'modules': [module for key, module in CHECKS.items() if checks.get(key, False)],
              'idor': idor, 'profile': validate_rules(saved.get('rules', DEFAULT)),
              'authorized': False, 'active_opt_in': False}
    for role, key in (('admin', 'admin_id'), ('student_a', 'student_a_id'), ('student_b', 'student_b_id')):
        config[role] = {'username': _text(saved.get(key, ''), key, 256), 'password': ''}
    return name, config


def save_profile(path, config, name='LMS Lab'):
    path = Path(path)
    content = json.dumps(export_profile(config, name), ensure_ascii=False, indent=2).encode('utf-8')
    if len(content) > MAX_BYTES:
        raise ValueError('프로파일 크기 제한 256KiB를 초과했습니다.')
    # Fail immediately on permission errors rather than retrying temporary names.
    temporary = path.parent / ('.rookies-profile-' + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def load_profile(path):
    with Path(path).open('rb') as source:
        content = source.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise ValueError('프로파일 크기 제한 256KiB를 초과했습니다.')
    try:
        return import_profile(json.loads(content.decode('utf-8-sig')))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('UTF-8 JSON 프로파일 파일을 선택하세요.') from exc
