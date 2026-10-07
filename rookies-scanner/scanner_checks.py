"""Configurable SQL Injection plugins and bounded checks; classification is rule based."""
import re
import statistics
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit, quote, urljoin
from concurrent.futures import ThreadPoolExecutor
from core import finding, detected
from auth import AuthManager
from profiles import profile
from sqli_checks import sqli


def parameter_path(path, key, value):
    p = urlsplit(path)
    if not path.startswith('/') or path.startswith('//') or p.scheme or p.netloc or p.fragment:
        raise ValueError('파라미터 경로는 동일 origin의 상대 경로여야 합니다.')
    pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != key]
    return urlunsplit(('', '', p.path, urlencode(pairs + [(key, value)]), ''))


def denied(r, login_path):
    return r.status in (401, 403, 404) or (r.status in (301, 302, 303, 307, 308) and urlsplit(r.location).path == login_path) or (
        bool(r.history) and urlsplit(r.url).path == login_path)


def access(ctx):
    auth = AuthManager(ctx)
    results = []
    specs = profile(ctx.config)['access']
    start = len(ctx.traces)
    try:
        student = auth.authenticated('student_a')
    except Exception as exc:
        for spec in specs:
            result = finding(ctx, 'access', 'Broken Access Control · 관리자 기능', spec['path'], 'inconclusive',
                {'reason': '학생 A 세션 인증을 확인하지 못해 이 경로를 비교하지 못했습니다.',
                 'authentication': auth.evidence, 'error_type': type(exc).__name__,
                 'detail': str(exc)[:300] if isinstance(exc, ValueError) else '연결 또는 요청 한도를 확인하세요.'},
                '계정 및 로그인 검증 마커를 확인하세요.', traces=ctx.traces[start:])
            result.update(method='GET', parameters=[])
            results.append(result)
        return results
    admin = None
    try:
        admin = auth.authenticated('admin')
    except Exception as exc:
        auth.evidence['admin_error'] = type(exc).__name__
    login_path = profile(ctx.config)['login']['path']
    for spec in specs:
        ctx.progress('Broken Access Control · ' + spec['path'])
        path = spec['path']
        markers = spec.get('markers', [spec.get('marker', '')])
        start = len(ctx.traces)
        try:
            student_probe = student.request(path)
            low = student.follow(student_probe)
        except Exception as exc:
            result = finding(ctx, 'access', 'Broken Access Control · 관리자 기능', path, 'inconclusive',
                {'reason': '이 경로의 요청/응답 비교를 완료하지 못했습니다.', 'error_type': type(exc).__name__},
                '대상 연결 상태 및 경로 설정을 확인하세요.', traces=ctx.traces[start:])
            result.update(method='GET', parameters=[])
            results.append(result)
            continue
        owner = None
        if admin:
            try:
                owner = admin.follow(admin.request(path))
                detected(owner, markers)
            except Exception:
                pass  # The student's response is the primary access-control probe.
        hits = detected(low, markers)
        blocked = denied(low, login_path)
        exposed = not blocked and low.status == 200 and bool(hits) and not low.trace['truncated']
        state = 'vulnerable' if exposed else 'not_detected' if blocked else 'inconclusive'
        result = finding(ctx, 'access', 'Broken Access Control · ' + path, path, state,
            {'reason': '학생 A 응답이 200이며 관리자 페이지 마커 확인' if exposed else
                       '학생 A 접근이 거부되거나 로그인 페이지로 이동함' if blocked else '학생 응답에 관리자 마커 또는 명확한 차단 근거를 확인하지 못함',
             'admin_status': owner.status if owner else None, 'student_status': low.status,
             'markers': markers, 'marker_detected': bool(hits), 'detected_markers': hits,
             'student_marker_exposed': exposed,
             'authentication': auth.evidence},
            '모든 관리자 기능에서 서버 측 역할 검증 및 기본 거부 정책을 적용합니다.',
            'high' if exposed else 'info', ctx.traces[start:], method='GET', parameters=[], primary=student_probe.trace)
        result.update(method='GET', parameters=[])
        results.append(result)
    return results


def idor(ctx):
    spec = ctx.config.get('idor', profile(ctx.config)['idor'])
    start = len(ctx.traces)
    auth = AuthManager(ctx)
    details = {'authentication': auth.evidence, 'idor_requests': {}}
    try:
        results = _idor(ctx, auth, details)
    except Exception as exc:
        results = [finding(ctx, 'idor', 'IDOR · 타 학생 성적 접근', spec.get('path', ''), 'inconclusive',
            {**details, 'reason': str(exc)[:300] if isinstance(exc, ValueError) else '학생 인증 또는 객체 요청 비교를 완료하지 못했습니다.',
             'error_type': type(exc).__name__}, '학생 계정, 객체 ID 및 응답 마커를 확인하세요.',
            traces=ctx.traces[start:])]
    for result in results:
        result.update(method='GET', parameters=[spec.get('parameter', 'student_id')] if spec.get('mode', 'path') == 'query' else ['id'])
    return results


def _idor(ctx, auth, details):
    start = len(ctx.traces)
    spec = ctx.config.get('idor', profile(ctx.config)['idor'])
    if not all(spec.get(k) for k in ('path', 'a_id', 'b_id')) or (spec.get('comparison', 'markers') == 'markers' and not all(spec.get(k) for k in ('a_marker', 'b_marker'))):
        return [finding(ctx, 'idor', 'IDOR · 객체 소유권', spec.get('path', ''), 'skipped',
            {'reason': '객체 경로, A/B 소유 ID와 성적 본문의 고유 식별 문자열을 입력하세요. 응답 비교 방식도 선택 가능합니다.'},
            '로그인 사용자와 조회 객체 소유권을 검증합니다.')]
    if spec['a_id'] == spec['b_id']:
        raise ValueError('서로 다른 소유 객체 ID가 필요합니다.')
    mode = spec.get('mode', 'path')
    def object_path(value):
        if mode == 'query':
            if not spec.get('parameter'):
                raise ValueError('Query 객체 파라미터가 필요합니다.')
            return parameter_path(spec['path'], spec['parameter'], value)
        if mode == 'path' and '{id}' in spec['path']:
            return spec['path'].replace('{id}', quote(value, safe=''))
        raise ValueError('Path 방식은 {id}가 필요합니다.')
    a, b = auth.authenticated('student_a'), auth.authenticated('student_b')
    login_path = urlsplit(profile(ctx.config)['login']['path']).path
    probes = {}
    def request_object(client, phase, role, value):
        path = object_path(value)
        info = {'role': role, 'object_id': value, 'request_url': ctx.base + path, 'method': 'GET'}
        details['idor_requests'][phase] = info
        probe = client.request(path)
        probes[phase] = probe
        info.update(http_status=probe.status, session_cookie_present=bool(client.session.cookies))
        try:
            response = client.follow(probe)
        finally:
            info.update(redirect_history=probe.trace.get('redirect_history', []), final_url=probe.trace.get('final_url'))
        redirected = any(urlsplit(h['location']).path in ('/', login_path) for h in response.history)
        final_path = urlsplit(response.url).path
        redirected |= final_path in ('/', login_path) and final_path != urlsplit(path).path
        info.update(final_status=response.status, redirected_to_root_or_login=bool(redirected),
                    session_authentication_failure_suspected=bool(redirected or response.status == 401),
                    session_cookie_present=bool(client.session.cookies))
        return response
    own_a = request_object(a, 'a_baseline', 'student_a', spec['a_id'])
    own_b = request_object(b, 'b_baseline', 'student_b', spec['b_id'])
    cross_a = request_object(a, 'a_to_b', 'student_a', spec['b_id'])
    cross_b = request_object(b, 'b_to_a', 'student_b', spec['a_id'])
    details['session_rechecks'] = {}
    for role in ('student_a', 'student_b'):
        if any(v['role'] == role and v['session_authentication_failure_suspected'] for v in details['idor_requests'].values()):
            details['session_rechecks'][role] = auth.student_session_status(role)
    def object_response(r, phase):
        return r.status == 200 and not r.trace['truncated'] and not details['idor_requests'][phase]['redirected_to_root_or_login']
    complete = object_response(own_a, 'a_baseline') and object_response(own_b, 'b_baseline')
    if spec.get('comparison', 'markers') == 'markers':
        am, bm = spec['a_marker'], spec['b_marker']
        for phase, r in zip(('a_baseline', 'b_baseline', 'a_to_b', 'b_to_a'), (own_a, own_b, cross_a, cross_b)):
            details['idor_requests'][phase]['detected_markers'] = detected(r, [am, bm])
        valid = (complete and am != bm and own_a.status == own_b.status == 200 and am in own_a.body
                 and bm in own_b.body and bm not in own_a.body and am not in own_b.body)
        leak_a, leak_b = bm in cross_a.body, am in cross_b.body
    elif spec['comparison'] == 'response':
        valid = complete and own_a.status == own_b.status == 200 and own_a.body != own_b.body
        leak_a, leak_b = cross_a.body == own_b.body, cross_b.body == own_a.body
    else:
        raise ValueError('IDOR 응답 비교 방식 오류')
    exposed = valid and ((object_response(cross_a, 'a_to_b') and leak_a) or (object_response(cross_b, 'b_to_a') and leak_b))
    def blocked(r, phase):
        info = details['idor_requests'][phase]
        if info['session_authentication_failure_suspected']:
            return details['session_rechecks'].get(info['role'], {}).get('verified') is True
        return denied(r, login_path)
    state = 'vulnerable' if exposed else 'not_detected' if valid and blocked(cross_a, 'a_to_b') and blocked(cross_b, 'b_to_a') else 'inconclusive'
    reason = ('학생별 소유 baseline 검증 후 다른 학생의 마커/응답이 교차 요청에서 노출됨' if exposed else
              '학생 세션을 유지한 상태에서 교차 객체 접근이 차단됨' if state == 'not_detected' else
              '학생 로그인 검증 후 객체 요청이 루트/로그인으로 이동하거나 소유 baseline/교차 응답 근거가 부족함')
    result = finding(ctx, 'idor', 'IDOR · 타 학생 성적 접근', object_path(spec['b_id']), state,
        {**details, 'reason': reason, 'mode': mode,
         'comparison': spec.get('comparison', 'markers'), 'ownership_baseline_verified': valid,
         'a_to_b_status': cross_a.status, 'b_to_a_status': cross_b.status,
         'a_to_b_foreign_content': valid and object_response(cross_a, 'a_to_b') and leak_a,
         'b_to_a_foreign_content': valid and object_response(cross_b, 'b_to_a') and leak_b,
         'detected_markers': sorted(set(cross_a.trace['detected_markers'] + cross_b.trace['detected_markers'])),
         'object_ids': [spec['a_id'], spec['b_id']]},
        'student_id를 신뢰하지 말고 세션 사용자와 객체 소유권을 서버에서 검증합니다.',
        'high' if exposed else 'info', ctx.traces[start:], method='GET',
        parameters=[spec['parameter']] if mode == 'query' else ['id'], primary=probes['a_to_b'].trace)
    result['parameters'] = [spec['parameter']] if mode == 'query' else ['id']
    return [result]


def brute(ctx):
    spec = profile(ctx.config)['brute']
    start = len(ctx.traces)
    role = spec.get('role', 'student_a')
    before = AuthManager(ctx)
    before.authenticated(role)
    baseline_ms = statistics.median(t['elapsed_ms'] for t in ctx.traces[start:] if t['method'] == 'POST')
    client, responses = ctx.client(), []
    for request_index in range(1, 6):
        ctx.progress(f'반복 인증 관찰 · 요청 {request_index}/5')
        r = client.request(spec['path'], {'username': ctx.config[role]['username'], 'password': 'rookie-known-invalid'},
                           evidence_payload={'username': '[REDACTED]', 'password': 'rookie-known-invalid'})
        detected(r, spec['lock_markers'])
        responses.append(r)
        if r.status == 429 or any(m.casefold() in r.body.casefold() for m in spec['lock_markers']):
            break
    limited = any(r.status == 429 for r in responses)
    locked = any(any(m.casefold() in r.body.casefold() for m in spec['lock_markers']) for r in responses)
    delayed = any(r.elapsed_ms >= max(spec.get('delay_threshold_ms', 1000), baseline_ms * spec.get('delay_ratio', 3)) for r in responses)
    # A fresh session must verify real authentication, not an existing session cookie.
    after = AuthManager(ctx)
    try:
        after.authenticated(role)
        normal_after = True
    except ValueError:
        normal_after = False
    failed = all(r.status in (200, 401, 403) and
                 not any(v['marker'] in r.body for k, v in profile(ctx.config)['login'].items() if k in ('admin', role))
                 for r in responses)
    weak = len(responses) == 5 and failed and normal_after and not any((limited, locked, delayed))
    state = 'vulnerable' if weak else 'not_detected' if any((limited, locked, delayed)) else 'inconclusive'
    reason = ('5회 실패 후 429/잠금/유의한 지연이 없고 정상 비밀번호 인증 가능: 제한된 검사 범위에서 방어 미흡' if weak
              else '제한/잠금/지연 관찰' if state == 'not_detected' else '실패 기준 또는 정상 재로그인을 확인하지 못해 판정 불가')
    return [finding(ctx, 'brute', '반복 인증 · Rate Limit/Lockout 미흡', spec['path'], state,
        {'reason': reason, 'attempts': len(responses),
         'statuses': [r.status for r in responses], 'elapsed_ms': [r.elapsed_ms for r in responses],
         'normal_before_verified': True, 'normal_after_verified': normal_after,
         'normal_after_evidence': after.evidence, 'normal_login_baseline_ms': baseline_ms,
         'delay_observed': delayed,
         'rate_limit_observed': limited, 'lock_marker_observed': locked,
         'note': '비밀번호 탐색/크래킹은 수행하지 않습니다. 5회 표본 결과이며 더 높은 임계값의 정책 존재 여부는 평가하지 않습니다.'},
        '계정·IP 제한, 점진적 지연, MFA 및 인증 실패 모니터링을 적용합니다.',
        'medium' if weak else 'info', traces=ctx.traces[start:], method='POST',
        parameters=['username', 'password'], primary=responses[0].trace)]


def availability(ctx):
    path = profile(ctx.config)['availability']['path']
    baseline = [ctx.client().request(path) for _ in range(3)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: ctx.client().request(path), range(12)))
    before, during = statistics.median(r.elapsed_ms for r in baseline), statistics.median(r.elapsed_ms for r in responses)
    slow = during > max(1000, before * 3)
    return [finding(ctx, 'availability', 'HTTP Flood · 제한된 가용성 관찰', path, 'observation_required',
        {'reason': '소규모 표본의 기준 대비 지연 관찰이며 완전 중단을 판정하지 않습니다.',
         'baseline_median_ms': before, 'sample_median_ms': during, 'sample_max_ms': max(r.elapsed_ms for r in responses),
         'response_time_ratio': round(during / before, 3) if before > 0 else None,
         'response_time_increase_percent': round((during / before - 1) * 100, 1) if before > 0 else None,
         'baseline_elapsed_ms': [r.elapsed_ms for r in baseline], 'sample_elapsed_ms': [r.elapsed_ms for r in responses],
         'concurrency': 2, 'sample_requests': 12, 'degradation_observed': slow,
         'statuses': [r.status for r in responses]},
        'Reverse Proxy 요청·연결 제한, 운영용 WSGI 및 지연/오류 모니터링을 적용합니다.',
        'info', [r.trace for r in baseline + responses], method='GET', parameters=[])]


REGISTRY = {'sqli': sqli, 'access': access, 'idor': idor, 'brute': brute, 'availability': availability}
