"""SQL Injection probes with baselines, encoded parameters and per-probe evidence."""
import re
from urllib.parse import urlsplit
from auth import AuthManager
from core import detected, finding
from profiles import profile
from student_objects import extract_students
from profile_identity import acquire_keyword


def exchange(response):
    if response is None:
        return None
    return {'request_url': response.trace['url'], 'method': response.trace['method'],
            'payload': response.trace['payload'], 'http_status': response.status,
            'redirect_history': response.trace.get('redirect_history', []),
            'final_url': response.trace.get('final_url', response.trace['url']),
            'detected_markers': response.trace['detected_markers']}


def sqli(ctx):
    results, auth = [], AuthManager(ctx)
    for spec in profile(ctx.config)['sqli']:
        start = len(ctx.traces)
        baseline = attack = baseline_final = attack_final = None
        evidence = {}
        path, key, method = spec.get('path', ''), spec.get('parameter', ''), spec.get('method', 'GET')
        parameters = list(dict.fromkeys([key] + (list(spec.get('data', {})) if method == 'POST' else [])))
        ctx.progress(spec.get('name', 'SQL Injection'))
        try:
            condition = spec['success_condition']
            def send(client, value, data=None):
                payload = {**spec.get('data', {}), **(data or {}), key: value}
                if method == 'GET':
                    return client.request(path, method='GET', params={key: value}, evidence_payload={key: value})
                return client.request(path, payload, method=method, evidence_payload=payload)

            if condition['kind'] == 'authenticated_page':
                wrong, injected = ctx.client(), ctx.client()
                baseline = send(wrong, spec.get('baseline_username', 'admin'),
                                spec.get('baseline_data', {'password': 'definitely_wrong_password'}))
                baseline_final = wrong.follow(baseline)
                attack = send(injected, spec['payload'])
                attack_final = injected.follow(attack)
                markers = list(dict.fromkeys([condition.get('marker', ''), *condition.get('markers', ['LMS 관리자', 'ADMIN'])]))
                baseline_hits = detected(baseline_final, markers)
                attack_hits = detected(attack_final, markers)
                destination = condition.get('redirect_path', '/admin')
                def admin_redirect(r):
                    return urlsplit(r.url).path == destination or any(
                        urlsplit(h['location']).path == destination for h in r.history)
                baseline_admin = admin_redirect(baseline_final) or bool(baseline_hits)
                redirected = admin_redirect(attack_final)
                baseline_failed = not baseline_admin and not baseline_final.trace['truncated'] and (
                    baseline_final.status in (401, 403) or (baseline_final.status == 200 and
                    urlsplit(baseline_final.url).path == urlsplit(path).path))
                marker_found = bool(attack_hits) and not attack_final.trace['truncated']
                confirmed = baseline_failed and (redirected or marker_found)
                rejected = not attack_final.trace['truncated'] and (attack_final.status in (401, 403) or (
                    attack_final.status == 200 and urlsplit(attack_final.url).path == urlsplit(path).path and not attack_hits))
                state = 'vulnerable' if confirmed else 'not_detected' if baseline_failed and rejected else 'inconclusive'
                reason = ('실패 비밀번호 기준은 인증되지 않고 SQL Injection 요청 후 관리자 URL/리다이렉트 또는 관리자 마커 확인' if confirmed else
                          '실패 비밀번호 기준에서도 관리자 접근이 확인되어 SQL Injection 효과를 분리할 수 없음' if not baseline_failed else
                          f'SQL Injection 요청 후 관리자 URL/리다이렉트와 관리자 마커가 확인되지 않음 (HTTP {attack_final.status}, 응답 잘림={attack_final.trace["truncated"]})')
                evidence.update(admin_redirect_detected=redirected, probe_marker_detected=marker_found,
                                admin_marker_detected=marker_found, protected_marker_exposed=marker_found,
                                baseline_failed=baseline_failed, baseline_marker=baseline_hits, attack_marker=attack_hits,
                                probe_status=attack.status, verified_page_status=attack_final.status)
            elif condition['kind'] in ('object_expansion', 'search_markers'):
                # Older marker profiles also use object comparison now.
                ctx.progress('SQL Injection · 정상 검색어 자동 획득')
                keyword, acquisition = acquire_keyword(ctx, auth, spec)
                evidence.update(normal_keyword_acquisition=acquisition, normal_keyword_source=acquisition['source'])
                if not keyword:
                    raise ValueError(acquisition['reason'] + ' 정상 검색어(학생 이름/학번)를 입력하거나 본인 정보 경로/필드를 확인하세요.')
                ctx.progress(spec.get('name', 'SQL Injection · 학생 검색'))
                client = auth.authenticated(spec.get('role', 'admin'))
                # Keep the verified identity before sending either search probe.
                evidence['authentication'] = auth.evidence
                evidence['admin_authentication'] = auth.evidence.get('admin', {})
                baseline = send(client, keyword)
                baseline_final = client.follow(baseline)
                attack = send(client, spec['payload'])
                attack_final = client.follow(attack)
                pattern = condition.get('link_pattern', r'^/admin/students/([^/]+)/?$')
                before, after = extract_students(baseline_final.body, pattern), extract_students(attack_final.body, pattern)
                extra = after.values - before.values
                subset = bool(before.values) and before.values.issubset(after.values)
                comparable = (0 < len(before.values) <= condition.get('max_baseline_objects', 5) and
                    before.mode == after.mode and
                    all(r.status == 200 and not r.trace['truncated'] for r in (baseline_final, attack_final)) and
                    all(urlsplit(r.url).path == urlsplit(path).path for r in (baseline_final, attack_final)))
                confirmed = comparable and subset and bool(extra) and len(after.values) > len(before.values)
                unchanged = comparable and after.values.issubset(before.values)
                state = 'vulnerable' if confirmed else 'not_detected' if unchanged else 'inconclusive'
                reason = '정상 검색 결과가 공격 결과의 진부분집합이며 추가 학생 객체가 노출됨' if confirmed else (
                    '공격 결과에서 정상 검색 외의 추가 객체가 탐지되지 않음' if unchanged else
                    before.reason or after.reason or '응답 상태/경로/잘림, 정상 결과 수, 객체 추출 방식 또는 포함 관계를 확인할 수 없음')
                evidence.update(authentication=auth.evidence, baseline_object_count=len(before.values),
                    attack_object_count=len(after.values), extra_object_count=len(extra),
                    baseline_extraction=before.mode, attack_extraction=after.mode,
                    baseline_fingerprints=before.fingerprints(), attack_fingerprints=after.fingerprints(),
                    extra_fingerprints=sorted(set(after.fingerprints()) - set(before.fingerprints())),
                    baseline_subset=subset, baseline_valid=comparable)
            elif condition['kind'] == 'table_rows':
                # Retain compatibility for existing custom row-count profiles.
                client = auth.authenticated(spec.get('role', 'admin'))
                normal, baseline = send(client, ''), send(client, '__rookie_no_match__')
                attack, no = send(client, spec['payload']), send(client, spec['false_payload'])
                baseline_final, attack_final = baseline, attack
                counts = [sum(bool(re.search(r'<td\b', x, re.I)) for x in re.findall(condition['row_pattern'], r.body, re.I | re.S))
                          for r in (normal, baseline, attack, no)]
                comparable = all(r.status == 200 and not r.trace['truncated'] for r in (normal, baseline, attack, no)) and counts[0] > 0 and counts[1] == 0
                confirmed = comparable and counts[2] > 0 and counts[3] == 0
                state = 'vulnerable' if confirmed else 'not_detected' if comparable and counts[2] == counts[3] == 0 else 'inconclusive'
                reason = '검색 결과의 정상/참/거짓 조건 행 수 비교'
                evidence.update(row_counts=dict(zip(('normal', 'no_match', 'true', 'false'), counts)), baseline_valid=comparable)
            else:
                raise ValueError('지원하지 않는 SQL Injection success condition')
            evidence.update(reason=reason, success_condition=condition)
        except Exception as exc:
            state = 'inconclusive'
            reason = str(exc)[:300] if isinstance(exc, (ValueError, KeyError, RuntimeError)) else f'요청 처리 실패 ({type(exc).__name__})'
            evidence.update(reason=reason, error_type=type(exc).__name__, authentication=auth.evidence)
        # Always retain diagnostic fields, including when authentication or redirects fail.
        probe_trace = attack.trace if attack else next((t for t in reversed(ctx.traces[start:]) if
            t['method'] == method and urlsplit(t['url']).path == urlsplit(path).path and
            t.get('payload', {}).get(key) == spec.get('payload')), None)
        evidence.update(parameter=key, payload={**spec.get('data', {}), key: spec.get('payload', '')},
                        request_url=probe_trace['url'] if probe_trace else ctx.base + path,
                        method=method, http_status=probe_trace['status'] if probe_trace else None,
                        redirect_history=probe_trace.get('redirect_history', []) if probe_trace else [],
                        final_url=probe_trace.get('final_url') if probe_trace else None,
                        baseline=exchange(baseline), attack=exchange(attack), attack_executed=attack is not None,
                        attack_request_attempted=probe_trace is not None,
                        baseline_marker=evidence.get('baseline_marker', []),
                        attack_marker=evidence.get('attack_marker', []),
                        admin_marker_detected=evidence.get('admin_marker_detected', False),
                        inconclusive_reason=evidence['reason'] if state == 'inconclusive' else '')
        if 'admin' in auth.evidence:
            evidence['admin_authentication'] = auth.evidence.get('admin', {})
        result = finding(ctx, 'sqli', spec.get('name', 'SQL Injection'), path, state, evidence,
            'SQL 파라미터 바인딩과 비밀번호 해시 검증을 적용하고 DB 오류를 외부에 노출하지 않습니다.',
            'high' if state == 'vulnerable' else 'info', ctx.traces[start:], method=method,
            parameters=parameters, primary=probe_trace)
        result.update(method=method, parameters=parameters)
        results.append(result)
    return results
