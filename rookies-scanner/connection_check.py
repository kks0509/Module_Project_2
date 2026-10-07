"""Read-only, bounded TCP/HTTP preflight; never authenticates or runs a scan."""
import socket
import time
from urllib.parse import urlsplit
from core import Context, validate_target
from profiles import profile


def check_connection(config, cancel=None):
    result = {'target': config.get('target', ''), 'allowed_scope': False, 'authorization_confirmed': False,
              'tcp': {'ok': False}, 'http': {}, 'login': {}, 'ok': False, 'requests': 0}
    try:
        base = validate_target(config.get('target', ''))
        result.update(target=base, allowed_scope=True, authorization_confirmed=config.get('authorized') is True)
        if not result['authorization_confirmed']:
            raise ValueError('허가된 실습 환경 확인 체크가 필요합니다.')
        # Validate the configured endpoint before any network operation.
        rules = profile(config)
        login = rules.get('login') if isinstance(rules, dict) else None
        if not isinstance(login, dict) or not isinstance(login.get('path'), str):
            raise ValueError('프로파일의 로그인 Endpoint path 설정을 확인하세요.')
        login_path = login['path']
        parsed_login = urlsplit(login_path)
        if not login_path.startswith('/') or login_path.startswith('//') or parsed_login.scheme or parsed_login.netloc or parsed_login.fragment:
            raise ValueError('로그인 Endpoint는 동일 origin 상대 경로여야 합니다.')
        if cancel and cancel.is_set():
            raise RuntimeError('연결 확인을 중지했습니다.')
        parsed = urlsplit(base)
        started = time.monotonic()
        with socket.create_connection((parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80)), timeout=2):
            pass
        result['tcp'] = {'ok': True, 'elapsed_ms': round((time.monotonic() - started) * 1000, 1)}
        ctx = Context({'target': base}, cancel)
        client = ctx.client()
        for key, path in (('http', '/'), ('login', login_path)):
            initial = None
            try:
                began = time.monotonic()
                initial = client.request(path, method='GET')
                final = client.follow(initial)
                result[key] = {'reachable': True, 'request_url': initial.trace['url'], 'status': initial.status,
                               'final_status': final.status, 'final_url': final.trace['final_url'],
                               'redirect_history': final.history,
                               'elapsed_ms': round((time.monotonic() - began) * 1000, 1),
                               'response_ms': initial.elapsed_ms, 'ok': 200 <= final.status < 400,
                               'truncated': final.trace['truncated']}
                if key == 'login':
                    declared_post = initial.status == 405 and 'POST' in initial.allowed_methods
                    result[key].update(endpoint_path=path, probe_method='GET', method='POST',
                                       allowed_methods=initial.allowed_methods,
                                       method_confirmed=declared_post or 'POST' in initial.allowed_methods,
                                       post_only=declared_post)
                    if declared_post:
                        result[key]['ok'] = True
                    elif initial.status == 405:
                        result[key]['reason'] = 'GET은 허용되지 않으며 Allow 헤더에서 POST 지원을 확인하지 못했습니다.'
                    elif initial.allowed_methods and 'POST' not in initial.allowed_methods:
                        result[key]['ok'] = False
                        result[key]['reason'] = 'Allow 헤더에 Scanner 로그인 방식인 POST가 포함되어 있지 않습니다.'
            except Exception as exc:
                result[key] = {'reachable': initial is not None, 'ok': False, 'error_type': type(exc).__name__,
                               'reason': str(exc) if isinstance(exc, ValueError) else 'HTTP 요청/리다이렉트를 완료하지 못했습니다.'}
                if initial is not None:
                    result[key].update(status=initial.status, response_ms=initial.elapsed_ms,
                                       request_url=initial.trace['url'], redirect_history=initial.trace['redirect_history'],
                                       final_status=None, final_url=initial.trace.get('final_url'))
                if key == 'login':
                    result[key].update(endpoint_path=path, probe_method='GET', method='POST')
        result['requests'] = ctx.count
        result['ok'] = result['http'].get('ok', False) and result['login'].get('ok', False)
    except Exception as exc:
        result.update(error_type=type(exc).__name__, reason=str(exc) if isinstance(exc, (ValueError, RuntimeError)) else
                      '대상 서버 TCP 연결 실패: IP·포트·ZeroTier·서버 실행 상태를 확인하세요.')
    return result


def connection_message(result):
    lines = [f"대상: {result['target']}"]
    lines.append(('✓' if result['allowed_scope'] and result['authorization_confirmed'] else '✕') + ' 실습 주소 범위 / 진단 권한 체크 확인')
    if not result['tcp']['ok']:
        lines.append('✕ 대상 서버에 연결할 수 없습니다. ' + result.get('reason', 'TCP 연결 실패'))
        return '\n'.join(lines)
    lines.append('✓ 대상 서버 TCP 연결 성공')
    for key, label in (('http', '대상 HTTP'), ('login', '로그인 Endpoint')):
        info = result[key]
        if key == 'login':
            path = info.get('endpoint_path', '/login')
            if info.get('ok'):
                lines.append('✓ 로그인 Endpoint 확인 · POST ' + path)
            else:
                lines.append('✕ ' + path + ' Endpoint를 확인할 수 없습니다.')
                if info.get('reachable'):
                    lines.append(f"  HTTP {info['status']}")
            if info.get('reason'):
                lines.append('  ' + info['reason'])
            continue
        if info.get('reachable'):
            lines.append(f"{'✓' if info['ok'] else '✕'} {label}: HTTP {info['status']} · 응답시간 {info['response_ms']} ms")
            if info.get('reason'):
                lines.append('  ' + info['reason'] + ' (' + info.get('error_type', '') + ')')
            if info.get('redirect_history') and info.get('final_status') is not None:
                lines.append(f"  최종 HTTP {info['final_status']} → {info['final_url']}")
            elif key == 'login':
                lines.append('  ' + info['request_url'])
        else:
            lines.append('✕ ' + label + ': ' + info.get('reason', '연결 실패'))
    return '\n'.join(lines)
