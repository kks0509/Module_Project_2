"""Bounded requests transport and evidence schema for authorized LMS labs."""
import hashlib
import ipaddress
import threading
import time
import urllib.parse
import requests
from classification import owasp_for
from dataclasses import dataclass, field

SENSITIVE_KEYS = {'password', 'passwd', 'username', 'token', 'access_token', 'csrf', 'csrf_token', 'session', 'sessionid'}


def evidence_url(url):
    p = urllib.parse.urlsplit(url)
    pairs = [(k, '[REDACTED]' if k.casefold() in SENSITIVE_KEYS else v)
             for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)]
    return urllib.parse.urlunsplit((p.scheme, p.netloc.rsplit('@', 1)[-1], p.path, urllib.parse.urlencode(pairs), ''))


def detected(response, markers):
    hits = [m for m in markers if m and m in response.body]
    response.trace['detected_markers'] = list(dict.fromkeys(response.trace.get('detected_markers', []) + hits))
    return hits


def validate_target(base):
    p = urllib.parse.urlsplit(base.strip())
    if p.scheme not in ('http', 'https') or p.username is not None or p.password is not None or p.path not in ('', '/') or p.query or p.fragment:
        raise ValueError('대상은 경로 없는 HTTP(S) origin이어야 합니다.')
    hostname = p.hostname
    if hostname == 'localhost':
        hostname = '127.0.0.1'
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        raise ValueError('DNS 이름 대신 허가된 실습 서버의 IP 주소를 입력하세요.')
    if not (address.is_loopback or address in ipaddress.ip_network('10.0.0.0/8') or address in ipaddress.ip_network('172.16.0.0/12') or address in ipaddress.ip_network('192.168.0.0/16')):
        raise ValueError('MVP 대상은 loopback 또는 RFC1918 IPv4 실습 주소로 제한됩니다.')
    port = p.port
    if port == 0:
        raise ValueError('포트는 1~65535 범위여야 합니다.')
    host = f'[{address}]' if address.version == 6 else str(address)
    return f'{p.scheme}://{host}' + (f':{port}' if port is not None else '')


@dataclass
class Response:
    status: int
    body: str
    location: str
    elapsed_ms: float
    trace: dict
    url: str = ''
    history: list = field(default_factory=list)
    allowed_methods: list = field(default_factory=list)


class Context:
    def __init__(self, config, cancel=None):
        self.config = config
        self.base = validate_target(config['target'])
        self.cancel = cancel or threading.Event()
        self.lock = threading.Lock()
        self.count = 0
        self.traces = []
        self.progress = lambda module: None

    def client(self):
        return Client(self)


class Client:
    def __init__(self, context):
        self.ctx = context
        self.session = requests.Session()
        self.session.trust_env = False

    def request(self, path, data=None, method=None, evidence_payload=None, params=None):
        p = urllib.parse.urlsplit(path)
        if not path.startswith('/') or path.startswith('//') or p.scheme or p.netloc or p.fragment:
            raise ValueError('요청 경로는 동일 origin 상대 경로만 허용됩니다.')
        if self.ctx.cancel.is_set():
            raise RuntimeError('사용자가 진단을 중지했습니다.')
        with self.ctx.lock:
            if self.ctx.count >= 100:
                raise RuntimeError('전체 요청 한도 100회 초과')
            self.ctx.count += 1
        if self.ctx.cancel.wait(.15):
            raise RuntimeError('사용자가 진단을 중지했습니다.')
        method = method or ('POST' if data is not None else 'GET')
        if method not in ('GET', 'POST'):
            raise ValueError('MVP는 GET/POST만 허용합니다.')
        start = time.monotonic()
        try:
            with self.session.request(method, self.ctx.base + path, data=data if method == 'POST' else None,
                                      params=params, timeout=(2, 4), allow_redirects=False, stream=True) as response:
                raw = response.raw.read(262145, decode_content=True)
                body = raw[:262144].decode('utf-8', errors='replace')
                status, location, response_url = response.status_code, response.headers.get('Location', ''), response.url
                # Retain only method names, never arbitrary authentication headers.
                allowed_methods = [m.strip().upper() for m in response.headers.get('Allow', '')[:512].split(',')
                                   if m.strip().upper() in {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE'}]
        except requests.RequestException as exc:
            prepared = requests.Request(method, self.ctx.base + path, params=params, data=data).prepare()
            url = evidence_url(prepared.url)
            fields = data.items() if data is not None else urllib.parse.parse_qsl(urllib.parse.urlsplit(prepared.url).query)
            trace = {'method': method, 'url': url, 'query_keys': list(urllib.parse.parse_qs(urllib.parse.urlsplit(prepared.url).query)),
                     'form_keys': list(data or {}), 'status': None, 'elapsed_ms': round((time.monotonic() - start) * 1000, 1),
                     'payload': evidence_payload if evidence_payload is not None else
                        {k: '[REDACTED]' if k.casefold() in SENSITIVE_KEYS else v for k, v in fields},
                     'redirect_history': [], 'redirect_url': '', 'final_url': None, 'detected_markers': [],
                     'error_type': type(exc).__name__, 'truncated': False}
            with self.ctx.lock:
                self.ctx.traces.append(trace)
            raise
        elapsed = round((time.monotonic() - start) * 1000, 1)
        # Never retain credentials, cookies, raw personal data, or response bodies.
        trace = {'method': method,
                 'url': evidence_url(response_url), 'query_keys': list(urllib.parse.parse_qs(urllib.parse.urlsplit(response_url).query)),
                 'form_keys': list(data or {}), 'status': status, 'elapsed_ms': elapsed,
                 'bytes_sampled': len(raw), 'truncated': len(raw) > 262144,
                 'body_sha256': hashlib.sha256(raw).hexdigest(),
                 'redirect_path': urllib.parse.urlsplit(location).path,
                 'redirect_url': evidence_url(urllib.parse.urljoin(response_url, location)) if location else '',
                 'payload': evidence_payload if evidence_payload is not None else
                            {k: '[REDACTED]' if k.casefold() in SENSITIVE_KEYS else v for k, v in
                             (data.items() if data is not None else urllib.parse.parse_qsl(urllib.parse.urlsplit(response_url).query, keep_blank_values=True))},
                 'detected_markers': [], 'redirect_history': [], 'final_url': evidence_url(response_url)}
        with self.ctx.lock:
            self.ctx.traces.append(trace)
        return Response(status, body, location, elapsed, trace, response_url, allowed_methods=allowed_methods)

    def follow(self, response, limit=3):
        initial = response
        history = list(response.history)
        for step in range(limit + 1):
            if response.status not in (301, 302, 303, 307, 308):
                response.history = history
                for trace in (initial.trace, response.trace):
                    trace.update(redirect_history=history, final_url=evidence_url(response.url))
                return response
            url = urllib.parse.urljoin(response.url, response.location)
            parsed = urllib.parse.urlsplit(url)
            history.append({'status': response.status, 'url': evidence_url(response.url), 'location': evidence_url(url)})
            initial.trace['redirect_history'] = history
            if parsed.scheme + '://' + parsed.netloc != self.ctx.base:
                raise ValueError('외부 origin 리다이렉트는 차단됩니다.')
            if step == limit:
                raise ValueError('리다이렉트 상한 초과')
            if response.status in (307, 308) and response.trace['method'] != 'GET':
                raise ValueError('POST를 보존하는 307/308 리다이렉트는 MVP에서 지원하지 않습니다.')
            response = self.request(parsed.path + ('?' + parsed.query if parsed.query else ''))


def finding(ctx, module, name, path, state, evidence, remedy, severity='info', traces=(),
            method=None, parameters=None, primary=None):
    traces = list(traces)
    if not path and module in ('brute', 'availability', 'idor'):
        from profiles import profile
        spec = ctx.config.get('idor', profile(ctx.config)['idor']) if module == 'idor' else profile(ctx.config)[module]
        path = spec.get('path', '')
    method = method or {'brute': 'POST', 'access': 'GET', 'idor': 'GET', 'availability': 'GET'}.get(module)
    matching = [t for t in traces if urllib.parse.urlsplit(t['url']).path == urllib.parse.urlsplit(path).path
                and (method is None or t['method'] == method)]
    primary = primary or (matching[-1] if matching else None)
    method = method or (primary['method'] if primary else 'GET')
    if parameters is None:
        parameters = {'brute': ['username', 'password'], 'access': [], 'availability': []}.get(module)
    if parameters is None:
        parameters = list(dict.fromkeys(primary.get('query_keys', []) + primary.get('form_keys', []))) if primary else []
    evidence = dict(evidence)
    markers = list(dict.fromkeys(m for t in matching for m in t.get('detected_markers', [])))
    defaults = {'request_url': primary['url'] if primary else ctx.base + path, 'method': method,
                'parameters': parameters, 'payload': primary.get('payload', {}) if primary else {},
                'http_status': primary['status'] if primary else None,
                'redirect_history': primary.get('redirect_history', []) if primary else [],
                'final_url': primary.get('final_url', primary['url']) if primary else None,
                'marker_detected': bool(markers), 'detected_markers': markers,
                'baseline_object_count': None, 'attack_object_count': None, 'extra_object_count': None,
                'inconclusive_reason': evidence.get('reason', '진단을 완료할 근거가 부족합니다.') if state == 'inconclusive' else ''}
    for key, value in defaults.items():
        evidence.setdefault(key, value)
    return {'module': module, 'name': name, 'vulnerability': name, 'owasp': owasp_for(module),
            'url': ctx.base + path, 'state': state,
            'severity': severity, 'evidence': evidence, 'remedy': remedy, 'requests': traces,
            'method': method, 'parameters': parameters,
            'reason': evidence.get('reason', evidence.get('note', '규칙 기반 요청/응답 비교 결과'))}
