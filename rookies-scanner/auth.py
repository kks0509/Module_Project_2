"""One isolated requests.Session per identity; verify content, URL and guest control."""
from urllib.parse import urlsplit
from profiles import login_settings
from core import detected


class AuthManager:
    def __init__(self, ctx):
        self.ctx = ctx
        self.spec = login_settings(ctx.config)
        self.clients = {}
        self.evidence = {}

    def login_request(self, client, role, credentials=None):
        credentials = self.ctx.config[role] if credentials is None else credentials
        method = self.spec.get('method', 'POST').upper()
        username_field = self.spec.get('username_field', 'username')
        password_field = self.spec.get('password_field', 'password')
        if method != 'POST' or not isinstance(username_field, str) or not isinstance(password_field, str) or not username_field or not password_field or username_field == password_field:
            raise ValueError('내부 로그인 Method/계정 필드 설정을 확인하세요.')
        if not credentials.get('username') or not credentials.get('password'):
            raise ValueError(f'{role} 계정 ID 또는 비밀번호가 비어 있습니다. 입력값을 다시 제출하세요.')
        data = {username_field: credentials['username'], password_field: credentials['password']}
        # Explicit redaction also protects nonstandard password field names.
        return client.request(self.spec['path'], data, method=method,
                              evidence_payload={username_field: '[REDACTED]', password_field: '[REDACTED]'})

    def authenticated(self, role):
        if role in self.clients:
            return self.clients[role]
        if role in ('student_a', 'student_b'):
            return self._student_authenticated(role)
        client = self.ctx.client()
        rule = self.spec[role]
        evidence = {'phase': 'guest_control', 'marker_verified': False, 'authenticated': False,
                    'login_request_url': self.ctx.base + self.spec['path'], 'login_method': self.spec['method'],
                    'login_status': None, 'login_redirect_history': [], 'login_final_url': None,
                    'matched_success_path': None, 'matched_success_markers': [],
                    'username_field': self.spec['username_field'], 'password_field': self.spec['password_field'],
                    'form_fields': [self.spec['username_field'], self.spec['password_field']],
                    'username_present': bool(self.ctx.config.get(role, {}).get('username')),
                    'password_present': bool(self.ctx.config.get(role, {}).get('password'))}
        self.evidence[role] = evidence
        try:
            return self._admin_authenticated(role, client, rule, evidence)
        except Exception as exc:
            evidence.update(authenticated=False, error_type=type(exc).__name__)
            evidence.setdefault('reason', '관리자 로그인/리다이렉트/세션 재접근을 완료하지 못했습니다.')
            raise

    def _admin_authenticated(self, role, client, rule, evidence):
        guest_client = self.ctx.client()
        guest = guest_client.follow(guest_client.request(rule['path']))
        evidence.update(phase='login', guest_status=guest.status, guest_final_url=guest.trace['final_url'])
        login = self.login_request(client, role)
        evidence.update(login_request_url=login.trace['url'], login_method=login.trace['method'], login_status=login.status)
        try:
            landing = client.follow(login)
        finally:
            evidence.update(login_redirect_history=login.trace.get('redirect_history', []),
                            login_final_url=login.trace.get('final_url'), session_cookie_present=bool(client.session.cookies))
        evidence['phase'] = 'protected_page_verification'
        check = client.follow(client.request(rule['path']))
        markers = [rule.get('marker', ''), *rule.get('markers', [])]
        if role == 'admin':
            markers += [*self.spec.get('admin_markers', ['LMS 관리자', 'ADMIN']), '관리자 대시보드']
        markers = list(dict.fromkeys(m for m in markers if m))
        hits, guest_hits = detected(check, markers), detected(guest, markers)
        success_paths = self.spec.get('admin_success_paths', ['/admin'])
        landed = urlsplit(landing.url).path in success_paths
        # A verified protected page may use a different post-login landing route.
        valid = (login.status < 400 and check.status == 200 and bool(set(hits) - set(guest_hits))
                 and not check.trace['truncated'] and not guest.trace['truncated']
                 and urlsplit(check.url).path == urlsplit(rule['path']).path)
        session_proof = False
        control = None
        if not valid and login.status in (301, 302, 303) and client.session.cookies and landing.status == 200:
            destinations = ([urlsplit(rule['path']).path] if role == 'admin' else
                            [p for p in self.spec['success_paths'] if not p.startswith('/admin')])
            if urlsplit(landing.url).path in destinations:
                wrong_client = self.ctx.client()
                wrong = self.login_request(wrong_client, role,
                    {'username': self.ctx.config[role]['username'], 'password': 'rookie-auth-control-invalid'})
                control = wrong_client.follow(wrong)
                wrong_authenticated = (wrong.status in (301, 302, 303) and bool(wrong_client.session.cookies)
                                       and urlsplit(control.url).path in destinations and control.status == 200)
                session_proof = not wrong_authenticated and (control.status in (401, 403) or
                    urlsplit(control.url).path == urlsplit(self.spec['path']).path)
                if role == 'admin':
                    session_proof &= check.status == 200 and urlsplit(check.url).path == urlsplit(rule['path']).path
                valid = bool(session_proof)
        evidence.update(login_status=login.status, landing_path=urlsplit(landing.url).path,
                        final_url=landing.trace['final_url'], redirect_history=landing.history,
                        configured_landing_match=landed, verification_status=check.status,
                        verification_url=check.trace['url'], detected_markers=hits,
                        guest_markers=guest_hits, marker_verified=valid)
        evidence.update(verification='protected_marker' if valid and not session_proof else
                                  'redirect_cookie_and_failed_login_control' if valid else 'failed',
                                  session_proof=session_proof, phase='complete',
                                  marker_verified=bool(set(hits) - set(guest_hits)), authenticated=valid,
                                  control_status=control.status if control else None,
                                  matched_success_path=urlsplit(landing.url).path if landed else None,
                                  matched_success_markers=[h for h in hits if h not in guest_hits])
        if not valid:
            reason = ('로그인 요청 후 로그인 페이지에 남아 있습니다. 제출 계정·로그인 필드명·서버 로그인 처리를 확인하세요.'
                      if urlsplit(landing.url).path == urlsplit(self.spec['path']).path else
                      '로그인 후 관리자 페이지의 지속적인 세션/성공 경로/마커를 확인하지 못했습니다.')
            evidence['reason'] = reason
            raise ValueError(f'{role} 인증 확인 실패: {reason}')
        self.clients[role] = client
        return client

    def student_rules(self, role):
        rule = self.spec.get(role, {})
        dashboard = rule.get('dashboard_path', self.spec.get('student_dashboard_path', '/student'))
        paths = rule.get('success_paths', self.spec.get('student_success_paths', ['/student']))
        markers = list(dict.fromkeys([*self.spec.get('student_markers', ['STUDENT', 'Dashboard', '성적 조회']),
                                     rule.get('marker', ''), *rule.get('markers', [])]))
        # Administrator markers are never student authentication evidence.
        markers = [m for m in markers if m and m not in self.spec.get('admin_markers', ['LMS 관리자', 'ADMIN'])]
        return dashboard, paths, markers

    def _student_authenticated(self, role):
        dashboard, paths, markers = self.student_rules(role)
        client = self.ctx.client()
        evidence = {'phase': 'login', 'authenticated': False, 'login_post_status': None,
                    'login_redirect_history': [], 'login_final_url': None, 'student_markers_detected': [],
                    'student_marker_detected': False, 'session_cookie_present': False,
                    'dashboard_path': dashboard, 'success_paths': paths}
        self.evidence[role] = evidence
        login = None
        try:
            login = self.login_request(client, role)
            evidence.update(login_post_status=login.status, login_status=login.status)
            landing = client.follow(login)
            evidence.update(login_redirect_history=landing.history, login_final_url=landing.trace['final_url'],
                            redirect_history=landing.history, final_url=landing.trace['final_url'],
                            landing_path=urlsplit(landing.url).path, session_cookie_present=bool(client.session.cookies),
                            phase='dashboard_verification')
            check = client.follow(client.request(dashboard))
            guest_client = self.ctx.client()
            guest = guest_client.follow(guest_client.request(dashboard))
            landing_hits, check_hits = detected(landing, markers), detected(check, markers)
            guest_hits = detected(guest, markers)
            hits = list(dict.fromkeys(landing_hits + check_hits))
            landing_path = urlsplit(landing.url).path
            path_match = landing_path in paths
            admin_landing = landing_path.startswith('/admin') or landing_path in self.spec.get('admin_success_paths', ['/admin'])
            check_path = urlsplit(check.url).path
            persistent = (check.status == 200 and not check.trace['truncated'] and
                          check_path == urlsplit(dashboard).path and (check_path in paths or bool(check_hits)))
            # Compare the dashboard, not either student's grade object, against a guest.
            contrast = bool(set(check_hits) - set(guest_hits)) or (
                guest.status != 200 or urlsplit(guest.url).path != check_path)
            session_proof = False
            control = None
            if persistent and not contrast and client.session.cookies and (path_match or hits):
                wrong = self.ctx.client()
                control = wrong.follow(self.login_request(wrong, role,
                    {'username': self.ctx.config[role]['username'], 'password': 'rookie-auth-control-invalid'}))
                session_proof = control.status in (401, 403) or urlsplit(control.url).path == urlsplit(self.spec['path']).path
            valid = (login.status < 400 and landing.status == 200 and not landing.trace['truncated'] and
                     not admin_landing and (path_match or bool(hits)) and persistent and (contrast or session_proof))
            evidence.update(verification_status=check.status, verification_url=check.trace['url'],
                            student_markers_detected=hits, student_marker_detected=bool(hits),
                            detected_markers=hits, marker_verified=bool(set(check_hits) - set(guest_hits)),
                            configured_landing_match=path_match, guest_markers=guest_hits,
                            guest_status=guest.status, guest_final_url=guest.trace['final_url'],
                            session_cookie_present=bool(client.session.cookies), session_proof=session_proof,
                            control_status=control.status if control else None, authenticated=bool(valid), phase='complete',
                            verification='student_dashboard' if valid else 'failed')
            if not valid:
                raise ValueError(f'{role} 인증 확인 실패: 학생 Dashboard URL/마커 또는 동일 세션의 재접근을 확인하지 못했습니다.')
            self.clients[role] = client
            return client
        except Exception as exc:
            if login is not None:
                evidence['login_redirect_history'] = login.trace.get('redirect_history', [])
                evidence['login_final_url'] = login.trace.get('final_url')
            evidence.update(error_type=type(exc).__name__, session_cookie_present=bool(client.session.cookies),
                            reason=str(exc)[:300] if isinstance(exc, (ValueError, KeyError)) else '학생 로그인 요청/리다이렉트를 완료하지 못함')
            raise

    def student_session_status(self, role):
        """Recheck an existing student client after an object redirects to root/login."""
        client = self.clients[role]
        dashboard, paths, markers = self.student_rules(role)
        try:
            response = client.follow(client.request(dashboard))
            hits = detected(response, markers)
            verified = (response.status == 200 and not response.trace['truncated'] and
                        urlsplit(response.url).path == urlsplit(dashboard).path and
                        (urlsplit(response.url).path in paths or bool(hits)))
            return {'verified': verified, 'status': response.status, 'final_url': response.trace['final_url'],
                    'redirect_history': response.history, 'student_markers_detected': hits,
                    'session_cookie_present': bool(client.session.cookies)}
        except Exception as exc:
            return {'verified': None, 'error_type': type(exc).__name__, 'session_cookie_present': bool(client.session.cookies)}
