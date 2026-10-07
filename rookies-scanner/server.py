"""Local UI/API, one bounded background job, session-only results."""
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from core import Context
from modules import REGISTRY
from profiles import profile
from engine import scan, new_scan_id

ROOT = Path(__file__).parent
TOKEN = secrets.token_urlsafe(32)
LOCK = threading.Lock()
JOB = {'state': 'idle', 'results': [], 'completed': 0, 'total': 0, 'requests': 0}
CANCEL = threading.Event()


def run(config, identity):
    try:
        def update(snapshot):
            with LOCK:
                JOB.clear()
                JOB.update(snapshot)
        finished = scan(config, CANCEL, update, scan_id=identity)
        with LOCK:
            JOB.clear()
            JOB.update(finished)
    except Exception:
        with LOCK:
            JOB.update(state='error', reason='진단 설정/연결을 확인하세요.')
    finally:
        config.clear()  # credentials are never written to disk


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, value, kind='application/json'):
        data = value.encode() if isinstance(value, str) else json.dumps(value, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', kind + '; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(data)

    def trusted(self):
        return self.headers.get('Host') in ('127.0.0.1:8765', 'localhost:8765')

    def do_GET(self):
        if not self.trusted():
            return self.reply(403, {'error': 'Invalid Host'})
        if self.path == '/api/session':
            return self.reply(200, {'token': TOKEN, 'profile': profile({})})
        if self.path in ('/api/job', '/api/export'):
            if self.headers.get('X-Scanner-Token') != TOKEN:
                return self.reply(403, {'error': 'Invalid session'})
            with LOCK:
                snapshot = json.loads(json.dumps(JOB))
            return self.reply(200, snapshot)
        assets = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}
        if self.path not in assets:
            return self.reply(404, {'error': 'Not found'})
        name, kind = assets[self.path]
        self.reply(200, (ROOT / 'static' / name).read_text(encoding='utf-8'), kind)

    def do_POST(self):
        if not self.trusted() or self.headers.get('X-Scanner-Token') != TOKEN or self.headers.get('Origin') not in ('http://127.0.0.1:8765', 'http://localhost:8765'):
            return self.reply(403, {'error': 'Invalid local session'})
        if self.path == '/api/cancel':
            CANCEL.set()
            return self.reply(200, {'ok': True})
        if self.path != '/api/scan':
            return self.reply(404, {'error': 'Not found'})
        try:
            size = int(self.headers.get('Content-Length', 0))
            if not 0 < size <= 16384:
                raise ValueError('설정 크기 제한 초과')
            config = json.loads(self.rfile.read(size))
            Context(config)
            selected = config.get('modules', [])
            if not isinstance(selected, list) or not selected or len(selected) != len(set(selected)) or any(m not in REGISTRY for m in selected):
                raise ValueError('유효한 모듈을 선택하세요.')
            if config.get('authorized') is not True:
                raise ValueError('대상 진단 권한 확인이 필요합니다.')
            if any(m in selected for m in ('brute', 'availability')) and config.get('active_opt_in') is not True:
                raise ValueError('반복 인증/부하 진단 실행 동의가 필요합니다.')
            for key in ('admin', 'student_a', 'student_b'):
                account = config.get(key, {})
                if not isinstance(account, dict) or set(account) != {'username', 'password'} or not all(isinstance(v, str) and len(v) <= 256 for v in account.values()):
                    raise ValueError('계정 설정 형식 오류')
            if not isinstance(config.get('idor', {}), dict) or any(not isinstance(v, str) for v in config.get('idor', {}).values()):
                raise ValueError('IDOR 설정 형식 오류')
            with LOCK:
                if JOB['state'] == 'running':
                    return self.reply(409, {'error': '이미 진단 중입니다.'})
                CANCEL.clear()
                identity = new_scan_id()
                JOB.clear()
                JOB.update(state='running', scan_id=identity, results=[], completed=0, total=len(selected), requests=0, started_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
            threading.Thread(target=run, args=(config, identity), daemon=True).start()
            self.reply(202, {'ok': True, 'scan_id': identity})
        except (ValueError, KeyError, TypeError) as exc:
            self.reply(400, {'error': str(exc)})


if __name__ == '__main__':
    print('ROOKIES Scanner: http://127.0.0.1:8765 (종료: Ctrl+C)')
    ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()
