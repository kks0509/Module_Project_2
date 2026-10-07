"""Write a credential-free snapshot; own and clean up the Streamlit process."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import re

ROOT = Path(__file__).resolve().parent


def save_report(job, directory=None):
    if job.get('state') not in ('done', 'cancelled') or not job.get('results'):
        raise ValueError('진단이 종료되고 결과가 있어야 리포트를 작성할 수 있습니다.')
    allowed = ('schema_version', 'source', 'scan_id', 'target', 'modules', 'started_at', 'finished_at', 'state', 'completed', 'total', 'requests', 'results')
    snapshot = {key: job[key] for key in allowed if key in job}
    directory = Path(directory or ROOT / 'reports')
    directory.mkdir(parents=True, exist_ok=True)
    identity = job.get('scan_id', '')
    filename = identity if isinstance(identity, str) and re.fullmatch(r'SCAN-[0-9a-f]{32}', identity) else uuid.uuid4().hex
    path = directory / (filename + '.json')
    path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding='utf-8')
    return path


class ReportService:
    def __init__(self):
        self.process = None
        self.lock = threading.Lock()
        self.closed = threading.Event()

    def _stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.process = None

    def open(self, job):
        if importlib.util.find_spec('streamlit') is None:
            raise RuntimeError('Streamlit이 없습니다. requirements.txt를 설치한 Python으로 앱을 실행하세요.')
        with self.lock:
            if self.closed.is_set():
                raise RuntimeError('앱이 종료 중입니다.')
            self._stop()
            path = save_report(job)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            env = {**os.environ, 'ROOKIES_REPORT_FILE': str(path)}
            log = open(ROOT / 'reports' / 'streamlit.log', 'a', encoding='utf-8')
            try:
                self.process = subprocess.Popen([sys.executable, '-m', 'streamlit', 'run', str(ROOT / 'report_app.py'),
                    '--server.address=127.0.0.1', f'--server.port={port}', '--server.headless=true',
                    '--browser.gatherUsageStats=false'], cwd=ROOT, env=env, stdout=log, stderr=log,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            finally:
                log.close()
            url = f'http://127.0.0.1:{port}'
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and not self.closed.is_set():
                if self.process.poll() is not None:
                    break
                try:
                    with opener.open(url + '/_stcore/health', timeout=.5) as response:
                        if response.status == 200 and response.read() == b'ok':
                            return url, path
                except (urllib.error.URLError, OSError):
                    pass
                self.closed.wait(.2)
            self._stop()
            raise RuntimeError('리포트 서버 시작 실패. reports/streamlit.log를 확인하세요.')

    def close(self):
        self.closed.set()
        with self.lock:
            self._stop()
