"""Session-owned scan worker. No Streamlit calls and no shared global job."""
from copy import deepcopy
import queue
import threading
from core import validate_target
from engine import new_scan_id, scan
from report_store import ReportStore, normalize_report
from sanitizing import sanitize


class ScanTask:
    def __init__(self, config, store=None):
        validate_target(config.get('target', ''))
        if config.get('authorized') is not True:
            raise ValueError('진단 권한 확인이 필요합니다.')
        if not config.get('modules'):
            raise ValueError('검사 항목을 선택하세요.')
        if any(m in config['modules'] for m in ('brute', 'availability')) and not config.get('active_opt_in'):
            raise ValueError('반복 인증/가용성 제한 검사 동의가 필요합니다.')
        self.scan_id = new_scan_id()
        self.cancel = threading.Event()
        self.events = queue.Queue()
        self.latest = {'state': 'running', 'scan_id': self.scan_id, 'total': len(config['modules']), 'completed': 0}
        self.job = None
        self.error = ''
        self.save_error = ''
        self.path = None
        self.finished = False
        self.store = store or ReportStore()
        owned_config = deepcopy(config)
        self.thread = threading.Thread(target=self._run, args=(owned_config,), daemon=True)
        self.thread.start()

    def _run(self, config):
        secrets = tuple(config.get(role, {}).get('password', '') for role in ('admin', 'student_a', 'student_b'))
        try:
            job = scan(config, self.cancel, lambda event: self.events.put(('progress', sanitize(event, secrets))),
                       scan_id=self.scan_id)
            job = normalize_report(job, secrets)
            path, save_error = None, ''
            try:
                path = self.store.save(job)
            except (OSError, ValueError):
                save_error = '진단은 종료되었으나 결과 파일을 저장하지 못했습니다. JSON을 다운로드하고 reports 폴더 권한을 확인하세요.'
            self.events.put(('done', (job, path, save_error)))
        except Exception:
            self.events.put(('error', '진단 실행 오류가 발생했습니다. 대상 연결·계정·진단 규칙을 확인하세요.'))
        finally:
            config.clear()
            secrets = ()

    def poll(self):
        while True:
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == 'progress':
                self.latest = value
            elif kind == 'done':
                self.job, self.path, self.save_error = value
                self.latest = self.job
                self.finished = True
            elif kind == 'error':
                self.error, self.finished = value, True
        return self.latest
