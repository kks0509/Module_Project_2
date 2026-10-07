from copy import deepcopy
import queue
import threading
import uuid
from external.pipeline import run_pipeline
from external.discovery import prepare_capture
from report_store import ReportStore


class ExternalTask:
    def __init__(self, config, store=None):
        config.validate()
        prepare_capture(config)
        self.scan_id = 'SCAN-' + uuid.uuid4().hex
        self.events, self.cancel = queue.Queue(), threading.Event()
        self.finished, self.job, self.error = False, None, ''
        self.latest = {'completed': 0, 'total': 3, 'module': '외부 진단 준비'}
        self.store = store or ReportStore()
        self.thread = threading.Thread(target=self._run, args=(deepcopy(config),), daemon=True)
        self.thread.start()

    def _run(self, config):
        try:
            job = run_pipeline(config, self.scan_id, self.store, self.cancel,
                               lambda event: self.events.put(('progress', event)))
            self.events.put(('done', job))
        except Exception:
            self.events.put(('error', '외부 분석 실행·저장에 실패했습니다. reports 폴더 권한과 서버 수집 설정을 확인하세요.'))
        finally:
            config.uploads.clear()

    def poll(self):
        while True:
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == 'progress':
                self.latest = value
            elif kind == 'done':
                self.job = value; self.latest = value; self.finished = True
            elif kind == 'error':
                self.error = value; self.finished = True
        return self.latest
