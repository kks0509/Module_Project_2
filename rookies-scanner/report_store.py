"""Normalized internal/external report contract and per-scan durable history."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import uuid
from sanitizing import sanitize
from terminology import report_text

ROOT = Path(__file__).resolve().parent / 'reports'
TOP_KEYS = ('schema_version', 'source', 'scan_id', 'target', 'dbms', 'modules', 'started_at',
            'finished_at', 'state', 'completed', 'total', 'requests', 'results')
FINDING_KEYS = ('source', 'scan_id', 'module', 'name', 'vulnerability', 'owasp', 'url',
                'method', 'parameters', 'state', 'severity', 'evidence', 'reason', 'remedy', 'requests')


def valid_scan_id(value):
    return isinstance(value, str) and bool(re.fullmatch(r'SCAN-[A-Za-z0-9-]{1,80}', value))


def normalize_report(report, secrets=()):
    """External producers may adopt this contract; no external probing is included."""
    if not isinstance(report, dict) or not isinstance(report.get('results', []), list):
        raise ValueError('결과 JSON 구조가 올바르지 않습니다.')
    if not valid_scan_id(report.get('scan_id')) or report.get('source', 'internal') not in ('internal', 'external'):
        raise ValueError('Scan ID 또는 결과 source가 올바르지 않습니다.')
    source = report.get('source', 'internal')
    result = {k: deepcopy(report[k]) for k in TOP_KEYS if k in report}
    result['source'] = source
    if source == 'external':
        for key in ('collection', 'pipeline_inputs'):
            if key in report:
                result[key] = deepcopy(report[key])
    result['results'] = []
    for item in report.get('results', []):
        if not isinstance(item, dict):
            raise ValueError('진단 항목 구조가 올바르지 않습니다.')
        finding = {k: deepcopy(item[k]) for k in FINDING_KEYS if k in item}
        finding.update(scan_id=report['scan_id'], source=source)
        result['results'].append(finding)
    return sanitize(report_text(result), secrets)


def write_json(path, value):
    """Atomic replace. UUID sibling avoids platform-specific tempfile ACL issues."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name('.' + uuid.uuid4().hex + '.tmp')
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


class ReportStore:
    def __init__(self, root=None):
        self.root = Path(root) if root is not None else ROOT

    def directory(self, identity):
        if not valid_scan_id(identity):
            raise ValueError('Scan ID가 올바르지 않습니다.')
        return self.root / identity

    def save(self, job, secrets=()):
        if job.get('state') not in ('done', 'cancelled'):
            raise ValueError('종료된 진단만 저장할 수 있습니다.')
        snapshot = normalize_report(job, secrets)
        path = self.directory(snapshot['scan_id']) / (snapshot['source'] + '_report.json')
        write_json(path, snapshot)
        return path

    def save_ai(self, identity, result):
        # This companion never overwrites the rule-based report.
        if result.get('scan_id') != identity:
            raise ValueError('AI 보고서의 Scan ID가 일치하지 않습니다.')
        path = self.directory(identity) / 'ai_report.json'
        write_json(path, sanitize(report_text(result)))
        return path

    def load_ai(self, identity):
        path = self.directory(identity) / 'ai_report.json'
        return self._read(path) if path.is_file() else None

    @staticmethod
    def _read(path):
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('보고서 크기 제한 초과')
        return sanitize(json.loads(path.read_text(encoding='utf-8')))

    def history(self):
        jobs = []
        paths = list(self.root.glob('SCAN-*/internal_report.json')) + list(self.root.glob('SCAN-*/external_report.json'))
        # Read previous desktop snapshots as well, without changing them.
        paths += list(self.root.glob('SCAN-*.json'))
        for path in paths:
            try:
                jobs.append(normalize_report(self._read(path)))
            except (OSError, ValueError, TypeError, KeyError):
                continue
        return sorted(jobs, key=lambda j: j.get('started_at', ''), reverse=True)


def ai_failure(identity, message):
    return {'scan_id': identity, 'source': 'internal', 'state': 'failed',
            'generated_at': datetime.now(timezone.utc).isoformat(), 'error': message}
