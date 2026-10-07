"""Minimal allowlisted input, strict output schema, immutable scanner results."""
from datetime import datetime, timezone
import json
import os
from llm.client import create_client, model_name, ReportGenerationError
from llm.prompts import SYSTEM_PROMPT, report_schema
from sanitizing import sanitize
from terminology import report_text

VERDICTS = {'vulnerable': '취약 확인', 'not_detected': '이번 검사에서 미탐지',
            'inconclusive': '판정 불가', 'skipped': '미실행', 'observation_required': '관찰 필요'}
EVIDENCE_KEYS = ('http_status', 'final_url', 'marker_detected', 'detected_markers',
                 'baseline_object_count', 'attack_object_count', 'extra_object_count',
                 'inconclusive_reason', 'attempts', 'normal_login_after', 'rate_limited',
                 'normal_before_verified', 'normal_after_verified', 'rate_limit_observed',
                 'lock_marker_observed', 'delay_observed', 'baseline_median_ms', 'sample_median_ms',
                 'sample_max_ms', 'response_time_ratio', 'response_time_increase_percent',
                 'concurrency', 'sample_requests', 'degradation_observed')


def prepare_input(job, secrets=()):
    job = report_text(job)
    if job.get('state') != 'done' or not job.get('results'):
        raise ReportGenerationError('완료된 진단 결과가 필요합니다.')
    results = []
    for index, result in enumerate(job['results']):
        evidence = result.get('evidence', {})
        selected = {k: evidence[k] for k in EVIDENCE_KEYS if k in evidence}
        # Timing summaries contain numbers only; never include arbitrary trace dumps.
        for key in ('baseline', 'sample', 'samples', 'observation'):
            value = evidence.get(key)
            if isinstance(value, dict):
                numeric = {k: v for k, v in value.items() if isinstance(v, (int, float, bool))}
                if numeric:
                    selected[key] = numeric
        results.append({'finding_id': str(index),
            'vulnerability': result.get('vulnerability', result.get('name', '')),
            'severity': result.get('severity', 'info').upper(), 'owasp': result.get('owasp', ''),
            'url': result.get('url', ''), 'method': result.get('method', ''),
            'parameters': result.get('parameters', []), 'verdict': VERDICTS.get(result.get('state'), '판정 불가'),
            'evidence': selected, 'reason': result.get('reason', ''), 'remediation': result.get('remedy', '')})
    cleaned = sanitize({'scan_id': job['scan_id'], 'source': job.get('source', 'internal'),
                        'target': job.get('target', ''), 'dbms': job.get('dbms', '미제공'), 'results': results},
                       (*secrets, os.environ.get('OPENAI_API_KEY', '')))
    def bounded(value):
        if isinstance(value, str):
            return value[:1200]
        if isinstance(value, list):
            return [bounded(v) for v in value[:50]]
        if isinstance(value, dict):
            return {k: bounded(v) for k, v in value.items()}
        return value
    return bounded(cleaned)


def validate_output(value, prepared):
    schema = report_schema()
    if not isinstance(value, dict) or set(value) != set(schema['required']):
        raise ReportGenerationError('AI 응답 형식이 올바르지 않습니다.')
    if any(not isinstance(value[k], str) or len(value[k]) > 30000 for k in ('summary', 'overall_assessment')):
        raise ReportGenerationError('AI 응답 형식이 올바르지 않습니다.')
    originals = {r['finding_id']: r for r in prepared['results']}
    fields = set(schema['properties']['findings']['items']['required'])
    if not isinstance(value['findings'], list) or len(value['findings']) != len(originals):
        raise ReportGenerationError('AI 응답의 진단 항목 수가 일치하지 않습니다.')
    seen = set()
    for row in value['findings']:
        if not isinstance(row, dict) or set(row) != fields or any(not isinstance(v, str) or len(v) > 30000 for v in row.values()):
            raise ReportGenerationError('AI 응답 형식이 올바르지 않습니다.')
        identity = row['finding_id']
        if identity not in originals or identity in seen:
            raise ReportGenerationError('AI 응답의 진단 식별자가 일치하지 않습니다.')
        seen.add(identity)
        row['title'] = originals[identity]['vulnerability']
    value['findings'].sort(key=lambda row: int(row['finding_id']))
    return value


def generate_report(job, *, client=None, secrets=()):
    prepared = prepare_input(job, secrets)
    owned = client is None
    model = model_name()
    try:
        client = create_client() if owned else client
        response = client.responses.create(model=model, instructions=SYSTEM_PROMPT,
            input=json.dumps(prepared, ensure_ascii=False), store=False, max_output_tokens=10000,
            text={'format': {'type': 'json_schema', 'name': 'rookies_security_report',
                             'strict': True, 'schema': report_schema()}})
        if getattr(response, 'status', 'completed') != 'completed' or not response.output_text:
            raise ReportGenerationError('AI 응답이 완료되지 않았습니다.')
        value = validate_output(json.loads(response.output_text), prepared)
        value = report_text(sanitize(value, (*secrets, os.environ.get('OPENAI_API_KEY', ''))))
    except ReportGenerationError:
        raise
    except Exception:
        raise ReportGenerationError('OpenAI 연결·인증·응답 오류가 발생했습니다. 서버 설정을 확인하세요.') from None
    finally:
        if owned and client is not None:
            try:
                client.close()
            except Exception:
                pass
    return {'scan_id': job['scan_id'], 'source': job.get('source', 'internal'), 'dbms': prepared.get('dbms', '미제공'), 'state': 'done',
            'generated_at': datetime.now(timezone.utc).isoformat(), 'model': model, **value}
