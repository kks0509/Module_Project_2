"""Finite version of the team's Burp parser and exact regex detection rules."""
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, parse_qs, unquote_plus
from external.config import MAX_RECORDS
from sanitizing import sanitize

PATTERNS = {
    'SQL Injection': [r'\bunion\s+select\b', r'\bor\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+',
                      r'\band\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+', r'\bdrop\s+table\b'],
    'XSS': [r'<\s*script\b', r'javascript\s*:', r'\bonerror\s*=', r'\bonload\s*='],
    'Path Traversal': [r'\.\./', r'\.\.\\'],
}
REQUEST = re.compile(r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d(?:\.\d)?$')
RESPONSE = re.compile(r'^HTTP/\d(?:\.\d)?\s+(\d{3})')
STATIC = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.woff', '.woff2', '.ttf', '.map')


def burp_records(text):
    from external.team_adapter import parse_burp
    return parse_burp(text)



def load_records(data):
    text = data.decode('utf-8-sig', errors='replace')
    if not text.strip():
        return []
    try:
        value = json.loads(text)
        if isinstance(value, dict):
            value = [value]
        if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
            raise ValueError('웹 로그 JSON은 객체 또는 객체 배열이어야 합니다.')
        records = value
    except json.JSONDecodeError:
        if REQUEST.search(text.splitlines()[0]) or any(REQUEST.match(l) for l in text.splitlines()[:100]):
            records = burp_records(text)
        else:
            # Includes the team's concatenated-object JSON and JSONL format.
            records, pos, decoder = [], 0, json.JSONDecoder()
            while pos < len(text):
                while pos < len(text) and text[pos].isspace():
                    pos += 1
                if pos == len(text):
                    break
                try:
                    value, pos = decoder.raw_decode(text, pos)
                except json.JSONDecodeError:
                    raise ValueError('지원하는 웹 로그 형식은 Burp HTTP 로그, JSON, JSONL입니다.') from None
                if not isinstance(value, dict):
                    raise ValueError('웹 로그 항목은 JSON 객체여야 합니다.')
                records.append(value)
                if len(records) > MAX_RECORDS:
                    raise ValueError('웹 로그 항목 제한(20,000개)을 초과했습니다.')
    if len(records) > MAX_RECORDS:
        raise ValueError('웹 로그 항목 제한(20,000개)을 초과했습니다.')
    if any('url_path' not in row or 'method' not in row for row in records):
        raise ValueError('웹 로그에는 method와 url_path가 필요합니다.')
    return records


def detect_web(records, source_file):
    from external.team_adapter import regex_results
    prepared, originals = [], []
    for row in records:
        parsed = urlsplit(str(row.get('url_path', '')))
        if parsed.path.lower().endswith(STATIC):
            continue
        query = row.get('query_params', parse_qs(parsed.query, keep_blank_values=True))
        prepared.append(dict(row, url_path=unquote_plus(str(row.get('url_path', ''))),
                             query_params=query,
                             request_body=unquote_plus(str(row.get('request_body', ''))) +
                             ' ' + str(row.get('request_data', ''))))
        originals.append((row, parsed, query))
    events = []
    for matched in regex_results(prepared):
        row, parsed, query = originals[matched['number'] - 1]
        evidence = [{'attack_type': item['attack_type'], 'matched_pattern': item['matched_pattern'][:160]}
                    for item in matched['evidence']]
        # Raw body, cookies, headers, authorization and query values never persist.
        events.append(sanitize({'source': 'WEB', 'source_file': source_file, 'number': matched['number'],
            'timestamp': str(row.get('timestamp') or ''),
            'timestamp_basis': row.get('timestamp_basis', 'provided_log_time'),
            'method': str(row.get('method', '')).upper()[:10], 'url_path': parsed.path[:1200],
            'parameters': list(query)[:30] if isinstance(query, dict) else [],
            'status_code': row.get('status_code') if isinstance(row.get('status_code'), int) else None,
            'suspicious': True, 'detected_types': matched['detected_types'], 'evidence': evidence,
            'pipeline_origin': 'log_team_optimization_original'}))
    return events
