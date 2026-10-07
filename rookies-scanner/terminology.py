"""LMS vocabulary for human prose, never wire values or module identifiers."""
from copy import deepcopy
import re

DBMS = 'MySQL 8.4'
ABBREVIATION = re.compile(r'(?<![A-Za-z0-9_])SQLi(?![A-Za-z0-9_])', re.I)
PROSE_FIELDS = ('name', 'vulnerability', 'title', 'reason', 'remedy', 'description',
                'cause', 'impact', 'evidence_summary', 'remediation')


def human_text(value):
    return ABBREVIATION.sub('SQL Injection', value) if isinstance(value, str) else value


def report_text(value):
    """New snapshot; only explicit prose fields change. Preserve forensic data."""
    cleaned = deepcopy(value)
    if cleaned.get('source', 'internal') == 'internal' and ('scan_id' in cleaned or 'results' in cleaned):
        cleaned.setdefault('dbms', DBMS)
    for key in ('summary', 'overall_assessment'):
        if key in cleaned:
            cleaned[key] = human_text(cleaned[key])
    for group in ('results', 'findings'):
        for row in cleaned.get(group, []):
            for key in PROSE_FIELDS:
                if key in row:
                    row[key] = human_text(row[key])
            evidence = row.get('evidence', {})
            for key in ('reason', 'inconclusive_reason'):
                if key in evidence:
                    evidence[key] = human_text(evidence[key])
    return cleaned
