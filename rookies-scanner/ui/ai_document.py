"""Continuous report presentation; no scanner rules, prompts or API calls."""
from datetime import datetime
from html import escape
from pathlib import Path
import re
from zoneinfo import ZoneInfo

from llm.report_generator import VERDICTS
from sanitizing import sanitize
from terminology import report_text
from ui.evidence_summary import external_evidence, readable_text

CSS = Path(__file__).resolve().parent / 'ai_document.css'


def text(value):
    return escape(str(value if value is not None else '—'), quote=True)


def prose(value, fallback='AI 설명이 제공되지 않았습니다.'):
    value = readable_text(value) or fallback
    return ''.join('<p>' + text(p).replace('\n', '<br>') + '</p>'
                   for p in re.split(r'\n\s*\n', value))


def timestamp(value):
    try:
        return datetime.fromisoformat(value).astimezone(ZoneInfo('Asia/Seoul')).strftime('%Y-%m-%d %H:%M:%S KST')
    except (ValueError, TypeError):
        return value or '—'


def linked_findings(value, job):
    """Scanner order is authoritative, even for missing/reordered AI findings."""
    rows = {}
    for row in value.get('findings', []):
        if isinstance(row, dict):
            rows.setdefault(str(row.get('finding_id', '')), row)
    return [(original, rows.get(str(index), {}))
            for index, original in enumerate(job.get('results', []))]


def recommendations(pairs):
    """Group identical advice (whitespace/bullet/case normalized), keep provenance.

    Priority comes from original verdict/severity, never AI-modified metadata.
    Semantically different advice is deliberately not merged without an LLM call.
    """
    grouped = {}
    rank = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
    for index, (original, row) in enumerate(pairs, 1):
        for line in re.split(r'\n\s*\n|\n', readable_text(row.get('remediation'))):
            advice = re.sub(r'^\s*(?:[-*•]\s+|\d+[.)]\s+)', '', line).strip()
            if not advice:
                continue
            identity = re.sub(r'\s+', ' ', advice).casefold()
            priority = (original.get('state') != 'vulnerable', rank.get(str(original.get('severity', '')).lower(), 4), index)
            item = grouped.setdefault(identity, {'advice': advice, 'refs': [], 'priority': priority})
            item['priority'] = min(item['priority'], priority)
            if index not in item['refs']:
                item['refs'].append(index)
    return sorted(grouped.values(), key=lambda item: item['priority'])


def facts_table(rows, caption=None):
    return ('<table class="report-facts">' + (f'<caption>{text(caption)}</caption>' if caption else '') +
            '<tbody>' + ''.join(f'<tr><th scope="row">{text(label)}</th><td>{text(value)}</td></tr>'
                               for label, value in rows) + '</tbody></table>')


def evidence_table(original):
    evidence = original.get('evidence', {})
    rows = []
    if original.get('source') == 'external':
        return ''
    for key, label in [('http_status', 'HTTP Status'), ('final_url', 'Final URL'),
                       ('detected_markers', '탐지된 Marker'), ('marker_detected', 'Marker 탐지 여부'),
                       ('baseline_object_count', 'Baseline 결과 수'), ('attack_object_count', 'Attack 결과 수'),
                       ('extra_object_count', '추가 객체 수'), ('inconclusive_reason', '판정 불가 사유')]:
        if key in evidence:
            value = evidence[key]
            if isinstance(value, list):
                value = ', '.join(map(str, value)) or '없음'
            rows.append((label, value))
    return facts_table(rows, 'Scanner 원본 근거 요약') if rows else ''


def build_document(value, job):
    """Return escaped HTML. Both inputs stay unchanged, including raw metadata."""
    if value.get('scan_id') != job.get('scan_id') or value.get('source', 'internal') != job.get('source', 'internal'):
        raise ValueError('AI 보고서와 Scanner 원본의 Scan ID 또는 source가 일치하지 않습니다.')
    value, job = sanitize(report_text(value)), sanitize(report_text(job))
    pairs = linked_findings(value, job)
    source = job.get('source', 'internal')
    if source == 'external':
        from external.contract import VERDICTS as external_verdicts
        verdicts = external_verdicts
    else:
        verdicts = VERDICTS
    kind = '내부 취약점 진단' if source == 'internal' else '외부 공격 진단'
    english = 'Internal Vulnerability Assessment Report' if source == 'internal' else 'External Assessment Report'
    explanation_note = ('관측 근거 요약은 원본 수치로 작성하며, 개요·원인·영향·대응 방안 및 종합 의견은 AI 설명입니다.'
                        if source == 'external' else '개요·원인·영향·근거 설명·대응 방안 및 종합 의견은 AI가 작성한 설명입니다.')
    sections = [('overview', '1. 진단 개요'), ('summary', '2. 진단 결과 요약'),
                ('findings', '3. 상세 진단 결과'), ('assessment', '4. 종합 분석'), ('recommendations', '5. 종합 대응 권고')]
    out = ['<article class="rookies-report" aria-label="AI 보안 진단 리포트">',
           '<header class="report-header"><div class="report-brand">ROOKIES Scanner</div>',
           '<h1>' + ('AI 기반 외부 공격 관찰 리포트' if source == 'external' else 'AI 기반 LMS 보안 진단 리포트') + '</h1>', f'<p>{english}</p></header>',
           facts_table([('Scan ID', job.get('scan_id')), ('진단 대상', job.get('target', '—')),
                        ('진단 유형', kind), ('DBMS', job.get('dbms', '미제공')), ('진단 시작', timestamp(job.get('started_at'))),
                        ('진단 종료', timestamp(job.get('finished_at'))), ('총 요청 수', job.get('requests', 0)),
                        ('AI 보고서 생성', timestamp(value.get('generated_at')))]),
           '<p class="report-note">판정·위험도·OWASP·URL·Method와 진단 결과는 Scanner 원본입니다. '
           + explanation_note + '</p>',
           '<nav class="report-toc" aria-label="보고서 목차"><h2>목차</h2><ol>']
    for anchor, label in sections:
        out.append(f'<li><a href="#report-{anchor}">{label}</a>')
        if anchor == 'findings':
            out.append('<ol>')
            for index, (original, _) in enumerate(pairs, 1):
                title = original.get('name', original.get('vulnerability', '진단'))
                out.append(f'<li><a href="#report-finding-{index}">3.{index} {text(title)}</a></li>')
            out.append('</ol>')
        out.append('</li>')
    out.append('</ol></nav><section id="report-overview"><h2>1. 진단 개요</h2>')
    if source == 'external':
        collection = job.get('collection', {})
        out.append('<p>본 보고서는 웹 로그 패턴 선별 및 네트워크 ML 분류를 설명합니다. '
                   '공격 의심은 공격 성공 또는 취약점 확인을 의미하지 않습니다. '
                   '클래스별 평균 모델 점수는 전체 Flow를 기준으로 계산하며, 공격 성공 확률이 아닙니다.</p>')
        out.append(facts_table([('웹 요청 수', collection.get('web_record_count', 0)),
                               ('네트워크 Flow 수', collection.get('flow_count', 0))]))
    else:
        out.append('<p>본 진단은 ROOKIES Scanner의 규칙 기반 검사 결과를 대상으로 작성되었습니다. '
                   '아래 보고서는 해당 Scan ID에 기록된 진단 범위와 확인된 근거를 기준으로 읽어주세요.</p>')
    out.append('<h3>AI 진단 개요</h3>' + prose(value.get('summary')) + '</section>')
    out.append('<section id="report-summary"><h2>2. 진단 결과 요약</h2>')
    results = [original for original, _ in pairs]
    counts = [('총 진단 항목', len(results))]
    counts += [(label, sum(r.get('state') == state for r in results)) for state, label in verdicts.items()]
    counts += [(s.upper(), sum(str(r.get('severity', '')).lower() == s for r in results))
               for s in ('high', 'medium', 'low', 'info') if s != 'low' or any(r.get('severity') == 'low' for r in results)]
    out.append(facts_table(counts, 'Scanner 원본 결과 집계'))
    out.append('<p class="report-note">위험도 집계는 관찰 필요·판정 불가 등 모든 진단 항목을 포함합니다.</p></section>')
    out.append('<section id="report-findings"><h2>3. 상세 진단 결과</h2>')
    for index, (original, row) in enumerate(pairs, 1):
        title = original.get('name', original.get('vulnerability', '진단'))
        severity = str(original.get('severity', 'info')).upper()
        badge = severity.lower() if severity.lower() in ('high', 'medium', 'low', 'info') else 'info'
        verdict = verdicts.get(original.get('state'), '판정 불가')
        out.append(f'<section class="report-finding" id="report-finding-{index}"><h3>3.{index} {text(title)}</h3>')
        out.append(f'<p class="report-severity">위험도 <span class="severity-{badge}">{text(severity)}</span></p>')
        out.append(facts_table([('OWASP', original.get('owasp', '—')), ('판정', verdict),
                               ('대상 URL', original.get('url', '—')), ('HTTP Method', original.get('method', '—')),
                               ('파라미터', ', '.join(original.get('parameters', [])) or '없음')], 'Scanner 원본'))
        out.append('<h4>① ' + ('관측 개요' if source == 'external' else '취약점 개요') + ' <small>AI 설명</small></h4>' + prose(row.get('description')))
        out.append('<h4>② 진단 결과 <small>Scanner 원본</small></h4>' + prose(original.get('reason'), '원본 판정 이유가 기록되지 않았습니다.'))
        out.append('<h4>③ 발생 원인 <small>AI 설명</small></h4>' + prose(row.get('cause')))
        out.append('<h4>④ 예상 영향 <small>AI 설명</small></h4>' + prose(row.get('impact')))
        out.append('<h4>⑤ 진단 근거</h4>')
        if source == 'external':
            out.append('<p class="report-label">관측 근거 요약 · Scanner 원본</p>')
            out.extend(prose(paragraph) for paragraph in external_evidence(original, job))
        else:
            out.append(evidence_table(original) + '<p class="report-label">AI 근거 설명</p>' + prose(row.get('evidence_summary')))
        out.append('<h4>⑥ 대응 방안 <small>AI 설명</small></h4>' + prose(row.get('remediation')) + '</section>')
    if not pairs:
        out.append('<p>기록된 진단 항목이 없습니다.</p>')
    out.append('</section><section id="report-assessment"><h2>4. 종합 분석</h2><p class="report-label">AI 종합 의견</p>')
    out.append(prose(value.get('overall_assessment')) + '</section>')
    out.append('<section id="report-recommendations"><h2>5. 종합 대응 권고</h2>')
    out.append('<p class="report-note">AI가 작성한 대응 방안 중 동일 문구를 묶었습니다. Scanner에서 취약 확인된 항목을 '
               '위험도 순으로 먼저 배치하고, 관찰 및 기타 항목을 이어서 표시합니다.</p>')
    advice = recommendations(pairs)
    for index, item in enumerate(advice, 1):
        refs = ', '.join('3.' + str(ref) for ref in item['refs'])
        out.append(f'<h3>우선순위 {index}</h3>' + prose(item['advice']) + f'<p class="report-label">관련 항목: {refs}</p>')
    if not advice:
        out.append('<p>AI 대응 방안이 제공되지 않았습니다. 원본 Scanner의 대응 방안을 확인하세요.</p>')
    out.append('</section><footer>ROOKIES Scanner · 원본 Scan ID와 연결된 AI 분석 리포트</footer></article>')
    return '<style>' + CSS.read_text(encoding='utf-8') + '</style>' + ''.join(out)
