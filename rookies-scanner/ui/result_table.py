"""Wrapping results table: parameters and URLs are never ellipsized."""
from html import escape
from pathlib import Path
from llm.report_generator import VERDICTS
from terminology import human_text

CSS = Path(__file__).resolve().parent / 'result_table.css'


def result_table(results):
    out = ['<style>' + CSS.read_text(encoding='utf-8') + '</style>',
           '<div class="rookies-results-scroll" tabindex="0" role="region" aria-label="진단 결과 표">',
           '<table class="rookies-results-table"><caption>진단 결과 · 전체 파라미터 및 대상 URL</caption>',
           '<colgroup>' + ''.join(f'<col class="col-{name}">' for name in
                                 ('name', 'url', 'method', 'parameters', 'verdict', 'severity', 'owasp')) + '</colgroup>',
           '<thead><tr>' + ''.join(f'<th scope="col">{label}</th>' for label in
                                  ('취약점', '대상 URL', 'Method', '파라미터', '판정', '위험도', 'OWASP')) + '</tr></thead><tbody>']
    def text(value):
        return escape(str(value if value is not None else '—'), quote=True)
    for row in results:
        parameters = ',<br>'.join(text(p) for p in row.get('parameters', [])) or '없음'
        values = [text(human_text(row.get('name', row.get('vulnerability', '')))), text(row.get('url', '')),
                  text(row.get('method', '')), parameters, text(VERDICTS.get(row.get('state'), '판정 불가')),
                  text(str(row.get('severity', 'info')).upper()), text(row.get('owasp', ''))]
        out.append('<tr>' + ''.join(f'<td>{value}</td>' for value in values) + '</tr>')
    if not results:
        out.append('<tr><td colspan="7">표시할 진단 결과가 없습니다.</td></tr>')
    out.append('</tbody></table></div>')
    return ''.join(out)
