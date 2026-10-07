"""Reader-facing evidence from original facts; raw identifiers stay in debug JSON."""
import math
import re


INTERNAL_PAIR = re.compile(
    r'''(?ix)(?:["'`]?\b(?:source|scan_id|finding_id|record_count|timestamp|kind|evidence|\w+_\w+)\b["'`]?\s*[:=]
    |["'][a-zA-Z_]\w*["']\s*:)''')


def readable_text(value):
    """Hide structured dump lines in old AI prose, without editing stored values."""
    lines = []
    fenced = False
    for line in str(value or '').splitlines():
        if line.strip().startswith('```'):
            fenced = not fenced
            continue
        if fenced or INTERNAL_PAIR.search(line) or line.strip().startswith(('{', '[{', '["', "['")) or line.strip() in ('}', '[', ']', '},'):
            continue
        lines.append(line)
    return '\n'.join(lines).strip()


def count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def score(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 1 else None


def web_context(job):
    total = count(job.get('collection', {}).get('web_record_count'))
    if total == 0:
        return '이번 분석에서는 분석 가능한 웹 로그가 확보되지 않아 웹 요청 기준의 근거는 확보되지 않았습니다. 웹 인증 성공·실패 로그와의 교차 검증 결과도 없습니다.'
    if total is not None:
        return '웹 로그도 분석 대상에 포함되었으나, 네트워크 분류와 웹 인증 성공·실패 로그의 교차 검증 결과는 기록되지 않았습니다.'
    return '웹 로그 확보 여부와 인증 성공·실패 로그와의 교차 검증 결과는 기록되지 않았습니다.'


def external_evidence(original, job):
    """Only recorded quantities/classes; never infer login success or missing-data BENIGN."""
    evidence = original.get('evidence', {})
    kind = evidence.get('source', evidence.get('kind'))
    if kind == 'NETWORK':
        total = count(evidence.get('flow_count'))
        if total == 0:
            return ['분석 가능한 Flow가 없어 네트워크 공격 분류 근거는 확보되지 않았습니다.', web_context(job)]
        if total is None:
            return ['분석한 Flow 수가 기록되지 않아 네트워크 분류 근거를 확인할 수 없습니다.', web_context(job)]
        counts = evidence.get('class_counts', {})
        classes = ('BRUTE FORCE', 'DOS', 'BENIGN')
        valid = isinstance(counts, dict) and all(count(counts.get(label)) is not None for label in classes)
        consistent = valid and sum(counts[label] for label in classes) == total
        if consistent:
            selected = [f'{counts[label]:,}개가 {label}' for label in classes if counts[label]]
            paragraphs = [f'관찰 자료의 총 {total:,}개 Flow 중 ' + ', '.join(selected) + '으로 분류되었습니다.']
        else:
            paragraphs = [f'관찰 자료에서 총 {total:,}개 Flow를 분석했습니다. 클래스별 집계는 추가 확인이 필요합니다.']
        probabilities = evidence.get('class_probabilities', {})
        if consistent and isinstance(probabilities, dict):
            relevant = [label for label in classes if label != 'BENIGN' and counts[label]] or ['BENIGN']
            for label in relevant:
                value = score(probabilities.get(label))
                if counts[label] and value is not None:
                    paragraphs.append(f'{label} 클래스의 평균 모델 점수는 {value:.3f}입니다.')
        if consistent and counts['BRUTE FORCE']:
            share = counts['BRUTE FORCE'] / total * 100
            paragraphs.append(f'전체 Flow의 {share:.1f}%가 BRUTE FORCE로 분류되어, 반복 인증 공격 패턴이 관찰되었습니다. 실제 인증 성공 여부는 웹 인증 로그·성공 응답·세션 발급 근거로 별도 판단해야 합니다.')
        if consistent and counts['DOS']:
            share = counts['DOS'] / total * 100
            paragraphs.append(f'전체 Flow의 {share:.1f}%가 DOS로 분류되어, 서비스 가용성을 겨냥한 네트워크 공격 패턴이 관찰되었습니다. 실제 서비스 중단 여부는 응답시간과 가용성 관측 근거로 별도 판단해야 합니다.')
        paragraphs.append(web_context(job))
        return paragraphs
    if kind == 'WEB' or original.get('module') == 'external_web' or str(original.get('name', '')).startswith('WEB'):
        matched = count(evidence.get('event_count'))
        if matched:
            labels = [label for label in evidence.get('detected_types', []) if label in ('SQL Injection', 'XSS', 'Path Traversal')]
            pattern = ', '.join(labels) or '공격 의심'
            paragraphs = [f'웹 로그에서 {matched:,}개 요청이 {pattern} 패턴과 일치했습니다.']
            method, path, status = evidence.get('method'), evidence.get('url_path'), count(evidence.get('status_code'))
            if method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS') and isinstance(path, str) and path.startswith('/'):
                paragraphs.append(f'대표 요청은 {method} {path}입니다.' + (f' 응답 상태는 HTTP {status}입니다.' if status else ''))
            paragraphs.append('요청 패턴의 일치는 공격 성공이나 인증 성공을 확인한 결과가 아닙니다.')
            return paragraphs
        records = count(evidence.get('record_count'))
        if records:
            return [f'웹 로그의 {records:,}개 요청을 분석했으며, 설정된 공격 의심 패턴은 탐지되지 않았습니다.']
        if original.get('state') == 'inconclusive':
            return ['웹 로그를 수집하거나 분석하지 못해 웹 요청 기준의 근거를 확보하지 못했습니다.']
        return ['이번 분석에서는 분석 가능한 웹 로그가 확보되지 않아 웹 요청 기준의 근거는 확보되지 않았습니다.']
    if evidence.get('state') == 'empty' and evidence.get('packet_count') == 0:
        return ['패킷 수집은 정상 완료되었으며, 해당 시간 동안 분석 가능한 패킷은 없었습니다.', web_context(job)]
    if evidence.get('state') == 'failed' or str(original.get('name', '')).startswith('NETWORK') and original.get('state') == 'inconclusive':
        return ['패킷 수집 또는 분석을 완료하지 못해 네트워크 분류 근거를 확보하지 못했습니다.', web_context(job)]
    return [readable_text(original.get('reason')) or '확인 가능한 근거가 기록되지 않았습니다. 상세 기술 데이터에서 분석 상태를 확인하세요.']
