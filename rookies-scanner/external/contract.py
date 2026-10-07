VERDICTS = {'suspicious': '공격 의심', 'not_detected': '의심 패턴 미탐지',
            'inconclusive': '판정 불가', 'skipped': '분석 자료 없음'}


def group_web(events):
    """One finding per team pattern class/file, with counts and bounded examples."""
    groups = {}
    for event in events:
        for label in event['detected_types']:
            group = groups.setdefault(label, {**event, 'detected_types': [label], 'event_count': 0,
                                              'sample_requests': [], 'evidence': []})
            group['event_count'] += 1
            if len(group['sample_requests']) < 5:
                group['sample_requests'].append({k: event.get(k) for k in
                    ('timestamp', 'method', 'url_path', 'status_code', 'parameters')})
                group['evidence'].extend(e for e in event['evidence'] if e['attack_type'] == label)
    return list(groups.values())


def finding(scan_id, event, target):
    source = event['source']
    labels = ', '.join(event.get('detected_types', [])) or 'BENIGN'
    suspicious = event.get('suspicious', False)
    name = f'{"네트워크 ML 분류" if source == "NETWORK" else "웹 로그 패턴 탐지"} · {labels}'
    if source == 'WEB' and 'event_count' in event:
        name += f" · {event['event_count']}개 요청"
    return {'source': 'external', 'scan_id': scan_id, 'module': 'external_' + source.lower(),
            'name': name, 'vulnerability': name, 'owasp': '외부 공격 관찰',
            'url': target + event.get('url_path', '') if source == 'WEB' else target,
            'method': event.get('method', '—'), 'parameters': event.get('parameters', []),
            'state': 'suspicious' if suspicious else 'not_detected',
            'severity': 'medium' if suspicious else 'info',
            'reason': ('관측 로그에서 공격 의심 신호를 탐지했습니다. 공격 성공 또는 취약점 존재를 확정하지 않습니다.'
                       if suspicious else '제공된 Flow에서 모델이 공격 클래스를 예측하지 않았습니다. 전체 환경의 안전성을 보장하지 않습니다.'),
            'remedy': '관련 시간대의 웹·인증 로그와 함께 검증하고, 요청 제한 및 권한·입력 검증 정책을 점검하세요.',
            'evidence': event, 'requests': []}


def status_finding(scan_id, target, name, reason, state='inconclusive', evidence=None):
    return {'source': 'external', 'scan_id': scan_id, 'module': 'external_status',
            'name': name, 'vulnerability': name, 'owasp': '외부 공격 관찰', 'url': target,
            'method': '—', 'parameters': [], 'state': state, 'severity': 'info',
            'reason': reason, 'remedy': '입력 로그 형식·수집 시간·패키지·파일 권한을 확인한 뒤 다시 분석하세요.',
            'evidence': evidence or {}, 'requests': []}
