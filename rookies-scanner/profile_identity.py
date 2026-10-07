"""Read the signed-in student's own profile; never guess a search identity."""
from dataclasses import dataclass, field
import hashlib
from html.parser import HTMLParser
import json
import re
import unicodedata
from urllib.parse import urlsplit
from profiles import DEFAULT, profile


def canonical(value):
    return re.sub(r'[\s_\-:：]', '', unicodedata.normalize('NFKC', value)).casefold()


def clean(value):
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return ''
    value = ' '.join(unicodedata.normalize('NFKC', str(value)).split())
    return value if 0 < len(value) <= 128 and value not in ('-', '?', '없음', 'null') and '{{' not in value else ''


@dataclass
class Node:
    tag: str
    attrs: dict = field(default_factory=dict)
    children: list = field(default_factory=list)

    def text(self):
        if self.tag in ('script', 'style', 'nav', 'header', 'footer'):
            return ''
        return ' '.join(c if isinstance(c, str) else c.text() for c in self.children)

    def walk(self):
        if self.tag in ('script', 'style', 'nav', 'header', 'footer'):
            return
        yield self
        for child in self.children:
            if isinstance(child, Node):
                yield from child.walk()


class ProfileHTML(HTMLParser):
    def __init__(self, body):
        super().__init__(convert_charrefs=True)
        self.root = Node('document')
        self.stack = [self.root]
        self.feed(body)

    def handle_starttag(self, tag, attrs):
        node = Node(tag, dict(attrs))
        self.stack[-1].children.append(node)
        if tag not in ('input', 'br', 'hr', 'img', 'meta', 'link', 'wbr', 'source', 'area', 'base', 'embed', 'param', 'col'):
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.stack[-1].children.append(Node(tag, dict(attrs)))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def extract_identity(body, settings):
    aliases = {kind: {canonical(a) for a in fields} for kind, fields in settings['fields'].items()}
    found = {kind: {} for kind in aliases}

    def add(label, value, strategy):
        label, value = canonical(label), clean(value)
        for kind, names in aliases.items():
            if value and label in names:
                found[kind].setdefault(value, strategy)

    try:
        document = json.loads(body)
    except ValueError:
        document = None
    def visit(value):
        if isinstance(value, dict):
            for key, child in value.items():
                add(key, child, 'json_field')
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    if document is not None:
        visit(document)
    else:
        nodes = list(ProfileHTML(body).root.walk())
        ids = {n.attrs['id']: n for n in nodes if n.attrs.get('id')}
        for node in nodes:
            if node.attrs.get('type', '').casefold() == 'password':
                continue
            value = node.attrs.get('value', node.text())
            for key in ('name', 'id', 'data-field'):
                add(node.attrs.get(key, ''), value, 'html_field')
            for key, value in node.attrs.items():
                if key.startswith('data-'):
                    add(key[5:], value, 'data_attribute')
            children = [n for n in node.children if isinstance(n, Node)]
            if node.tag == 'tr' and len(children) == 2 and all(c.tag in ('th', 'td') for c in children):
                add(children[0].text(), children[1].text(), 'table_label')
            for i, child in enumerate(children[:-1]):
                if children[i + 1].attrs.get('type', '').casefold() == 'password':
                    continue
                if child.tag == 'dt' and children[i + 1].tag == 'dd':
                    add(child.text(), children[i + 1].text(), 'definition_label')
                elif child.tag == 'label':
                    add(child.text(), children[i + 1].attrs.get('value', children[i + 1].text()), 'adjacent_label')
                elif child.tag in ('span', 'strong', 'b'):
                    add(child.text(), children[i + 1].attrs.get('value', children[i + 1].text()), 'adjacent_label')
            if node.tag == 'label':
                target = ids.get(node.attrs.get('for'))
                if target is not None and target.attrs.get('type', '').casefold() != 'password':
                    add(node.text(), target.attrs.get('value', target.text()), 'input_label')
                for child in node.walk():
                    if child.tag == 'input' and child.attrs.get('type', '').casefold() != 'password':
                        add(node.text(), child.attrs.get('value', ''), 'input_label')
            if node.tag in ('p', 'li', 'div', 'span'):
                match = re.fullmatch(r'\s*([^:：]+)[:：]\s*([^:：]+?)\s*', node.text())
                if match:
                    add(match.group(1), match.group(2), 'text_label')
    for kind in ('student_number', 'name'):
        values = found.get(kind, {})
        if len(values) > 1:
            return None, {'reason': f'{kind} 값이 여러 개여서 본인 식별값을 확정하지 못함'}
        if values:
            value, strategy = next(iter(values.items()))
            return value, {'field': kind, 'extraction': strategy}
    return None, {'reason': '학번/이름에 해당하는 명확한 필드 또는 라벨을 찾지 못함'}


def acquire_keyword(ctx, auth, spec):
    settings = {**DEFAULT['student_identity'], **profile(ctx.config).get('student_identity', {})}
    settings['fields'] = {**DEFAULT['student_identity']['fields'], **settings.get('fields', {})}
    attempts = []
    info = {'role': 'student_a', 'attempts': attempts, 'source': 'unavailable'}
    try:
        client = auth.authenticated('student_a')
        paths = settings['paths']
        if not isinstance(paths, list):
            raise ValueError('student_identity.paths는 상대 경로 목록이어야 합니다.')
        for path in paths[:3]:
            if ctx.cancel.is_set():
                raise RuntimeError('사용자가 진단을 중지했습니다.')
            attempt = {'path': path}
            attempts.append(attempt)
            try:
                probe = client.request(path)
                response = client.follow(probe)
                attempt.update(request_url=probe.trace['url'], http_status=response.status,
                               redirect_history=probe.trace['redirect_history'], final_url=response.trace['final_url'])
                if response.status != 200 or response.trace['truncated']:
                    attempt['reason'] = '본인 정보 응답이 200이 아니거나 표본이 잘림'
                    continue
                if urlsplit(response.url).path.rstrip('/') != urlsplit(path).path.rstrip('/'):
                    attempt['reason'] = '본인 정보 페이지 이외의 경로로 리다이렉트됨'
                    continue
                value, details = extract_identity(response.body, settings)
                attempt.update(details)
                if value:
                    info.update(source='student_profile', source_url=response.trace['url'], **details,
                                keyword_sha256=hashlib.sha256(value.encode()).hexdigest())
                    return value, info
            except Exception as exc:
                if ctx.cancel.is_set():
                    raise
                attempt.update(error_type=type(exc).__name__, reason=str(exc)[:200] if isinstance(exc, ValueError) else '본인 정보 요청을 완료하지 못함')
        info['automatic_failure_reason'] = '설정된 본인 정보 페이지에서 학번/이름을 확인하지 못함'
    except Exception as exc:
        if ctx.cancel.is_set():
            raise
        info.update(automatic_failure_reason=str(exc)[:200] if isinstance(exc, (ValueError, KeyError)) else '학생 A 인증/정보 획득 요청 실패',
                    error_type=type(exc).__name__)
    manual = clean(ctx.config.get('normal_keyword')) or clean(spec.get('baseline_value', ''))
    if manual:
        info.update(source='manual_input' if clean(ctx.config.get('normal_keyword')) else 'profile_fallback',
                    keyword_sha256=hashlib.sha256(manual.encode()).hexdigest())
        return manual, info
    info['reason'] = '학번/이름 자동 추출 실패 후 사용할 정상 검색어도 없습니다.'
    return None, info
