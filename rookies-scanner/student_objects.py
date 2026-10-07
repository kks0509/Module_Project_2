"""Extract object identities from HTML; retain only fingerprints in scan evidence."""
from dataclasses import dataclass
import hashlib
from html.parser import HTMLParser
import re
import unicodedata
from urllib.parse import unquote, urlsplit


def normalized(value):
    return ' '.join(unicodedata.normalize('NFKC', value).split()).casefold()


class StudentHTML(HTMLParser):
    def __init__(self, body):
        super().__init__(convert_charrefs=True)
        self.tables, self.stack, self.links = [], [], []
        self.row = self.cell = None
        self.hidden = 0
        self.feed(body)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('script', 'style'):
            self.hidden += 1
        if tag == 'a' and not self.hidden:
            self.links.append(attrs.get('href', ''))
        if tag == 'table':
            table = []
            self.tables.append(table)
            self.stack.append(table)
        elif tag == 'tr' and self.stack:
            self.row = {'cells': [], 'header': False, 'spanning': False}
        elif tag in ('td', 'th') and self.row is not None:
            self.cell = []
            self.row['header'] |= tag == 'th'
            self.row['spanning'] |= attrs.get('colspan', '1') != '1'
        elif tag == 'br' and self.cell is not None:
            self.cell.append(' ')

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.hidden = max(0, self.hidden - 1)
        elif tag in ('td', 'th') and self.cell is not None and self.row is not None:
            self.row['cells'].append(normalized(''.join(self.cell)))
            self.cell = None
        elif tag == 'tr' and self.row is not None and self.stack:
            self.stack[-1].append(self.row)
            self.row = None
        elif tag == 'table' and self.stack:
            self.stack.pop()

    def handle_data(self, data):
        if self.cell is not None and not self.hidden:
            self.cell.append(data)


@dataclass
class Objects:
    values: set
    mode: str
    reason: str = ''

    def fingerprints(self):
        return sorted(hashlib.sha256(v.encode()).hexdigest() for v in self.values)


def extract_students(body, link_pattern=r'^/admin/students/([^/]+)/?$'):
    parsed = StudentHTML(body)
    links = set()
    for link in parsed.links:
        match = re.fullmatch(link_pattern, unquote(urlsplit(link).path))
        if match and match.lastindex and match.group(1):
            links.add('link:' + normalized(match.group(1)))
    if links:
        return Objects(links, 'detail_link_id')
    candidates = []
    preferred = []
    empty_modes = []
    for table in parsed.tables:
        headers = [r['cells'] for r in table if r['header']]
        rows = [r['cells'] for r in table if not r['header'] and not r['spanning'] and any(r['cells'])]
        header_text = ' '.join(v for row in headers for v in row)
        if not rows:
            if any(word in header_text for word in ('학생', '학번', 'student', '학적')):
                empty_modes.append('normalized_row' if headers[0][0] in ('no', 'no.', '#', '순번') else 'first_column')
            continue
        item = (rows, headers[0] if headers else [])
        if any(word in header_text for word in ('학생', '학번', 'student', '학적')):
            preferred.append(item)
        elif all(len(row) >= 2 for row in rows):
            candidates.append(item)
    tables = preferred or candidates
    if not tables and len(empty_modes) == 1:
        return Objects(set(), empty_modes[0])
    if len(tables) != 1:
        return Objects(set(), 'unavailable', '학생 목록 테이블이 없거나 여러 개여서 객체를 확정할 수 없습니다.')
    rows, headers = tables[0]
    first = [row[0] for row in rows]
    ordinal = bool(headers and headers[0] in ('no', 'no.', '#', '순번'))
    if not ordinal and all(first) and len(first) == len(set(first)):
        return Objects({'column:' + value for value in first}, 'first_column')
    # Repeated first cells/ordinal columns are not stable identities.
    values = {'row:' + '\x1f'.join(row[1:] if ordinal else row) for row in rows}
    return Objects(values, 'normalized_row')
