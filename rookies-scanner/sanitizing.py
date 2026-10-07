"""Defense in depth for persisted evidence and the much smaller LLM input."""
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = '[REDACTED]'
SECRET_KEY = re.compile(r'password|passwd|cookie|authorization|api[_-]?key|token|^session$|session[_-]?(?:id|key)|secret', re.I)
SECRET_TEXT = re.compile(r'(\b(?:password|passwd|cookie|authorization|api[_-]?key|token|session)\s*[:=]\s*)([^\r\n,;]+)', re.I)


def sanitize(value, secrets=()):
    """New objects only; never mutate the scanner snapshot. Parameter names remain."""
    secrets = tuple(sorted((s for s in secrets if isinstance(s, str) and s), key=len, reverse=True))
    if isinstance(value, dict):
        return {str(k): (REDACTED if SECRET_KEY.search(str(k)) and not isinstance(v, bool)
                         else sanitize(v, secrets)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v, secrets) for v in value]
    if not isinstance(value, str):
        return value
    for secret in secrets:
        value = value.replace(secret, REDACTED)
    value = re.sub(r'\bsk-[A-Za-z0-9_-]{8,}', REDACTED, value)
    value = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~-]+', 'Bearer ' + REDACTED, value)
    # URL query secrets can be percent encoded. Drop userinfo and fragments too.
    if value.startswith(('http://', 'https://')):
        try:
            p = urlsplit(value)
            query = [(k, REDACTED if SECRET_KEY.search(k) else sanitize(v, secrets))
                     for k, v in parse_qsl(p.query, keep_blank_values=True)]
            value = urlunsplit((p.scheme, p.netloc.rsplit('@', 1)[-1], p.path, urlencode(query), ''))
        except ValueError:
            value = REDACTED
    else:
        value = SECRET_TEXT.sub(lambda m: m.group(1) + REDACTED, value)
    return value
