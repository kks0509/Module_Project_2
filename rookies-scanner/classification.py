"""Requested OWASP Top 10:2021 labels, independent of verdicts and severity."""
OWASP = {
    'sqli': 'A03:2021 Injection',
    'access': 'A01:2021 Broken Access Control',
    'idor': 'A01:2021 Broken Access Control',
    'brute': 'A07:2021 Identification and Authentication Failures',
    'availability': '가용성 관련 관찰 항목',
}


def owasp_for(module):
    return OWASP.get(module, '분류 없음')
