import os


class ReportGenerationError(RuntimeError):
    """Safe user-facing error; do not attach SDK response bodies or credentials."""


def create_client():
    key = os.environ.get('OPENAI_API_KEY', '').strip()
    if not key:
        raise ReportGenerationError('서버 환경변수 OPENAI_API_KEY가 설정되지 않았습니다.')
    try:
        from openai import OpenAI
    except ImportError:
        raise ReportGenerationError('서버에 OpenAI SDK를 설치하세요.') from None
    # Fixed official endpoint; no browser-provided URLs or tools. No automatic retries.
    return OpenAI(api_key=key, base_url='https://api.openai.com/v1', timeout=60.0, max_retries=0)


def model_name():
    return os.environ.get('OPENAI_MODEL', 'gpt-4o-mini').strip() or 'gpt-4o-mini'
