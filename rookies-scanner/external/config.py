from dataclasses import dataclass, field
import os
import platform
from pathlib import Path
import re
from core import validate_target

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 20000
ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / 'external' / 'models' / 'final4.pkl'


@dataclass
class ExternalConfig:
    target: str
    authorized: bool = False
    mode: str = 'files'
    uploads: list = field(default_factory=list)
    duration: int = 30
    network: bool = True
    web: bool = True
    interface: str = ''
    auto_capture: bool = False
    fallback_interface: str = ''
    capture_host: str = ''
    capture_port: int = 0
    capture_port_only: bool = False
    capture_info: dict = field(default_factory=dict)

    def validate(self):
        self.target = validate_target(self.target)
        if not self.authorized:
            raise ValueError('이 로그와 네트워크를 분석할 권한이 있음을 확인하세요.')
        if self.mode not in ('files', 'live'):
            raise ValueError('수집 방식을 확인하세요.')
        if self.mode == 'files':
            if not self.uploads or len(self.uploads) > 10:
                raise ValueError('분석할 파일을 1~10개 선택하세요.')
            if any(not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES for _, data in self.uploads):
                raise ValueError('파일 하나의 크기는 16 MB 이하여야 합니다.')
            if sum(len(data) for _, data in self.uploads) > MAX_TOTAL_BYTES:
                raise ValueError('전체 입력 크기는 32 MB 이하여야 합니다.')
        else:
            if not 5 <= self.duration <= 120 or not (self.network or self.web):
                raise ValueError('수집 시간은 5~120초이며 수집 대상을 하나 이상 선택하세요.')
            if self.network and not self.auto_capture and not re.fullmatch(r'[A-Za-z0-9_.:\\{}-]{1,120}', self.interface):
                raise ValueError('네트워크 인터페이스 이름 또는 번호를 입력하세요.')
            if self.fallback_interface and not re.fullmatch(r'[A-Za-z0-9_.:\\{}-]{1,120}', self.fallback_interface):
                raise ValueError('수동 수집 인터페이스 이름 또는 번호를 확인하세요.')
            if self.web and not web_log_path().is_file():
                raise ValueError('서버 EXTERNAL_WEB_LOG_PATH에 읽을 수 있는 웹 로그 파일을 설정하세요.')
        return self


def web_log_path():
    # Server administrator config only. The browser cannot read arbitrary paths.
    return Path(os.environ.get('EXTERNAL_WEB_LOG_PATH', '/home/lms/burp_share/burp_live.log')).expanduser()


def dumpcap_path():
    # Ubuntu must not depend on the Streamlit service's PATH.
    return '/usr/bin/dumpcap' if platform.system() == 'Linux' else os.environ.get('EXTERNAL_DUMPCAP', 'dumpcap')
