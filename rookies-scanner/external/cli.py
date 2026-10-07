"""Ubuntu terminal entry point for the same external pipeline as the web UI."""
import argparse
from pathlib import Path
import threading
import uuid
from dotenv import load_dotenv
from external.config import ExternalConfig, ROOT, MAX_FILE_BYTES
from external.pipeline import run_pipeline
from external.discovery import prepare_capture
from external.llm_report import generate_report
from llm.client import ReportGenerationError
from report_store import ReportStore, ai_failure


def main():
    load_dotenv(ROOT / '.env', override=False)
    parser = argparse.ArgumentParser(description='ROOKIES Scanner 외부 로그/네트워크 진단')
    parser.add_argument('--target', required=True)
    parser.add_argument('--input', action='append', default=[], help='PCAP / CSV / 웹 로그 / NETWORK JSON')
    parser.add_argument('--collect', action='store_true', help='앱 실행 서버에서 제한 시간 수집')
    parser.add_argument('--interface', default='', help='수집 인터페이스 직접 지정. 생략 시 CLI의 ZeroTier → Docker bridge 자동 감지 사용')
    parser.add_argument('--duration', type=int, default=30)
    parser.add_argument('--web', action='store_true')
    parser.add_argument('--network', action='store_true')
    parser.add_argument('--authorized', action='store_true', help='허가된 로그 및 네트워크임을 확인')
    parser.add_argument('--ai', action='store_true', help='완료 후 OpenAI API 보고서 생성')
    args = parser.parse_args()
    uploads = []
    try:
        for name in args.input:
            path = Path(name)
            if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError('입력 파일을 확인하세요. 파일당 최대 16 MB입니다.')
            uploads.append((path.name, path.read_bytes()))
        config = ExternalConfig(args.target, args.authorized, 'live' if args.collect else 'files', uploads,
                                args.duration, args.network, args.web, args.interface,
                                auto_capture=not bool(args.interface)).validate()
        prepare_capture(config)
        store = ReportStore()
        identity = 'SCAN-' + uuid.uuid4().hex
        print('Scan ID:', identity)
        job = run_pipeline(config, identity, store, threading.Event(),
                           lambda event: print(f"{event['current']}/{event['total']} · {event['module']}"))
        print('저장:', store.directory(identity) / 'external_report.json')
        if args.ai:
            try:
                report = generate_report(job)
            except ReportGenerationError as exc:
                report = ai_failure(identity, str(exc)); report['source'] = 'external'
            store.save_ai(identity, report)
            print('AI 보고서:', report['state'])
    except (ValueError, OSError) as exc:
        parser.exit(1, '외부 진단 설정/입력 오류: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
