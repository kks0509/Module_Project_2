"""Bounded passive collection. No traffic generation, sudo, or source deletion."""
import os
from pathlib import Path
import subprocess
import struct
import time
from urllib.parse import urlsplit
from external.config import dumpcap_path, web_log_path, MAX_FILE_BYTES, MAX_RECORDS
from external.discovery import prepare_capture
from sanitizing import sanitize, SECRET_KEY


def capture_command(config, destination):
    target = urlsplit(config.target)
    host = config.capture_host or target.hostname
    port = config.capture_port or target.port or (443 if target.scheme == 'https' else 80)
    bpf = f'tcp port {port}' if config.capture_port_only else f'host {host} and tcp port {port}'
    from external.team_adapter import original_capture_command
    original = original_capture_command(dumpcap_path(), config.interface, config.duration, destination)
    return original[:3] + ['-f', bpf] + original[3:] + [
        '-a', 'filesize:16000', '-c', str(MAX_RECORDS), '-P']


def packet_count(path):
    """Count bounded classic PCAP records (-P), without decoding/persisting payloads."""
    formats = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
               b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
    with path.open('rb') as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in formats:
            raise ValueError('수집 PCAP 헤더가 올바르지 않습니다.')
        endian = formats[header[:4]]
        count = 0
        size = path.stat().st_size
        while True:
            record = stream.read(16)
            if not record:
                return count
            if len(record) != 16:
                raise ValueError('수집 PCAP의 패킷 헤더가 잘렸습니다.')
            _, _, captured, original = struct.unpack(endian + 'IIII', record)
            if captured > original or captured > size - stream.tell():
                raise ValueError('수집 PCAP의 패킷 길이가 올바르지 않습니다.')
            stream.seek(captured, 1)
            count += 1
            if count > MAX_RECORDS:
                raise ValueError('수집 패킷 제한(20,000개)을 초과했습니다.')


def safe_debug(value):
    secrets = tuple(v for k, v in os.environ.items() if v and SECRET_KEY.search(k))
    return sanitize(str(value), secrets)[:8192]


def stop_process(proc):
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait(timeout=3)


def collect(config, directory, cancel, progress):
    proc, stream, inputs, errors = None, None, [], []
    pcap = directory / 'capture.pcap'
    stderr = directory / 'capture.stderr'
    offset, identity, web_data = 0, None, bytearray()
    diagnostics = {'source': 'COLLECTION', 'dumpcap_path': dumpcap_path(), 'interface': config.interface,
                   'capture_filter': capture_command(config, pcap)[4], 'output_pcap': str(pcap),
                   'return_code': None, 'stderr': '', 'exception_type': None,
                   'pcap_exists': False, 'pcap_size_bytes': 0, 'packet_count': None, 'state': 'starting'}
    if config.web:
        path = web_log_path()
        stat = path.stat()
        offset, identity = stat.st_size, (stat.st_dev, stat.st_ino)
    try:
        if config.network:
            try:
                prepare_capture(config)
                command = capture_command(config, pcap)
                diagnostics.update(interface=config.interface, capture_filter=command[4])
                stream = stderr.open('wb')
                proc = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                        stderr=stream, shell=False, creationflags=(
                                            subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0))
            except (ValueError, OSError) as exc:
                diagnostics.update(state='failed', exception_type=type(exc).__name__, exception_message=safe_debug(exc))
                errors.append(('NETWORK', '패킷 수집기를 시작하지 못했습니다. 상세 기술 근거의 실행 경로·예외를 확인하세요.'))
        start = time.monotonic()
        while not cancel.is_set() and time.monotonic() - start < config.duration:
            if not config.web and (proc is None or proc.poll() is not None):
                break
            if config.web:
                try:
                    stat = path.stat()
                    if (stat.st_dev, stat.st_ino) != identity or stat.st_size < offset:
                        offset, identity = 0, (stat.st_dev, stat.st_ino)
                    with path.open('rb') as web:
                        web.seek(offset)
                        chunk = web.read(min(65536, MAX_FILE_BYTES - len(web_data) + 1))
                        offset = web.tell()
                    web_data.extend(chunk)
                    if len(web_data) > MAX_FILE_BYTES:
                        raise ValueError('웹 로그 수집 크기 제한(16 MB)에 도달했습니다.')
                except OSError:
                    errors.append(('WEB', '수집 중 웹 로그를 읽지 못했습니다. 경로·읽기 권한을 확인하세요.'))
                    config.web = False
                except ValueError as exc:
                    errors.append(('WEB', str(exc))); config.web = False
            progress(f'로그·네트워크 수집 · {min(config.duration, int(time.monotonic() - start))}/{config.duration}초')
            cancel.wait(.25)
        if proc is not None:
            if proc.poll() is None and not cancel.is_set():
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
            if proc.poll() is None and not cancel.is_set():
                diagnostics.update(exception_type='TimeoutExpired', exception_message='수집 종료 대기 시간이 초과되었습니다.')
            stop_process(proc)
            diagnostics['return_code'] = proc.returncode
            diagnostics['pcap_exists'] = pcap.is_file()
            diagnostics['pcap_size_bytes'] = pcap.stat().st_size if pcap.is_file() else 0
            if cancel.is_set():
                diagnostics['state'] = 'cancelled'
            elif proc.returncode != 0 or not pcap.is_file():
                diagnostics['state'] = 'failed'
                errors.append(('NETWORK', '패킷 수집 프로세스 종료 코드 또는 출력 파일을 확인하세요. 상세 기술 근거에 기록했습니다.'))
            else:
                try:
                    if diagnostics['pcap_size_bytes'] > MAX_FILE_BYTES:
                        raise ValueError('수집 PCAP 크기 제한(16 MB)을 초과했습니다.')
                    count = packet_count(pcap) if diagnostics['pcap_size_bytes'] else 0
                    diagnostics.update(packet_count=count, state='completed' if count else 'empty')
                    if count:
                        inputs.append(('capture.pcap', pcap.read_bytes()))
                except (ValueError, OSError) as exc:
                    diagnostics.update(state='failed', exception_type=type(exc).__name__, exception_message=safe_debug(exc))
                    errors.append(('NETWORK', '수집 PCAP 검증 실패: 상세 기술 근거의 파일 크기·검증 사유를 확인하세요.'))
        if web_data:
            inputs.append(('collected_web.log', bytes(web_data[:MAX_FILE_BYTES])))
        elif config.web:
            inputs.append(('collected_web.log', b''))
        return inputs, errors
    finally:
        stop_process(proc)
        if stream is not None:
            stream.close()
        if config.network:
            if stderr.is_file():
                with stderr.open('rb') as log:
                    diagnostics['stderr'] = safe_debug(log.read(16384).decode('utf-8', errors='replace'))
            config.capture_info.update(diagnostics)
