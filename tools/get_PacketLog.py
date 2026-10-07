import os
import re
import platform
import subprocess
import time
import threading
import subprocess
from pathlib import Path
import shutil

# PCAP 저장 디렉토리 및 설정
PCAP_DIR = "./pcap_buffer"  # 저장할 PCAP 파일 디렉토리
DEFAULT_TIME = 300        # 패킷 저장 기본 시간 (600초) 동안 나온 패킷 PCAP 파일 저장

# 윈도우 환경
if platform.system() == "Windows":
    # 윈도우 환경에서 dumpcap 경로 설정
    DUMPCAP_PATH = r"C:\Program Files\Wireshark\dumpcap.exe"
# 리눅스 환경
else:                   
    DUMPCAP_PATH = "dumpcap"

# Windows와 Linux 모두에서 작동하는 dumpcap 인터페이스 자동 탐색 함수
def get_auto_interface(dumpcap_path="dumpcap"):
    os_type = platform.system()  # 'Linux' 또는 'Windows'

    try:
        # dumpcap -D 실행 (리눅스에서는 sudo 권한 필요할 수 있음)
        result = subprocess.run(
            [dumpcap_path, "-D"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=True,
        )

        lines = result.stdout.strip().splitlines()

        # 제외할 가상/루프백 인터페이스 키워드 목록
        exclude_keywords = [
            "loopback",
            "lo",
            "any",
            "docker",
            "veth",
            "br-",
            "nflog",
            "nfqueue",
            "dbus",
        ]

        fallback_idx = None

        for line in lines:
            # 포맷 매칭: "1. eth0", "1. \Device\NPF_... (Ethernet)" 등
            match = re.match(r"^(\d+)\.\s+(.*)", line.strip())
            if not match:
                continue

            idx, desc = match.group(1), match.group(2)
            desc_lower = desc.lower()

            # 1. 불필요한 가상/루프백 인터페이스 필터링
            if any(kw in desc_lower for kw in exclude_keywords):
                continue

            # 2. OS별 활성 랜카드 우선순위 매칭
            if os_type == "Linux":
                # 리눅스 주요 물리 랜카드 패턴 (eth0, ens33, enp0s3, wlan0 등)
                if any(
                    desc_lower.startswith(prefix)
                    for prefix in ["eth", "ens", "enp", "wlan", "wlp"]
                ):
                    print(
                        f"[*] [Linux] 자동 감지된 인터페이스: [{idx}] {desc}"
                    )
                    return idx

            elif os_type == "Windows":
                # 윈도우 주요 랜카드 키워드
                if "ethernet" in desc_lower or "wi-fi" in desc_lower:
                    print(
                        f"[*] [Windows] 자동 감지된 인터페이스: [{idx}] {desc}"
                    )
                    return idx

            # 3. 백업용 첫 번째 유효 인터페이스 저장
            if fallback_idx is None:
                fallback_idx = (idx, desc)

        if fallback_idx:
            print(
                f"[*] 자동 감지된 기본 인터페이스: [{fallback_idx[0]}] {fallback_idx[1]}"
            )
            return fallback_idx[0]

    except Exception as e:
        print(
            f"[!] 인터페이스 자동 탐색 실패 ({e}). 기본 인덱스 '1'을 사용합니다."
        )

    return "1"

# PCAP 저장 디렉토리 생성
def setup_directory():
    if not os.path.exists(PCAP_DIR):
        os.makedirs(PCAP_DIR)
    return os.path.abspath(PCAP_DIR)        # PCAP_DIR의 전체 경로 반환

# 현재 날짜와 시각을 이용해 고유한 파일명 생성 (예: capture_00001_20261003133045.pcap)
def setup_fileName():
    filename = "capture.pcap" 
    return os.path.join(PCAP_DIR, filename)

# PCAP 저장 디렉토리를 감시하여 작성이 완료된 파일만 큐로 전달하는 쓰레드
def pcap_file_watcher(file_queue, stop_event, pcap_dir=PCAP_DIR):
    # print(f"[디버그] Watcher 감시 시작 대상 디렉토리: {os.path.abspath(pcap_dir)}")
    processed_files = set()

    while not stop_event.is_set():
        try:
            # 1. 디렉토리 내의 .pcap 파일 목록을 수정 시간(mtime) 순으로 정렬
            files = sorted(
                [
                    os.path.join(pcap_dir, f)
                    for f in os.listdir(pcap_dir)
                    if f.endswith(".pcap")
                ],
                key=os.path.getmtime,
            )

            # 2. 파일이 2개 이상일 때만 처리
            # (가장 마지막 파일은 dumpcap이 '현재 실시간으로 작성 중'이므로 제외해야 안전함)
            if len(files) > 1:
                completed_files = files[:-1]  # 작성 진행 중인 마지막 파일 제외

                for file_path in completed_files:
                    if file_path not in processed_files:
                        # print(
                        #     f"[+] [PCAP 감시] 새 완료 파일 감지 ➔ 큐 전송: {file_path}"
                        # )
                        file_queue.put(file_path)  # 디스패처 큐로 파일 경로 전달
                        processed_files.add(file_path)

        except Exception as e:
            print(f"[!] PCAP 감시 중 오류 발생: {e}")

        time.sleep(1)  # 1초 주기로 폴링

# 패킷 캡처 전 파일 삭제
def delete_files(pcap_dir=PCAP_DIR):
    dir_path = Path(pcap_dir)
    
    # 해당 디렉토리가 존재하는지 확인
    if not dir_path.exists():
        print(f"오류: '{pcap_dir}' 디렉토리가 존재하지 않습니다.")
        return

    # 디렉토리 내부를 순회하며 삭제
    for item in dir_path.iterdir():
        try:
            if item.is_file() or item.is_symlink():
                item.unlink()  # 파일 또는 심볼릭 링크 삭제
            elif item.is_dir():
                shutil.rmtree(item)  # 하위 폴더 및 내부 콘텐츠 전체 삭제
        except Exception as e:
            print(f"기존 파일 삭제 실패 ({item}): {e}")

        
# 실시간 패킷 캡처 함수
def get_PacketLog_pipeline(file_queue, TIME=DEFAULT_TIME):
    interface = get_auto_interface(DUMPCAP_PATH)        # 자동 INTERFACE 탐색
    # pcap_queue = queue.Queue()                        # 완료된 PCAP 파일을 전달할 큐 (Thread-safe) 
    delete_files()                                      # pcap 폴더 청소
    pcap_dir = setup_directory()                        # PCAP 저장 디렉토리 생성
    
    # dumpcap 백그라운드 프로세스 실행 (-b 옵션으로 끊김 없는 연속 캡처)
    output_pattern = setup_fileName()
    cmd = [
        DUMPCAP_PATH,
        "-i", interface,
        "-F", "pcap"
        "-b", f"duration:{TIME}",  # N초마다 자동 파일 분할
        "-w", output_pattern,
        "-q"
    ]
    
    print(f"[*] 실시간 패킷 수집 및 ML 파이프라인 시작 (인터페이스: {interface})...")
    dumper_process = subprocess.Popen(
        cmd,
        stderr=subprocess.DEVNULL
        )

    # 쓰레드 제어용 이벤트 객체
    stop_event = threading.Event()

    # 파일 감시 쓰레드 구동
    watcher_thread = threading.Thread(
        target=pcap_file_watcher,
        args=(file_queue, stop_event, pcap_dir),
        daemon=True,
    )
    watcher_thread.start()
    
    try:
        # 메인 스레드 유지
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 파이프라인 중단 요청 수신. 종료 작업 중...")
    finally:
        dumper_process.terminate()
        dumper_process.wait()

        # 2. 감시 쓰레드 종료
        stop_event.set()

        # 3. dumpcap이 종료되면서 마지막으로 닫힌 최종 파일도 큐에 챙겨 넣어줌
        remaining_files = sorted(
            [
                os.path.join(pcap_dir, f)
                for f in os.listdir(pcap_dir)
                if f.endswith(".pcap")
            ],
            key=os.path.getmtime,
        )
        for file_path in remaining_files:
            # 아직 큐에 안 들어간 남아있는 마지막 PCAP 파일 처리
            # (processed_files는 쓰레드 내부 변수이므로 크기나 마직막 파일 체크하여 put)
            file_queue.put(file_path)





# 실행을 한 번만 하는 패킷 캡처 함수 (현재 미사용)
def start_pcap_dumper_once(TIME=DEFAULT_TIME):
    """
    dumpcap을 백그라운드 프로세스로 실행하여 설정한 시간동안 나온 패킷들을 PCAP 파일에 저장
    """
    setup_directory()                                   # PCAP 저장 디렉토리 생성
    output_pattern = setup_fileName()                   # 저장할 PCAP 파일 경로와 이름
    interface = get_auto_interface(DUMPCAP_PATH)        # 자동 INTERFACE 탐색

    # dumpcap 명령어 (tshark의 순수 패킷 캡처 전용 CLI 버전)
    cmd = [
        DUMPCAP_PATH,
        "-i", interface,
        # "-b", f"duration:{TIME}",  
        "-a", f"duration:{TIME}",  # 지정된 시간 동안만 캡처
        "-w", output_pattern,    
        "-q"                       # 터미널 출력 최소화 (Quiet)
    ]
    
    print(f"[*] {interface} 인터페이스에서 {TIME}초 동안 패킷 캡처를 시작합니다...")
    
    try:
        # 지정한 시간 동안 캡처가 끝날 때까지 대기 (동기 실행)
        subprocess.run(cmd, check=True)
        print(f"[+] 패킷 수집 완료 및 저장 완료 / 파일명 : {output_pattern}")
        return output_pattern
    except subprocess.CalledProcessError as e:
        print(f"[!] 패킷 수집 중 오류 발생: {e}")
        return None
    except KeyboardInterrupt:
        print("\n[*] 수집을 중단합니다.")
    
        