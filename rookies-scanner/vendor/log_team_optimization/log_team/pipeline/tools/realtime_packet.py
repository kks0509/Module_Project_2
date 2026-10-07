import os
import glob
import time
import queue
import threading
import subprocess
from datetime import datetime

PCAP_DIR = "./pcap_buffer"
ROTATE_INTERVAL = 10  # 10초 단위로 파일 분할 (환경에 맞춰 조정)
DUMPCAP_PATH = r"C:\Program Files\Wireshark\dumpcap.exe"  # Windows 예시
INTERFACE = "5"

# 완료된 PCAP 파일을 전달할 큐 (Thread-safe)
pcap_queue = queue.Queue()

def setup_directory():
    if not os.path.exists(PCAP_DIR):
        os.makedirs(PCAP_DIR)

# =========================================================
# 1. [ML 연동 인터페이스] 추후 구현할 ML 함수 인터페이스
# =========================================================
def process_ml_inference(pcap_path: str):
    """
    ML 모델 담당자가 구현할 분석 함수
    PCAP 파일 경로를 받아 패킷을 특징량(Feature)으로 변환 후 모델 예측을 수행합니다.
    """
    print(f"  [ML Worker] 분석 시작: {pcap_path}")
    
    # ----------------------------------------------------
    # TODO: ML 모델 연동 파트
    # 1. PCAP 파싱 (Scapy / PyShark 등 이용)
    # 2. Feature 추출 (Packet Length, Flow, Protocol, Flag 등)
    # 3. ml_model.predict(features)
    # ----------------------------------------------------
    
    # 예시: 임시 처리 시간 흉내 (실제 ML 연동 시 제거)
    time.sleep(2) 
    
    # ML 분석 결과 예시 (이상 탐지 시)
    anomaly_detected = True  # 예: 모델이 공격을 감지함
    
    if anomaly_detected:
        print(f"  [!] [ML 알림] 이상 패킷 감지! -> LLM 2차 분석으로 전달: {pcap_path}")
        # TODO: 여기서 LLM 분석 모듈 호출 (e.g., run_llm_analysis(...))

# =========================================================
# 2. [소비자 스레드] 큐에서 PCAP을 꺼내 ML 모델로 전달
# =========================================================
def ml_worker():
    """
    큐를 상시 감시하다가 새로운 PCAP 파일이 들어오면 ML 분석을 실행
    """
    while True:
        pcap_path = pcap_queue.get()
        if pcap_path is None:  # 종료 시그널
            break
            
        try:
            process_ml_inference(pcap_path)
        except Exception as e:
            print(f"  [!] ML 분석 중 오류 발생 ({pcap_path}): {e}")
        finally:
            # 처리 완료 후 임시 PCAP 파일 삭제 (용량 관리)
            if os.path.exists(pcap_path):
                os.remove(pcap_path)
                print(f"  [-] 처리 완료 파일 삭제: {pcap_path}")
            pcap_queue.task_done()

# =========================================================
# 3. [생성자 스레드] PCAP 파일 감지 및 큐 삽입
# =========================================================
def pcap_file_watcher():
    """
    PCAP 디렉토리를 주기적으로 확인하여 완결된 파일만 ML 큐에 넣음
    """
    processed_files = set()
    
    while True:
        # 파일 수정 시간 순 정렬
        files = sorted(glob.glob(os.path.join(PCAP_DIR, "traffic_*.pcap")), key=os.path.getmtime)
        
        # 최소 2개 이상 존재해야 마지막 전 파일이 '완전히 쓰여진 파일'임
        if len(files) > 1:
            ready_files = files[:-1]  # 작성 중인 마지막 파일 제외
            
            for pcap_file in ready_files:
                if pcap_file not in processed_files:
                    processed_files.add(pcap_file)
                    pcap_queue.put(pcap_file)  # ML 큐에 대입
                    print(f"\n[+] [Collector] 새 PCAP 큐에 추가: {os.path.basename(pcap_file)}")
                    
        time.sleep(1)

# =========================================================
# 4. [메인 파이프라인] 수집기 실행 함수
# =========================================================
def start_realtime_pipeline():
    setup_directory()
    
    # 1) ML 분석 소비자 스레드 시작
    worker_thread = threading.Thread(target=ml_worker, daemon=True)
    worker_thread.start()
    
    # 2) 파일 감시 스레드 시작
    watcher_thread = threading.Thread(target=pcap_file_watcher, daemon=True)
    watcher_thread.start()

    # 3) dumpcap 백그라운드 프로세스 실행 (-b 옵션으로 끊김 없는 연속 캡처)
    output_pattern = os.path.join(PCAP_DIR, "traffic.pcap")
    cmd = [
        DUMPCAP_PATH,
        "-i", INTERFACE,
        "-b", f"duration:{ROTATE_INTERVAL}",  # N초마다 자동 파일 분할
        "-w", output_pattern,
        "-q"
    ]
    
    print(f"[*] 실시간 패킷 수집 및 ML 파이프라인 시작 (인터페이스: {INTERFACE})...")
    dumper_process = subprocess.Popen(cmd)
    
    try:
        # 메인 스레드 유지
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 파이프라인 중단 요청 수신. 종료 작업 중...")
    finally:
        dumper_process.terminate()
        dumper_process.wait()
        pcap_queue.put(None)  # ML worker 종료 신호
        print("[*] 모든 프로세스 및 스레드가 안전하게 종료되었습니다.")

if __name__ == "__main__":
    start_realtime_pipeline()