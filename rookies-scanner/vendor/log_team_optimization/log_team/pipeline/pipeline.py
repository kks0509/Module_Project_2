from tools.get_PacketLog import get_PacketLog_pipeline
from tools.parser import get_WebLog_pipeline
from tools.regex_filter import filter_logs
from tools.report_generator_v2 import run_analysis
from tools.final_test import ML_analyze
import multiprocessing
import queue
import sys
import os
import json
import traceback

WEB_KEYS = {
    "timestamp",
    "method",
    "url_path",
    "query_params",
    "request_body",
    "headers",
    "cookie",
    "authorization",
    "status_code",
    "response_body"
}


# 파이썬 내부 로직으로 로그 파일 종류(pcap, json 등) 분류하는 함수
def classify_log_type(file_path):
    if not os.path.exists(file_path):
        return "INVALID"

    # 1. PCAP / PCAPNG 바이너리 매직 넘버 검사
    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
        if header in [
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x0a\x0d\x0d\x0a",
        ]:
            return "NETWORK"
    except OSError:
        return "INVALID"

    # 2. JSON 포맷 웹 로그 검사 (파일로 들어온 경우)
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

            # JSON 배열([ ... ])인 경우 첫 번째 요소를 추출
            first_item = data[0] if isinstance(data, list) and data else data

            # 웹 로그 필수 키(method, url_path, timestamp 등) 존재 여부 검증
            if isinstance(first_item, dict):
                if any(k in first_item for k in WEB_KEYS):
                    return "WEB"
    except json.JSONDecodeError:
        # 파일 전체가 하나의 JSON이 아닌, 줄바꿈 단위 JSONL 형식일 경우 대처
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline().strip()
                parsed = json.loads(first_line)
                if isinstance(parsed, dict):
                    return "WEB"
        except Exception:
            pass
    except Exception:
        pass

    return "INVALID"

# 큐에서 파일 경로를 순차적으로 1개씩 꺼내 분류 및 개별 처리 실행
def file_dispatcher_worker(file_queue: multiprocessing.Queue):
    print("[+] 파일 통합 라우팅 디스패처 가동 완료")
    while True:
        try:
            # 큐에서 파일 경로 대기 (1초 타임아웃)
            file_path = file_queue.get(timeout=1)

            # 종료 시그널 처리
            if file_path is None:
                print("[*] 디스패처 종료 시그널 수신")
                break

            if not os.path.exists(file_path):
                print(f"  [!] 파일 존재 안 함: {file_path}")
                continue

            print(f"\n[큐 수신] 작업 대기열에서 파일 추출: {file_path}")

            # 파일 유형 판별
            log_type = classify_log_type(file_path)
            return log_type

        except queue.Empty:
            # 큐가 비어있을 때는 계속 대기
            continue
        except Exception as e:
            print(f"  [!] 디스패처 파일 처리 중 오류 발생: {e}")

if __name__ == "__main__":
    """
    통합 로그 분석 과정 
        1.      로그 수집 및 정제
        2.      웹 로그는 수집 시 정규표현식으로 1차 필터링
        2-2     나온 결과는 JSON으로 LLM에게 전달, LLM으로 분석 후 결과 출력
        3.      네트워크 패킷은 설정한 시간 단위로 pcap 파일 생성, 파일 감지 후 csv로 변환
        3-2.    csv 파일을 ML 모델에 적용시켜 분석, 공격 유무 ( BRUTE FORCE, DOS, BENIGN ) 판단
        3-3.    판단 결과를 JSON 형식으로 저장하여 LLM 모델 전달
        4.      JSON 데이터를 받은 LLM은 분석후 결과 출력
        5.      분석 결과를 Streamlit에 시각화 
    """  
    # 0. 실행 전 파라미터 설정 일단 네트워크는 시간 설정 먼저 하기 
    try:
        print("네트워크 패킷 캡처 시간을 정해주세요. (예: 60초 마다 파일 생성)")
        time = input("시간 입력 (초단위) : ")
    except KeyboardInterrupt:
        print("종료")
        sys.exit()

    # 1. 통합(웹, 네트워크) 로그 수집 및 정제
    print("통합 로그 분석을 시작합니다.")
    print("==================================================")
    print("[*] 실시간 웹/네트워크 통합 수집 파이프라인 가동")
    print("==================================================")

    # 파일 저장 공유 큐 
    shared_queue = multiprocessing.Queue()

    # 1.1 각각의 수집 함수를 별도의 프로세스로 등록
    web_process = multiprocessing.Process(
        target=get_WebLog_pipeline, name="WebLogWorker" , args=(shared_queue,)
    )
    pac_process = multiprocessing.Process(
        target=get_PacketLog_pipeline, name="PacketLogWorker", args=(shared_queue, time)
    )
    # try:
        # 1.2 프로세스 시작 (동시 실행)
    web_process.start()
    pac_process.start()

    print(f"[+] 웹 수집 프로세스 PID: {web_process.pid}")
    print(f"[+] 네트워크 수집 프로세스 PID: {pac_process.pid}")
    print("[+] 종료하려면 Ctrl + C 를 누르세요.\n")

    try:
        while True:
            try:
                file_path = shared_queue.get(timeout=1)     # 큐에 저장된 파일 읽어오기
            except queue.Empty:
                continue                                    # 없으면 대기

            log_type = classify_log_type(file_path)         # 읽은 파일 종류 파악

            if log_type == "NETWORK":                       # 파일이 네트워크 파일일 경우
                print(f"감지된 로그 파일 종류 : {log_type}")
                # 이후 ML 모델 적용 
                json_path = ML_analyze(file_path)

                if json_path is None:
                    print("[*] 이번 캡처에는 분석 가능한 네트워크 Flow가 없습니다.")
                    print("[*] 다음 캡처를 계속 처리합니다.")
                    continue

                # LLM 분석
                run_analysis(json_path)
            elif log_type == "WEB":                         # 파일이 웹 파일일 경우
                print(f"감지된 로그 파일 종류 : {log_type}")
                # 정규표현식 1차 필터링
                json_path = filter_logs(file_path)

                # 의심 요청 있을 때
                if json_path:
                    # LLM 분석
                    run_analysis(json_path)
                else:
                    pass
            else:                                           
                print(f"유효하지 않은 로그 파일입니다. ({log_type})")    # 그 외

            """ run_analysis 인자 
            file_path,
            output_path="report_result.json",
            source=None,
            append=True, # 파일 중복 생성, True이면 이어쓰기, False이면 파일 새로 만들기
            api_key=None
            """
            

    except KeyboardInterrupt:
            print("\n[*] 사용자 요청으로 전체 수집 파이프라인을 종료합니다...")

    except Exception as e:
        # 메인을 떨어뜨린 진짜 에러 원인 출력
        print("\n[!] 메인 프로세스 예외 발생 원인:")
        traceback.print_exc()        

    finally:
            # 강제 종료 처리
            if web_process.is_alive():
                web_process.terminate()
                web_process.join()
    
            if pac_process.is_alive():
                pac_process.terminate()
                pac_process.join()
    
            print("[+] 모든 수집 프로세스가 안전하게 종료되었습니다.")
            sys.exit(0)

    




