import os
import re
import time
import json
from datetime import datetime
from urllib.parse import urlsplit, parse_qs, unquote_plus
# from regex_filter import filter_logs

# LOG_FILE = "/mnt/hgfs/burp_share/burp_live.log"
LOG_FILE = r"/home/lms/burp_share/burp_live.log"

REQUEST_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d(?:\.\d)?$"
)

RESPONSE_RE = re.compile(
    r"^HTTP/\d(?:\.\d)?\s+(\d{3})"
)

STATIC_EXTENSIONS = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".map"
)

def is_static_file(path):
    """
    URL이 정적 파일인지 확인
    Query String은 제거한 뒤 확장자를 검사
    """

    clean_path = path.split("?", 1)[0].lower()

    return clean_path.endswith(STATIC_EXTENSIONS)

def is_separator(line):

    text = line.strip()

    return len(text) >= 10 and set(text) == {"="}

def mask_cookie(cookie):
    if not cookie:
        return None

    masked = []

    for part in cookie.split(";"):

        part = part.strip()

        if "=" in part:

            name, _ = part.split("=", 1)

            masked.append(f"{name}=***")

        else:

            masked.append(part)

    return "; ".join(masked)

def build_log(
    method,
    path,
    request_headers,
    request_body,
    status_code,
    response_body
):

    parsed = urlsplit(path)

    useful_headers = {}

    useful_header_names = [
        "Host",
        "Content-Type",
        "Origin",
        "Referer",
        "User-Agent"
    ]

    for name in useful_header_names:

        if name in request_headers:

            useful_headers[name] = request_headers[name]


    log_data = {
        "timestamp":
            datetime.now().astimezone().isoformat(),
        "method":
            method,
        "url_path":
            parsed.path,
        "query_params":
            parse_qs(
                parsed.query,
                keep_blank_values=True
            ),
        "request_body":
            unquote_plus(request_body.strip())[:2000],
        "headers":
            useful_headers,
        "cookie":
            mask_cookie(
                request_headers.get("Cookie")
            ),
        "authorization":
            "***"
            if request_headers.get("Authorization")
            else None,
        "status_code":
            status_code,
        "response_body":
            response_body.strip()[:500]
    }

    return log_data

def get_WebLog_pipeline(file_queue, log_file_path=LOG_FILE):
    """
    Burp 로그 파일을 실시간 감시하여 패킷을 추출/정제하고 
    JSON으로 출력하는 전체 파이프라인 실행 함수
    """
    
    # 로그 파일 읽기
    with open(
        log_file_path,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as f:

        f.seek(0, 2)

        print("[+] Burp 실시간 로그 파싱 시작\n")
        state = "WAIT_REQUEST"

        method = None
        path = None

        request_headers = {}
        request_body_lines = []

        status_code = None
        response_body_lines = []

        while True:
            try: 
                line = f.readline()

                # 파일 내용 갱신까지 대기 
                if not line:
                    time.sleep(0.2)
                    continue

                line = line.rstrip("\r\n")

                request_match = REQUEST_RE.match(line)

                if request_match:

                    method = request_match.group(1)
                    path = request_match.group(2)

                    if is_static_file(path):

                        print(f"[SKIP] 정적 파일 제외: {path}")
                        state = "SKIP_WAIT_RESPONSE"
                        continue

                    request_headers = {}
                    request_body_lines = []

                    status_code = None
                    response_body_lines = []

                    state = "REQUEST_HEADERS"

                    continue

                if state == "SKIP_WAIT_RESPONSE":

                    response_match = RESPONSE_RE.match(line)

                    if response_match:

                        state = "SKIP_RESPONSE"

                    continue

                if state == "SKIP_RESPONSE":

                    if is_separator(line):

                        state = "WAIT_REQUEST"

                    continue

                if state == "REQUEST_HEADERS":
                    if line == "":
                        state = "REQUEST_BODY"
                        continue

                    if ":" in line:
                        key, value = line.split(":", 1)
                        request_headers[key.strip()] = value.strip()

                    continue

                if state == "REQUEST_BODY":

                    response_match = RESPONSE_RE.match(line)

                    if response_match:

                        status_code = int(
                            response_match.group(1)
                        )

                        state = "RESPONSE_HEADERS"
                        continue

                    if is_separator(line):
                        continue

                    request_body_lines.append(line)

                    continue

                if state == "RESPONSE_HEADERS":
                    if line == "":

                        state = "RESPONSE_BODY"

                        continue


                    continue

                if state == "RESPONSE_BODY":

                    if is_separator(line):

                        log_data = build_log(

                            method,

                            path,

                            request_headers,

                            "\n".join(
                                request_body_lines
                            ),

                            status_code,

                            "\n".join(
                                response_body_lines
                            )
                        )
                        # 저장 파일 경로
                        WEB_LOG_DIR = "web_logs"
                        os.makedirs(WEB_LOG_DIR, exist_ok=True)

                        file_name = f"web_{int(time.time() * 1000)}.json"
                        file_path = os.path.abspath(os.path.join(WEB_LOG_DIR, file_name))

                        # JSON 파일로 저장
                        with open(file_path, "w", encoding="utf-8") as file:
                            json.dump(log_data, file, ensure_ascii=False, indent=4)

                        # 디스크 저장 없이 파싱 데이터를 이벤트 객체 형태로 큐에 직행
                        file_queue.put(file_path)

                        # 상태 초기화
                        state = "WAIT_REQUEST"
                        method = None
                        path = None
                        request_headers = {}
                        request_body_lines = []
                        status_code = None
                        response_body_lines = []
                        continue
                    
                    response_body_lines.append(line)
            # 강제 종료 시 루프 탈출
            except KeyboardInterrupt:
                print("\n[*] 로그 파싱 중단")
                break
            except Exception as e:
                print(f"[!] 처리 오류: {e}")
                # 상태 초기화 후 계속
                state = "WAIT_REQUEST"

if __name__ == "__main__":
    get_WebLog_pipeline()
