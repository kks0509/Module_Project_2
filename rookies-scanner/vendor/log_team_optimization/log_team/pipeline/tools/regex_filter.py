import re
import json

# 공격 유형별 정규식 패턴
patterns = {
    "SQL Injection": [
        r"\bunion\s+select\b",
        r"\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"\band\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"\bdrop\s+table\b"
    ],

    "XSS": [
        r"<\s*script\b",
        r"javascript\s*:",
        r"\bonerror\s*=",
        r"\bonload\s*="
    ],

    "Path Traversal": [
        r"\.\./",
        r"\.\.\\"
    ]
}


# JSON 객체가 여러 개 섞여 있는 파일 읽기
def load_logs(filename):
    with open(filename, "r", encoding="utf-8") as file:
        text = file.read()

    logs = []
    decoder = json.JSONDecoder()
    position = 0

    while position < len(text):
        start = text.find("{", position)

        if start == -1:
            break

        try:
            log, end = decoder.raw_decode(text, start)
            logs.append(log)
            position = end

        except json.JSONDecodeError:
            position = start + 1

    return logs

# 공격 테스트 로그 읽기
def filter_logs(filename, output_path="filter_result.json"):
    # 결과를 저장할 리스트
    results = []
    logs = load_logs(filename)

    # 로그 하나씩 검사
    for index, log in enumerate(logs, start=1):
        url_path = str(log.get("url_path", ""))

        query_params = json.dumps(
            log.get("query_params", {}),
            ensure_ascii=False
        )

        request_body = str(
            log.get("request_body", "")
        )

        # 정규식 검사 대상
        request_text = " ".join([
            url_path,
            query_params,
            request_body
        ])

        detected_types = []
        evidence = []

        # 공격 패턴 검사
        for attack_type, pattern_list in patterns.items():

            for pattern in pattern_list:

                match = re.search(
                    pattern,
                    request_text,
                    re.IGNORECASE
                )
                if match:
                    detected_types.append(attack_type)

                    evidence.append({
                        "attack_type": attack_type,
                        "matched_pattern": match.group(0)
                    })
                    break

        if detected_types:
            print("의심 요청 발견")
            print("=" * 50)
            # print(f"{index}번 로그")
            print("검사 대상:", request_text)

            for attack_type in detected_types:
                print("-", attack_type)

            # 결과 만들기
            result = {
                "number": index,
                "timestamp": log.get("timestamp"),
                "method": log.get("method"),
                "url_path": log.get("url_path"),
                "status_code": log.get("status_code"),
                "suspicious": len(detected_types) > 0,
                "detected_types": detected_types,
                "evidence": evidence,           # LLM이 참고할 탐지 근거
                "request_data": request_text    # 공격 문자열이 들어있는 요청 정보
            }
        
            results.append(result)
    if results:
        # 의심 요청이 있을때만 결과 파일로 저장
        with open(
                output_path,
                "w",
                encoding="utf-8"
            ) as file:
            
                json.dump(
                    results,
                    file,
                    ensure_ascii=False,
                    indent=4
                )
        return output_path
    else:
        print("의심 패턴 없음")
        return None



if __name__=="__main__":
    filter_logs("./web_logs/web_1791222920592.json")