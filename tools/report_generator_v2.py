import json
import os
from datetime import datetime, timezone, timedelta
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-6-luna"  # 사용할 모델


# ==========================================
# 1. 공통 유틸 함수
# ==========================================

def normalize_attack_type(attack_type):
    """공격 유형 이름 통일"""
    if not attack_type:
        return "Unknown"

    text = str(attack_type).lower()

    if "sql" in text:
        return "SQL Injection"
    if "xss" in text or "스크립" in text:
        return "XSS"
    if "brute" in text:
        return "Brute Force"
    if "dos" in text or "ddos" in text:
        return "DoS"
    if "path traversal" in text:
        return "Path Traversal"

    return str(attack_type)


def normalize_severity(severity):
    """위험도 이름 통일"""
    if not severity:
        return "UNKNOWN"

    severity = str(severity).upper()

    if severity in ["LOW", "MEDIUM", "HIGH"]:
        return severity

    return "UNKNOWN"


def convert_to_kst(timestamp):
    """시간을 한국 시간(KST)으로 통일"""
    if not timestamp:
        return None

    try:
        timestamp = timestamp.replace("Z", "+00:00")
        dt = datetime.fromisoformat(timestamp)
        kst = timezone(timedelta(hours=9))
        return dt.astimezone(kst).isoformat(timespec="seconds")
    except Exception:
        # 변환 실패하면 원래 값 사용
        return timestamp


def load_json(path, default=None):
    """JSON 파일 읽기 (파일이 없으면 default 반환)"""
    if not os.path.exists(path):
        print(f"[경고] 파일을 찾을 수 없습니다: {path}")
        return default

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def get_llm_report(client, prompt):
    """LLM 응답 받아서 JSON으로 변환"""
    response = client.responses.create(
        model=OPENAI_MODEL,
        input=prompt,
        store=False
    )

    text = response.output_text.strip()

    # 코드 블록 제거
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]

    if text.endswith("```"):
        text = text[:-3]

    return json.loads(text.strip())


def to_list(value):
    """recommendation을 항상 리스트로 맞추기"""
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [str(value)]


# ==========================================
# 2. 프롬프트 생성
# ==========================================

def build_web_prompt(web_input):
    return f"""
다음은 웹 보안 정규식 탐지 결과입니다.

입력 데이터:

{json.dumps(web_input, ensure_ascii=False, indent=2)}

웹 보안 관점에서 분석해주세요.

공격 유형은 가능한 경우 아래 값 중 하나만 사용하세요.

- SQL Injection
- XSS
- Path Traversal
- Other

주의사항:

1. 정규식 탐지 결과를 기반으로 분석하세요.
2. HTTP 200만으로 공격 성공을 단정하지 마세요.
3. 확인되지 않은 사실은 추측하지 마세요.
4. severity는 LOW, MEDIUM, HIGH 중 하나만 사용하세요.
5. recommendation은 대응 방안 3개를 작성하세요.

반드시 JSON 형식으로만 응답해주세요.

{{
    "attack_type": "공격 유형",
    "severity": "LOW 또는 MEDIUM 또는 HIGH",
    "summary": "탐지 결과 요약",
    "evidence": "탐지 근거",
    "impact": "예상 영향",
    "recommendation": [
        "대응 방안 1",
        "대응 방안 2",
        "대응 방안 3"
    ]
}}
"""


def build_network_prompt(network_input):
    return f"""
다음은 머신러닝 기반 네트워크 트래픽 분석 결과입니다.

입력 데이터:

{json.dumps(network_input, ensure_ascii=False, indent=2)}

네트워크 보안 관점에서 분석해주세요.

공격 유형은 가능한 경우 아래 값 중 하나만 사용하세요.

- DoS
- Brute Force
- BENIGN

주의사항:

1. 머신러닝 예측값과 확률을 근거로 분석하세요.

2. class_probabilities와 class_counts를 함께 고려하세요.

3. 확률이 매우 낮은 공격 유형은
주요 공격으로 단정하지 마세요.

4. 가장 높은 확률과 탐지 Flow 수를
중심으로 주요 공격 유형을 판단하세요.

5. 머신러닝 결과만으로 실제 공격 성공을
단정하지 마세요.

6. severity는
LOW, MEDIUM, HIGH 중 하나만 사용하세요.

7. recommendation은
구체적인 대응 방안 3개를 작성하세요.

반드시 JSON 형식으로만 응답해주세요.

{{
    "attack_type": "주요 공격 유형",
    "severity": "LOW 또는 MEDIUM 또는 HIGH",
    "summary": "분석 결과 요약",
    "evidence": "탐지 근거",
    "impact": "예상 영향",
    "recommendation": [
        "대응 방안 1",
        "대응 방안 2",
        "대응 방안 3"
    ]
}}
"""


# ==========================================
# 3. WEB 분석
# ==========================================

def analyze_web(client, filter_results):
    """정규식 탐지 결과(filter_result.json 내용)를 LLM으로 분석"""
    reports = []

    for log in filter_results:

        # 정상 요청이면 LLM 분석 생략
        if not log.get("suspicious"):
            continue

        web_input = {
            "timestamp": log.get("timestamp"),
            "source": "WEB",
            "method": log.get("method"),
            "url_path": log.get("url_path"),
            "status_code": log.get("status_code"),
            "detected_types": log.get("detected_types"),
            "evidence": log.get("evidence"),
            "request_data": log.get("request_data")
        }

        print("=" * 60)
        print("[WEB] LLM 분석 요청 중...")
        print("URL:", log.get("url_path"))
        print("탐지 유형:", log.get("detected_types"))

        try:
            llm_report = get_llm_report(client, build_web_prompt(web_input))
        except Exception as error:
            print("[WEB] 보고서 생성 오류")
            print(error)
            continue

        report = {
            # 공통 필드
            "timestamp": convert_to_kst(log.get("timestamp")),
            "source": "WEB",

            # WEB 필드
            "method": log.get("method"),
            "url_path": log.get("url_path"),
            "status_code": log.get("status_code"),

            # NETWORK 필드
            "source_file": None,
            "flow_count": None,
            "attack_probability": None,
            "class_probabilities": {},
            "class_counts": {},

            # LLM 결과
            "attack_type": normalize_attack_type(llm_report.get("attack_type")),
            "severity": normalize_severity(llm_report.get("severity")),
            "summary": llm_report.get("summary"),
            "evidence": llm_report.get("evidence"),
            "impact": llm_report.get("impact"),
            "recommendation": to_list(llm_report.get("recommendation"))
        }

        reports.append(report)

        print("[WEB] 보고서 생성 완료")
        print("공격 유형:", report["attack_type"])
        print("위험도:", report["severity"])

    return reports


# ==========================================
# 4. NETWORK 분석
# ==========================================

def analyze_network(client, network_result):
    """머신러닝 네트워크 분석 결과를 LLM으로 분석 (보고서 리스트 반환)"""
    reports = []

    if not network_result or not network_result.get("suspicious"):
        print("=" * 60)
        print("[NETWORK] 의심 트래픽 없음")
        return reports

    # 네트워크 입력 복사 (개인 PC 로컬 경로는 제외)
    network_input = network_result.copy()
    network_input.pop("prediction_csv", None)

    print("=" * 60)
    print("[NETWORK] LLM 분석 요청 중...")
    print("탐지 유형:", network_result.get("detected_types"))
    print("공격 확률:", network_result.get("attack_probability"))

    try:
        llm_report = get_llm_report(client, build_network_prompt(network_input))
    except Exception as error:
        print("[NETWORK] 보고서 생성 오류")
        print(error)
        return reports

    network_report = {
        # 공통 필드
        "timestamp": convert_to_kst(network_result.get("timestamp")),
        "source": "NETWORK",

        # WEB 필드
        "method": None,
        "url_path": None,
        "status_code": None,

        # NETWORK 필드
        "source_file": network_result.get("source_file"),
        "flow_count": network_result.get("flow_count"),
        "attack_probability": network_result.get("attack_probability"),
        "class_probabilities": network_result.get("class_probabilities", {}),
        "class_counts": network_result.get("class_counts", {}),

        # LLM 결과
        "attack_type": normalize_attack_type(llm_report.get("attack_type")),
        "severity": normalize_severity(llm_report.get("severity")),
        "summary": llm_report.get("summary"),
        "evidence": llm_report.get("evidence"),
        "impact": llm_report.get("impact"),
        "recommendation": to_list(llm_report.get("recommendation"))
    }

    reports.append(network_report)

    print("[NETWORK] 보고서 생성 완료")
    print("공격 유형:", network_report["attack_type"])
    print("위험도:", network_report["severity"])

    return reports


# ==========================================
# 5. 입력 파일 종류 판별
# ==========================================
 
NETWORK_KEYS = {
    "flow_count", "class_probabilities", "class_counts",
    "attack_probability", "source_file", "prediction_csv"
}
WEB_KEYS = {"url_path", "request_data", "method", "status_code"}
 
 # 파일 구별 함수
def detect_source(data):
    """
    JSON 내용을 보고 WEB / NETWORK 중 어느 쪽 입력인지 판별
    - 리스트 -> WEB (filter_result.json 형태)
    - 딕셔너리 + 네트워크 키(flow_count 등) -> NETWORK
    - 딕셔너리 + 웹 키(url_path 등) -> WEB (로그 1건)
    """
    if isinstance(data, list):
        return "WEB"
 
    if isinstance(data, dict):
        network_score = len(NETWORK_KEYS & data.keys())
        web_score = len(WEB_KEYS & data.keys())
 
        if network_score > web_score:
            return "NETWORK"
        if web_score > network_score:
            return "WEB"
 
    raise ValueError(
        "입력 파일이 WEB/NETWORK 어느 형식인지 판별할 수 없습니다. "
        "source='WEB' 또는 source='NETWORK'로 직접 지정하세요."
    )
 
 
# ==========================================
# 6. 전체 실행 함수
# ==========================================
 
def run_analysis(
    file_path,
    output_path="report_result.json",
    source=None,
    append=True, # 파일 중복 생성, True이면 이어쓰기, False이면 파일 새로 만들기
    api_key=None
):
    """
    파일 하나를 입력받아 WEB 또는 NETWORK 중 해당하는 쪽만 분석합니다.
    (나머지 한쪽은 실행하지 않고 대기)
 
    Parameters
    ----------
    file_path : 분석할 JSON 파일 경로 (WEB 또는 NETWORK 결과 파일)
    output_path : 통합 보고서 저장 경로
    source : "WEB" / "NETWORK" 직접 지정 (None이면 파일 내용으로 자동 판별)
    append : True면 기존 output_path 보고서에 이어서 저장,
             False면 이번 결과로 덮어쓰기
    api_key : OpenAI API 키 (없으면 .env의 OPENAI_API_KEY 사용)
 
    Returns
    -------
    list : 이번 실행에서 새로 생성된 보고서 리스트
    """
    data = load_json(file_path)
    if data is None:
        return []
 
    # WEB / NETWORK 판별
    source = (source or detect_source(data)).upper()
 
    client = OpenAI(api_key=api_key or OPENAI_API_KEY)
 
    # 해당하는 쪽만 실행
    if source == "WEB":
        if isinstance(data, dict):  # 로그 1건이면 리스트로 감싸기
            data = [data]
        new_reports = analyze_web(client, data)
 
    elif source == "NETWORK":
        new_reports = analyze_network(client, data)
 
    else:
        raise ValueError("source는 'WEB' 또는 'NETWORK'만 가능합니다.")
 
    # 기존 보고서에 이어붙이기
    reports = []
    if append:
        reports = load_json(output_path, default=[]) or []
    reports.extend(new_reports)
 
    # 시간순 정렬
    reports.sort(key=lambda x: x.get("timestamp") or "")
 
    # 통합 JSON 저장
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(reports, file, ensure_ascii=False, indent=4)
 
    print("=" * 60)
    print(f"{source} 분석 완료")
    print("이번에 생성된 보고서 수:", len(new_reports))
    print("전체 보고서 수:", len(reports))
    print(f"{output_path} 저장 완료")
 
    return new_reports
 
 
if __name__ == "__main__":
    run_analysis("filter_result.json")