import html
import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
import pandas as pd
import streamlit as st


APP_DIR = Path(__file__).resolve().parent
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
SEVERITY_KO = {
    "CRITICAL": "치명적",
    "HIGH": "높음",
    "MEDIUM": "중간",
    "LOW": "낮음",
    "INFO": "정보",
    "UNKNOWN": "미분류",
}


def resolve_path(env_name: str, *candidates: Path) -> Path:
    configured = os.getenv(env_name)
    if configured:
        return Path(configured)
    return next((path for path in candidates if path.exists()), candidates[0])


WEB_REPORT_PATH = resolve_path(
    "WEB_REPORT_JSON_PATH",
    APP_DIR / "report_result_v2.json",
)
NETWORK_REPORT_PATH = resolve_path(
    "NETWORK_REPORT_JSON_PATH",
    APP_DIR / "slowdata_network_input.json",
)

st.set_page_config(
    page_title="ROOKIES Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;600;700;800&display=swap');
:root {
    --green:#278a50; --green-dark:#173d31; --green-soft:#f1f6f3;
    --ink:#172d26; --muted:#718079; --line:#d9e1dd; --white:#fff;
    --high:#c63b43; --medium:#b47712; --low:#3971a6;
}
* { box-sizing:border-box; }
html, body, [class*="css"] { font-family:'Noto Sans KR', sans-serif; }
.stApp { color:var(--ink); background:var(--white); }
#MainMenu, footer, [data-testid="stDecoration"], [data-testid="stStatusWidget"] { display:none !important; }
[data-testid="stHeader"] { background:rgba(255,255,255,.94); }
.block-container { max-width:980px; padding:3.6rem 2.6rem 6rem; }

[data-testid="stSidebar"] {
    width:230px !important; background:#f2f7f4; border-right:1px solid #e2e9e5;
}
[data-testid="stSidebar"] > div:first-child { padding-top:3.7rem; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#6e7d76; }
.side-title { color:var(--ink); font-size:.82rem; font-weight:700; margin:0 0 .25rem; }
.side-note { color:#7b8983; font-size:.76rem; line-height:1.65; margin-top:1.2rem; }
[data-testid="stSidebar"] [data-testid="stRadio"] label {
    min-height:1.55rem; padding:.05rem 0; font-size:.82rem;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label p { color:#31443d; }
[data-testid="stSidebar"] input[type="radio"] { accent-color:var(--green); }
label[data-testid="stRadioOption"][data-selected="true"] > div > div > div:first-child {
    background:var(--green) !important; border-color:var(--green) !important;
}

.brand { margin-bottom:1.75rem; }
.brand-name { color:var(--green-dark); font-size:2.45rem; font-weight:800; letter-spacing:.015em; }
.brand-copy { color:var(--muted); font-size:.78rem; margin-top:.35rem; }
.page-title { color:var(--ink); font-size:1.72rem; font-weight:800; letter-spacing:-.035em; margin:.5rem 0 1rem; }
.page-copy { color:#4e6159; font-size:.88rem; line-height:1.8; margin-bottom:1.5rem; }
.eyebrow { color:#285e4c; font-size:.88rem; font-weight:700; letter-spacing:.12em; text-align:center; }
.report-title { color:var(--ink); font-size:1.8rem; font-weight:800; text-align:center; margin:1rem 0 .6rem; }
.report-subtitle { color:#33443e; font-size:.92rem; text-align:center; margin-bottom:2.4rem; }
.green-rule { height:3px; background:#285e4c; margin:0 0 1.55rem; }

.panel { border:1px solid var(--line); border-radius:7px; padding:1.15rem; margin:1rem 0; }
.muted { color:var(--muted); font-size:.76rem; line-height:1.7; }
.progress-copy { font-size:.76rem; margin-bottom:.4rem; }
.progress-track { height:8px; background:#e4ebe7; border-radius:8px; overflow:hidden; }
.progress-value { height:100%; background:var(--green); border-radius:8px; }

.metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(135px,1fr)); gap:1.1rem; margin:1.25rem 0 2rem; }
.metric { padding:.15rem 0; }
.metric-label { color:#344a41; font-size:.78rem; margin-bottom:.25rem; }
.metric-value { color:var(--ink); font-size:2rem; line-height:1.15; }

.section { border-top:1px solid var(--line); margin-top:2.1rem; padding-top:1.55rem; }
.section:first-child { border-top:0; margin-top:0; }
.section-title { color:var(--ink); font-size:1.38rem; font-weight:800; margin-bottom:1rem; }
.subsection-title { color:var(--ink); font-size:1.05rem; font-weight:800; margin:1.35rem 0 .8rem; }
.body-text { color:#203b31; font-size:.88rem; line-height:1.85; }
.toc { color:#1c6048; font-size:.86rem; line-height:1.75; }
.toc-indent { padding-left:1.35rem; }

.report-table { width:100%; border-collapse:collapse; margin:.55rem 0 1.2rem; font-size:.78rem; table-layout:fixed; }
.report-table th, .report-table td { border-bottom:1px solid #e2e7e4; padding:.68rem .65rem; text-align:left; vertical-align:top; word-break:break-word; }
.report-table th { width:29%; color:#1d332b; background:#f3f6f4; font-weight:700; }
.report-table thead th { width:auto; color:#213a31; background:#f0f5f2; }
.severity { display:inline-block; border-radius:4px; padding:.18rem .5rem; font-size:.68rem; font-weight:800; }
.severity-high, .severity-critical { color:#b72f39; background:#fde7e8; }
.severity-medium { color:#95610e; background:#fff0cf; }
.severity-low { color:#2f6598; background:#e8f2fb; }
.severity-info, .severity-unknown { color:#5e6b65; background:#edf1ef; }
.source-pill { display:inline-block; color:#27664d; background:#e9f5ee; border-radius:4px; padding:.18rem .5rem; font-size:.68rem; font-weight:700; }

.detail-block { border-top:1px solid var(--line); padding:1.65rem 0 .7rem; }
.detail-title { color:var(--ink); font-size:1.05rem; font-weight:800; margin-bottom:.9rem; }
.detail-label { color:#245b47; font-size:.78rem; font-weight:800; margin:1.05rem 0 .35rem; }
.detail-text { color:#20382f; font-size:.84rem; line-height:1.82; }
.recommendation { display:flex; gap:.8rem; border-top:1px solid #e2e7e4; padding:.85rem 0; }
.recommendation:first-child { border-top:0; }
.rec-number { flex:0 0 auto; color:#fff; background:var(--green); width:24px; height:24px; display:grid; place-items:center; border-radius:3px; font-size:.65rem; font-weight:800; }
.rec-text { color:#263d34; font-size:.82rem; line-height:1.65; }

[data-testid="stExpander"] { border-color:var(--line) !important; border-radius:7px !important; margin:.55rem 0; }
[data-testid="stExpander"] summary { font-size:.8rem; color:#243c33; }
.stButton > button, .stDownloadButton > button {
    min-height:2.45rem; color:#fff; background:var(--green); border:1px solid var(--green); border-radius:6px;
}
.stButton > button:hover, .stDownloadButton > button:hover { color:#fff; background:#217744; border-color:#217744; }
[data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:7px; overflow:hidden; }

@media (max-width:760px) {
    .block-container { padding:2.3rem 1rem 4rem; }
    .brand-name { font-size:2rem; }
    .metrics { grid-template-columns:1fr 1fr; }
    .report-table { font-size:.72rem; }
}
</style>
"""


def render(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def safe(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def read_json(path: Path) -> tuple[Any, datetime]:
    with path.expanduser().open("r", encoding="utf-8-sig") as file:
        payload = json.load(file)
    return payload, datetime.fromtimestamp(path.stat().st_mtime)


def extract_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("detections", "findings", "results", "items", "data"):
            if isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
        if "attack_type" in payload:
            return [payload]
    raise ValueError("JSON에서 탐지 결과 목록을 찾지 못했습니다.")


def probability_severity(probability: float) -> str:
    if probability >= .9:
        return "HIGH"
    if probability >= .7:
        return "MEDIUM"
    return "LOW" if probability > 0 else "INFO"


def guidance(attack_type: str) -> tuple[str, list[str]]:
    name = attack_type.lower()
    if "dos" in name or "denial" in name:
        return (
            "서비스 자원 고갈, 응답 지연 또는 가용성 저하로 이어질 수 있습니다. 실제 장애 발생 여부는 서버 지표와 함께 확인해야 합니다.",
            [
                "동일 출발지의 반복 요청과 트래픽 증가 시점을 확인하세요.",
                "요청 속도 제한, 연결 제한 및 방화벽 정책을 점검하세요.",
                "CPU·메모리·네트워크 사용량과 응답 시간을 함께 관찰하세요.",
            ],
        )
    if "brute" in name:
        return (
            "반복 인증 시도가 성공하면 계정 무단 접근과 정보 노출로 이어질 수 있습니다.",
            [
                "로그인 실패 횟수 제한과 계정 잠금 정책을 적용하세요.",
                "다단계 인증과 비정상 로그인 탐지를 적용하세요.",
                "반복 시도의 출발지와 대상 계정을 확인하세요.",
            ],
        )
    return (
        "비정상 네트워크 패턴이 서비스 성능이나 보안에 영향을 줄 수 있습니다.",
        [
            "탐지 시점의 서버와 네트워크 로그를 함께 확인하세요.",
            "동일한 패턴이 반복되는지 모니터링하세요.",
            "필요하면 방화벽과 접근 제어 정책을 점검하세요.",
        ],
    )


def normalize_web(payload: Any) -> list[dict[str, Any]]:
    records = []
    for index, item in enumerate(extract_items(payload)):
        recommendations = item.get("recommendation", [])
        recommendations = [recommendations] if isinstance(recommendations, str) else recommendations
        records.append({
            "id": index,
            "source": str(item.get("source", "WEB")).upper(),
            "timestamp": item.get("timestamp"),
            "last_detected_at": item.get("last_detected_at"),
            "attack_type": str(item.get("attack_type", "미분류 공격")),
            "severity": str(item.get("severity", "UNKNOWN")).upper(),
            "summary": str(item.get("summary") or "요약 정보가 없습니다."),
            "evidence": str(item.get("evidence") or "탐지 근거가 없습니다."),
            "impact": str(item.get("impact") or "영향 정보가 없습니다."),
            "recommendation": [str(value) for value in recommendations or []],
            "method": str(item.get("method") or "").upper(),
            "url_path": str(item.get("url_path") or ""),
            "status_code": item.get("status_code", ""),
            "source_file": str(item.get("source_file") or ""),
            "attack_probability": float(item.get("attack_probability") or 0),
            "flow_count": item.get("flow_count"),
            "detected_flow_count": item.get("detected_flow_count"),
            "class_probabilities": item.get("class_probabilities") or {},
            "class_counts": item.get("class_counts") or {},
            "prediction_csv": str(item.get("prediction_csv") or ""),
        })
    return records


def normalize_network(payload: Any) -> list[dict[str, Any]]:
    if not (isinstance(payload, dict) and "detected_types" in payload and "attack_type" not in payload):
        return normalize_web(payload)
    detected_types = payload.get("detected_types") or ["의심 패턴 없음"]
    detected_types = [detected_types] if isinstance(detected_types, str) else detected_types
    evidence_items = payload.get("evidence") if isinstance(payload.get("evidence"), list) else []
    records = []
    for index, attack_type in enumerate(map(str, detected_types)):
        evidence = next((item for item in evidence_items if isinstance(item, dict) and str(item.get("attack_type")) == attack_type), {})
        probability = float(evidence.get("attack_probability", payload.get("attack_probability", 0)) or 0)
        total = int(evidence.get("total_flow_count", payload.get("flow_count", 0)) or 0)
        detected = int(evidence.get("detected_flow_count", total) or 0)
        impact, recommendations = guidance(attack_type)
        records.append({
            "id": index,
            "source": "NETWORK",
            "timestamp": payload.get("timestamp"),
            "last_detected_at": payload.get("last_detected_at"),
            "attack_type": attack_type,
            "severity": probability_severity(probability),
            "summary": f"전체 {total:,}개 Flow 중 {detected:,}개가 {attack_type} 유형으로 분류되었으며 모델 확률은 {probability * 100:.2f}%입니다.",
            "evidence": f"분석 파일 {payload.get('source_file', '-')} · 탐지 Flow {detected:,}/{total:,} · 분류 확률 {probability * 100:.2f}%",
            "impact": impact,
            "recommendation": recommendations,
            "method": "",
            "url_path": "",
            "status_code": "",
            "source_file": str(payload.get("source_file") or ""),
            "attack_probability": probability,
            "flow_count": total,
            "detected_flow_count": detected,
            "class_probabilities": payload.get("class_probabilities") or {},
            "class_counts": payload.get("class_counts") or {},
            "prediction_csv": str(payload.get("prediction_csv") or ""),
        })
    return records


def parse_time(value: Any) -> pd.Timestamp:
    return pd.to_datetime(value, utc=True, errors="coerce")


def format_kst(value: Any) -> str:
    parsed = parse_time(value)
    return "-" if pd.isna(parsed) else parsed.tz_convert("Asia/Seoul").strftime("%Y-%m-%d %H:%M:%S KST")


def highest_severity(records: list[dict[str, Any]]) -> str:
    levels = {item["severity"] for item in records}
    return next((level for level in SEVERITY_ORDER if level in levels), "UNKNOWN")


def severity_badge(level: str) -> str:
    name = level.lower()
    return f'<span class="severity severity-{safe(name)}">{safe(level)}</span>'


def html_table(rows: list[tuple[Any, Any]]) -> str:
    body = "".join(f"<tr><th>{safe(label)}</th><td>{safe(value)}</td></tr>" for label, value in rows)
    return f'<table class="report-table"><tbody>{body}</tbody></table>'


def brand(title: str, description: str = "") -> None:
    render(f"""
    <div class="brand">
        <div class="brand-name">ROOKIES Scanner</div>
        <div class="brand-copy">LMS Security Assessment Platform</div>
    </div>
    <div class="page-title">{safe(title)}</div>
    {f'<div class="page-copy">{safe(description)}</div>' if description else ''}
    """)


def metrics(items: list[tuple[str, Any]]) -> None:
    cards = "".join(f'<div class="metric"><div class="metric-label">{safe(label)}</div><div class="metric-value">{safe(value)}</div></div>' for label, value in items)
    render(f'<div class="metrics">{cards}</div>')


def detail(item: dict[str, Any], number: int) -> None:
    target = item["url_path"] or item["source_file"] or "-"
    rows = [
        ("Source", item["source"]),
        ("대상", target),
        ("HTTP Method", item["method"] or "-"),
        ("상태 코드", item["status_code"] or "-"),
        ("최초 탐지", format_kst(item["timestamp"])),
        ("마지막 탐지", format_kst(item["last_detected_at"])),
    ]
    if item["attack_probability"]:
        rows.append(("공격 확률", f'{item["attack_probability"] * 100:.2f}%'))
    recommendations = "".join(
        f'<div class="recommendation"><div class="rec-number">{index:02d}</div><div class="rec-text">{safe(value)}</div></div>'
        for index, value in enumerate(item["recommendation"], 1)
    )
    render(f"""
    <div class="detail-block">
        <div class="detail-title">3.{number} {safe(item['attack_type'])} · {safe(target)}</div>
        <div><strong>위험도</strong>&nbsp;&nbsp;{severity_badge(item['severity'])}</div>
        {html_table(rows)}
        <div class="detail-label">① 분석 요약</div><div class="detail-text">{safe(item['summary'])}</div>
        <div class="detail-label">② 탐지 근거</div><div class="detail-text">{safe(item['evidence'])}</div>
        <div class="detail-label">③ 예상 영향</div><div class="detail-text">{safe(item['impact'])}</div>
        <div class="detail-label">④ 대응 권고</div>{recommendations or '<div class="detail-text">제공된 권고사항이 없습니다.</div>'}
    </div>
    """)


def detection_table(records: list[dict[str, Any]]) -> None:
    rows = [{
        "공격 유형": item["attack_type"],
        "Source": item["source"],
        "대상": item["url_path"] or item["source_file"] or "-",
        "Method": item["method"] or "-",
        "위험도": item["severity"],
        "탐지 시각": format_kst(item["timestamp"]),
    } for item in records]
    st.dataframe(rows, width="stretch", hide_index=True)


def page_dashboard(web: list[dict[str, Any]], network: list[dict[str, Any]]) -> None:
    all_records = web + network
    brand("통합 Dashboard", "웹 로그와 네트워크 ML 분석 결과를 한 화면에서 확인합니다.")
    completion = 100 if web and network else 50 if all_records else 0
    render(f'<div class="progress-copy">데이터 연결 · {int(bool(web)) + int(bool(network))}/2 · {completion}%</div><div class="progress-track"><div class="progress-value" style="width:{completion}%"></div></div>')
    metrics([
        ("전체 탐지", len(all_records)),
        ("웹 탐지", len(web)),
        ("네트워크 탐지", len(network)),
        ("공격 유형", len({item["attack_type"] for item in all_records})),
        ("최고 위험도", SEVERITY_KO.get(highest_severity(all_records), "-")),
    ])
    render('<div class="section"><div class="section-title">최근 탐지 결과</div></div>')
    detection_table(sorted(all_records, key=lambda item: parse_time(item["timestamp"]).value if not pd.isna(parse_time(item["timestamp"])) else 0, reverse=True))


def page_source(records: list[dict[str, Any]], source: str, modified: datetime | None) -> None:
    source_name = "웹 공격 진단" if source == "WEB" else "네트워크 공격 진단"
    description = "Burp Suite 로그 기반 공격 분석 결과입니다." if source == "WEB" else "PCAP 및 ML 분류 기반 네트워크 분석 결과입니다."
    brand(source_name, description)
    counts = Counter(item["attack_type"] for item in records)
    metrics([
        ("전체 탐지", len(records)),
        ("공격 유형", len(counts)),
        ("최고 위험도", SEVERITY_KO.get(highest_severity(records), "-")),
        ("데이터 갱신", modified.strftime("%H:%M:%S") if modified else "-"),
    ])
    render('<div class="section"><div class="section-title">진단 결과</div></div>')
    detection_table(records)
    render('<div class="section"><div class="section-title">상세 탐지 내역</div></div>')
    for index, item in enumerate(records, 1):
        title = f'{item["attack_type"]} · {item["url_path"] or item["source_file"] or "-"} · {item["severity"]}'
        with st.expander(title):
            detail(item, index)


def page_report(web: list[dict[str, Any]], network: list[dict[str, Any]], generated_at: datetime) -> None:
    records = web + network
    source_counts = Counter(item["source"] for item in records)
    types = Counter(item["attack_type"] for item in records)
    render("""
    <div class="eyebrow">ROOKIES Scanner</div>
    <div class="report-title">AI 기반 LMS 보안 분석 리포트</div>
    <div class="report-subtitle">Integrated Web &amp; Network Security Analysis Report</div>
    <div class="green-rule"></div>
    """)
    render(html_table([
        ("진단 유형", "웹 로그 · 네트워크 트래픽 통합 분석"),
        ("웹 Source", WEB_REPORT_PATH.name),
        ("네트워크 Source", NETWORK_REPORT_PATH.name),
        ("웹 탐지 건수", source_counts.get("WEB", 0)),
        ("네트워크 탐지 건수", source_counts.get("NETWORK", 0)),
        ("보고서 생성", generated_at.strftime("%Y-%m-%d %H:%M:%S KST")),
    ]))
    toc_items = "".join(
        f'<div class="toc-indent">3.{index} {safe(item["attack_type"])} · {safe(item["url_path"] or item["source_file"] or "-")}</div>'
        for index, item in enumerate(records, 1)
    )
    render(f"""
    <div class="section"><div class="section-title">목차</div>
        <div class="toc">1. 진단 개요<br>2. 진단 결과 요약<br>3. 상세 진단 결과{toc_items}4. 종합 분석<br>5. 종합 대응 권고</div>
    </div>
    <div class="section"><div class="section-title">1. 진단 개요</div>
        <div class="body-text">본 보고서는 Burp Suite에서 수집한 웹 요청과 네트워크 트래픽 ML 분석 결과를 대상으로 작성되었습니다. 탐지 결과는 공격 패턴 또는 의심 행위를 의미하며 실제 공격 성공 여부는 관련 서버 로그와 시스템 상태를 함께 확인해야 합니다.</div>
    </div>
    <div class="section"><div class="section-title">2. 진단 결과 요약</div></div>
    """)
    metrics([
        ("총 진단 항목", len(records)),
        ("웹 탐지", len(web)),
        ("네트워크 탐지", len(network)),
        ("공격 유형", len(types)),
        ("최고 위험도", SEVERITY_KO.get(highest_severity(records), "-")),
    ])
    render('<div class="section"><div class="section-title">3. 상세 진단 결과</div></div>')
    for index, item in enumerate(records, 1):
        detail(item, index)
    render(f"""
    <div class="section"><div class="section-title">4. 종합 분석</div>
        <div class="body-text">현재 입력된 결과에서는 웹 공격 {len(web)}건과 네트워크 공격 {len(network)}건이 확인되었습니다. 주요 유형은 {safe(', '.join(types.keys()) or '없음')}입니다. 각 탐지는 입력 패턴 또는 분류 모델 결과에 기반하므로 서버·인증·데이터베이스·네트워크 장비 기록과 교차 확인해야 합니다.</div>
    </div>
    <div class="section"><div class="section-title">5. 종합 대응 권고</div></div>
    """)
    unique_recommendations = list(dict.fromkeys(value for item in records for value in item["recommendation"]))
    recommendations = "".join(f'<div class="recommendation"><div class="rec-number">{index:02d}</div><div class="rec-text">{safe(value)}</div></div>' for index, value in enumerate(unique_recommendations, 1))
    render(recommendations or '<div class="body-text">제공된 권고사항이 없습니다.</div>')


def page_history(records: list[dict[str, Any]]) -> None:
    brand("진단 이력", "현재 JSON에 저장된 탐지 기록을 시간순으로 확인합니다.")
    detection_table(sorted(records, key=lambda item: parse_time(item["timestamp"]).value if not pd.isna(parse_time(item["timestamp"])) else 0, reverse=True))


def load_records(path: Path, source: str) -> tuple[list[dict[str, Any]], datetime | None, str | None]:
    try:
        payload, modified = read_json(path)
        records = normalize_web(payload) if source == "WEB" else normalize_network(payload)
        if source == "WEB":
            web_only = [item for item in records if item["source"] == "WEB"]
            records = web_only or records
        return records, modified, None
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        return [], None, f"{path}: {error}"


st.markdown(CSS, unsafe_allow_html=True)
with st.sidebar:
    render('<div class="side-title">메뉴</div>')
    page = st.radio(
        "메뉴",
        ["통합 Dashboard", "웹 공격 진단", "네트워크 공격 진단", "AI 분석 리포트", "진단 이력"],
        label_visibility="collapsed",
    )
    render('<div class="side-note">Burp Suite 로그 · 네트워크 ML 분석<br>허가된 실습 환경 전용</div>')

web_records, web_modified, web_error = load_records(WEB_REPORT_PATH, "WEB")
network_records, network_modified, network_error = load_records(NETWORK_REPORT_PATH, "NETWORK")

if web_error:
    st.warning(f"웹 보고서를 불러오지 못했습니다: {web_error}")
if network_error:
    st.warning(f"네트워크 보고서를 불러오지 못했습니다: {network_error}")
if not web_records and not network_records:
    st.error("표시할 분석 결과가 없습니다. JSON 파일 경로를 확인해 주세요.")
    st.stop()

if page == "통합 Dashboard":
    page_dashboard(web_records, network_records)
elif page == "웹 공격 진단":
    page_source(web_records, "WEB", web_modified)
elif page == "네트워크 공격 진단":
    page_source(network_records, "NETWORK", network_modified)
elif page == "AI 분석 리포트":
    page_report(web_records, network_records, datetime.now().astimezone())
else:
    page_history(web_records + network_records)