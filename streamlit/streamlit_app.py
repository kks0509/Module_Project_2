from __future__ import annotations

import html
import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st


APP_DIR = Path(__file__).resolve().parent
REPORT_PATH = Path(os.getenv("REPORT_JSON_PATH", APP_DIR / "report_result.json"))

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
SEVERITY_LABEL = {
    "CRITICAL": "치명적",
    "HIGH": "높음",
    "MEDIUM": "중간",
    "LOW": "낮음",
    "INFO": "정보",
    "UNKNOWN": "미분류",
}
SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH": "#f97316",
    "MEDIUM": "#f59e0b",
    "LOW": "#0ea5e9",
    "INFO": "#64748b",
    "UNKNOWN": "#94a3b8",
}
ATTACK_COLORS = ["#2563eb", "#7c3aed", "#14b8a6", "#f59e0b", "#ef4444"]


st.set_page_config(
    page_title="보안 탐지 대시보드",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;600;700;800&display=swap');

        :root {
            --primary: #2563eb;
            --background: #f5f7fb;
            --card: #ffffff;
            --text: #172033;
            --muted: #718096;
            --line: #e5eaf1;
        }
        html, body, [class*="css"] { font-family: 'Noto Sans KR', sans-serif; }
        .stApp { background: var(--background); color: var(--text); }
        #MainMenu,
        [data-testid="stDecoration"],
        [data-testid="stStatusWidget"],
        footer { display: none !important; }
        [data-testid="stToolbar"] {
            display: flex !important;
            background: transparent !important;
        }
        [data-testid="stToolbar"] [data-testid="stBaseButton-header"],
        [data-testid="stToolbar"] [data-testid="stMainMenuButton"] {
            display: none !important;
        }
        [data-testid="stHeader"] { height: 0; background: transparent; }
        .block-container { max-width: 1380px; padding: 2rem 2.2rem 4rem; }

        /* 파란색 관리자 메뉴 */
        [data-testid="stSidebar"] {
            background: #234f91;
            border-right: 0;
        }
        [data-testid="stSidebar"] > div:first-child { padding-top: 1rem; }
        [data-testid="stSidebar"] * { color: #ffffff; }
        [data-testid="stSidebarUserContent"] { transform: translateY(-48px); }
        [data-testid="stSidebarCollapseButton"],
        [data-testid="stSidebarCollapsedControl"],
        [data-testid="stExpandSidebarButton"] {
            display: block !important;
            visibility: visible !important;
            opacity: 1 !important;
            position: fixed !important;
            top: .75rem !important;
            left: .75rem !important;
            z-index: 999999 !important;
        }
        [data-testid="stSidebarCollapseButton"] button,
        [data-testid="stSidebarCollapsedControl"] button,
        [data-testid="stExpandSidebarButton"] {
            width: 40px !important;
            height: 40px !important;
            visibility: visible !important;
            opacity: 1 !important;
            color: #ffffff !important;
            background: #234f91 !important;
            border: 1px solid rgba(255,255,255,.3) !important;
            border-radius: 6px !important;
            box-shadow: 0 2px 7px rgba(15,23,42,.16) !important;
        }
        [data-testid="stSidebarCollapseButton"] button svg,
        [data-testid="stSidebarCollapseButton"] button span,
        [data-testid="stSidebarCollapsedControl"] button svg,
        [data-testid="stExpandSidebarButton"] span { display: none !important; }
        [data-testid="stSidebarCollapseButton"] button::after,
        [data-testid="stSidebarCollapsedControl"] button::after,
        [data-testid="stExpandSidebarButton"]::after {
            content: '☰';
            color: #ffffff;
            font-size: 1.25rem;
            line-height: 1;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: .72rem;
            padding: .55rem .25rem 1.5rem;
            margin-bottom: .5rem;
            border-bottom: 1px solid rgba(255,255,255,.2);
        }
        .brand-mark {
            display: grid;
            place-items: center;
            width: 38px;
            height: 38px;
            border-radius: 6px;
            background: #ffffff;
            color: #234f91 !important;
            border: 0;
            font-weight: 800;
        }
        .brand-name { font-size: 1rem; font-weight: 800; }
        .brand-sub { font-size: .66rem; opacity: .72; margin-top: .08rem; }
        .source-card {
            margin: 1rem 0 .8rem;
            padding: .9rem;
            border-radius: 6px;
            background: rgba(12, 35, 112, .18);
            border: 1px solid rgba(255,255,255,.16);
        }
        .source-label { font-size: .64rem; opacity: .65; margin-bottom: .3rem; }
        .source-value { font-size: .76rem; font-weight: 700; word-break: break-all; }
        .source-status { font-size: .67rem; opacity: .75; margin-top: .5rem; }
        .status-dot {
            display: inline-block;
            width: 7px;
            height: 7px;
            margin-right: .35rem;
            border-radius: 50%;
            background: #6ee7b7;
            box-shadow: none;
        }
        [data-testid="stSidebar"] .stButton > button {
            width: 100%;
            min-height: 2.55rem;
            color: #ffffff;
            background: rgba(255,255,255,.12);
            border: 1px solid rgba(255,255,255,.25);
            border-radius: 6px;
            font-weight: 700;
        }
        [data-testid="stSidebar"] .stButton > button:hover {
            color: #ffffff;
            background: rgba(255,255,255,.2);
            border-color: rgba(255,255,255,.5);
        }

        /* 제목 */
        .page-title {
            color: var(--text);
            font-size: clamp(1.65rem, 3vw, 2.25rem);
            line-height: 1.2;
            letter-spacing: -.04em;
            font-weight: 800;
            margin: 0;
        }
        .page-copy { color: var(--muted); font-size: .85rem; margin-top: .55rem; }
        .update-chip {
            display: inline-block;
            float: right;
            color: #526076;
            background: #ffffff;
            border: 1px solid var(--line);
            border-radius: 6px;
            padding: .58rem .7rem;
            font-size: .72rem;
            box-shadow: none;
            margin-top: .6rem;
        }

        /* 상단 요약 카드 */
        .stats-grid-spacer { height: .55rem; }
        .stat-card {
            position: relative;
            overflow: hidden;
            min-height: 112px;
            background: var(--card);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 1rem 1.05rem .9rem;
            box-shadow: 0 2px 8px rgba(31, 51, 89, .04);
        }
        .stat-card::before {
            content: '';
            position: absolute;
            inset: 0 0 auto 0;
            width: 100%;
            height: 3px;
            background: var(--accent);
        }
        .stat-top { display: block; }
        .stat-label { color: #748096; font-size: .74rem; font-weight: 600; }
        .stat-value {
            color: var(--text);
            font-size: 1.75rem;
            font-weight: 800;
            letter-spacing: -.04em;
            margin: .5rem 0 .15rem;
        }
        .stat-foot { color: #9aa6b7; font-size: .67rem; }

        .section-anchor { scroll-margin-top: 3rem; }
        .section-head {
            display: flex;
            justify-content: space-between;
            align-items: end;
            margin: 1.65rem 0 .8rem;
        }
        .section-title { color: var(--text); font-size: 1.05rem; font-weight: 800; letter-spacing: -.02em; }
        .section-sub { color: var(--muted); font-size: .74rem; margin-top: .22rem; }
        /* 그래프와 표 */
        .stPlotlyChart,
        [data-testid="stDataFrame"] {
            overflow: hidden;
            background: #ffffff;
            border: 1px solid var(--line);
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(31, 51, 89, .04);
        }

        /* 선택 이벤트 상세 */
        .finding-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            background: #ffffff;
            border: 1px solid var(--line);
            border-left: 4px solid #2563eb;
            border-radius: 8px;
            padding: 1.1rem 1.2rem;
            color: var(--text);
            box-shadow: 0 2px 8px rgba(31, 51, 89, .04);
            margin-bottom: .85rem;
        }
        .finding-title { font-size: 1rem; font-weight: 800; }
        .finding-route { color: #718096; font-size: .7rem; margin-top: .3rem; }
        .severity-pill {
            flex: 0 0 auto;
            color: #9a6700;
            background: #fff7dc;
            border: 1px solid #f7d46b;
            border-radius: 4px;
            padding: .4rem .68rem;
            font-size: .67rem;
            font-weight: 800;
        }
        .info-card {
            height: 100%;
            min-height: 155px;
            background: #ffffff;
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 1rem 1.05rem;
            box-shadow: 0 2px 8px rgba(31, 51, 89, .04);
        }
        .info-label {
            color: var(--primary);
            font-size: .66rem;
            font-weight: 800;
            letter-spacing: .06em;
            margin-bottom: .5rem;
        }
        .info-body { color: #4a5568; font-size: .8rem; line-height: 1.75; }
        .detail-block {
            background: #ffffff;
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 1rem 1.05rem;
            box-shadow: 0 2px 8px rgba(31, 51, 89, .04);
            margin-top: .8rem;
        }
        .detail-block-title { color: var(--text); font-size: .82rem; font-weight: 800; margin-bottom: .65rem; }
        .evidence-box {
            color: #334155;
            background: #f6f8fc;
            border-left: 3px solid var(--primary);
            border-radius: 4px;
            padding: .78rem .85rem;
            font-size: .76rem;
            line-height: 1.7;
        }
        .recommendation {
            display: flex;
            align-items: flex-start;
            gap: .72rem;
            padding: .72rem 0;
            border-bottom: 1px solid #edf0f5;
            color: #4a5568;
            font-size: .78rem;
            line-height: 1.65;
        }
        .recommendation:last-child { border-bottom: 0; }
        .rec-number {
            flex: 0 0 auto;
            display: grid;
            place-items: center;
            width: 23px;
            height: 23px;
            color: var(--primary);
            background: #eaf0ff;
            border-radius: 4px;
            font-size: .65rem;
            font-weight: 800;
        }
        .footer-note { color: #98a4b5; font-size: .67rem; text-align: center; margin-top: 2rem; }

        @media (max-width: 800px) {
            .block-container { padding: 1.35rem .9rem 3rem; }
            .update-chip { float: none; margin-top: .8rem; }
            .finding-head { align-items: flex-start; flex-direction: column; }
            .stat-card { min-height: 110px; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def safe(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def normalize_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        items = None
        for key in ("detections", "findings", "results", "items", "data"):
            if isinstance(payload.get(key), list):
                items = payload[key]
                break
        if items is None and "attack_type" in payload:
            items = [payload]
        if items is None:
            raise ValueError("JSON에서 탐지 목록을 찾지 못했습니다.")
    else:
        raise ValueError("JSON 최상위 값은 배열 또는 객체여야 합니다.")

    records: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        row = dict(item)
        row["_source_index"] = index
        row["severity"] = str(row.get("severity", "UNKNOWN")).upper()
        row["attack_type"] = str(row.get("attack_type", "미분류 공격"))
        row["method"] = str(row.get("method", "-")).upper()
        row["url_path"] = str(row.get("url_path", "-"))
        row["status_code"] = row.get("status_code", "-")
        row["summary"] = str(row.get("summary", "요약 정보가 없습니다."))
        row["evidence"] = str(row.get("evidence", "탐지 근거가 없습니다."))
        row["impact"] = str(row.get("impact", "영향 정보가 없습니다."))
        recommendations = row.get("recommendation", [])
        if isinstance(recommendations, str):
            recommendations = [recommendations]
        if not isinstance(recommendations, list):
            recommendations = []
        row["recommendation"] = [str(text) for text in recommendations]
        records.append(row)

    if not records:
        raise ValueError("표시할 탐지 항목이 없습니다.")
    return records


def read_report(path: Path) -> tuple[Any, datetime]:
    resolved = path.expanduser()
    if not resolved.is_absolute():
        resolved = (APP_DIR / resolved).resolve()
    with resolved.open("r", encoding="utf-8-sig") as file:
        payload = json.load(file)
    return payload, datetime.fromtimestamp(resolved.stat().st_mtime)


def parse_timestamp(value: Any) -> pd.Timestamp:
    return pd.to_datetime(value, utc=True, errors="coerce")


def format_kst(value: Any, short: bool = False) -> str:
    parsed = parse_timestamp(value)
    if pd.isna(parsed):
        return str(value or "-")
    converted = parsed.tz_convert("Asia/Seoul")
    return converted.strftime("%m-%d %H:%M" if short else "%Y-%m-%d %H:%M:%S KST")


def sort_value(item: dict[str, Any]) -> int:
    parsed = parse_timestamp(item.get("timestamp"))
    return -1 if pd.isna(parsed) else parsed.value


def section_header(anchor: str, title: str, subtitle: str) -> None:
    st.markdown(
        f"""
        <div id="{safe(anchor)}" class="section-anchor"></div>
        <div class="section-head">
            <div>
                <div class="section-title">{safe(title)}</div>
                <div class="section-sub">{safe(subtitle)}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def stat_card(label: str, value: str, foot: str, accent: str) -> None:
    st.markdown(
        f"""
        <div class="stat-card" style="--accent:{safe(accent)}">
            <div class="stat-top">
                <div class="stat-label">{safe(label)}</div>
            </div>
            <div class="stat-value">{safe(value)}</div>
            <div class="stat-foot">{safe(foot)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def chart_layout(title: str, height: int = 325) -> dict[str, Any]:
    return {
        "height": height,
        "margin": {"l": 38, "r": 30, "t": 62, "b": 42},
        "paper_bgcolor": "#ffffff",
        "plot_bgcolor": "#ffffff",
        "font": {"family": "Noto Sans KR", "color": "#718096", "size": 11},
        "title": {"text": title, "font": {"size": 14, "color": "#172033"}, "x": .06, "xanchor": "left"},
        "hoverlabel": {"bgcolor": "#172033", "bordercolor": "#172033", "font_color": "#ffffff"},
    }


def cumulative_chart(records: list[dict[str, Any]]) -> go.Figure:
    ordered = sorted(records, key=sort_value)
    x_values = [parse_timestamp(item.get("timestamp")).tz_convert("Asia/Seoul") for item in ordered]
    y_values = list(range(1, len(ordered) + 1))
    labels = [item["attack_type"] for item in ordered]
    figure = go.Figure(
        go.Scatter(
            x=x_values,
            y=y_values,
            mode="lines+markers",
            line={"color": "#2563eb", "width": 3, "shape": "spline"},
            marker={"size": 8, "color": "#ffffff", "line": {"color": "#2563eb", "width": 3}},
            fill="tozeroy",
            fillcolor="rgba(37,99,235,.08)",
            customdata=labels,
            hoverinfo="skip",
        )
    )
    figure.update_layout(**chart_layout("시간대별 누적 탐지"))
    figure.update_layout(hovermode=False, dragmode=False)
    figure.update_xaxes(showgrid=False, tickformat="%H:%M", title=None, linecolor="#e5eaf1", fixedrange=True)
    figure.update_yaxes(showgrid=True, gridcolor="#edf1f6", zeroline=False, dtick=1, rangemode="tozero", title="누적 건수", fixedrange=True)
    return figure


def attack_chart(records: list[dict[str, Any]]) -> go.Figure:
    counts = Counter(item["attack_type"] for item in records)
    figure = go.Figure(
        go.Bar(
            x=list(counts.values()),
            y=list(counts.keys()),
            orientation="h",
            marker={"color": ATTACK_COLORS[: len(counts)]},
            text=[f"{value}건" for value in counts.values()],
            textposition="inside",
            insidetextanchor="end",
            hoverinfo="skip",
        )
    )
    figure.update_layout(**chart_layout("공격 유형별 탐지"))
    figure.update_layout(
        showlegend=False,
        xaxis={"showgrid": True, "gridcolor": "#edf1f6", "dtick": 1, "title": "탐지 건수"},
        yaxis={"showgrid": False, "autorange": "reversed"},
        bargap=.5,
        hovermode=False,
        dragmode=False,
    )
    figure.update_xaxes(fixedrange=True)
    figure.update_yaxes(fixedrange=True)
    return figure


def render_detail(item: dict[str, Any]) -> None:
    severity = item["severity"]
    st.markdown(
        f"""
        <div class="finding-head">
            <div>
                <div class="finding-title">{safe(item['attack_type'])}</div>
                <div class="finding-route">{safe(item['method'])} {safe(item['url_path'])} · HTTP {safe(item['status_code'])} · {safe(format_kst(item.get('timestamp')))}</div>
            </div>
            <div class="severity-pill">{safe(SEVERITY_LABEL.get(severity, severity))} · {safe(severity)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    summary_column, impact_column = st.columns(2, gap="medium")
    with summary_column:
        st.markdown(
            f'<div class="info-card"><div class="info-label">분석 요약</div><div class="info-body">{safe(item["summary"])}</div></div>',
            unsafe_allow_html=True,
        )
    with impact_column:
        st.markdown(
            f'<div class="info-card"><div class="info-label">예상 영향</div><div class="info-body">{safe(item["impact"])}</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown(
        f'<div class="detail-block"><div class="detail-block-title">탐지 근거</div><div class="evidence-box">{safe(item["evidence"])}</div></div>',
        unsafe_allow_html=True,
    )

    recommendation_rows = "".join(
        f'<div class="recommendation"><div class="rec-number">{index}</div><div>{safe(text)}</div></div>'
        for index, text in enumerate(item.get("recommendation", []), start=1)
    )
    if not recommendation_rows:
        recommendation_rows = '<div class="recommendation">등록된 권고 조치가 없습니다.</div>'
    st.markdown(
        f'<div class="detail-block"><div class="detail-block-title">권고 조치</div>{recommendation_rows}</div>',
        unsafe_allow_html=True,
    )


inject_styles()

try:
    raw_payload, modified_at = read_report(REPORT_PATH)
    records = normalize_payload(raw_payload)
except FileNotFoundError:
    st.error(f"보고서 파일을 찾을 수 없습니다: {REPORT_PATH}")
    st.info("streamlit_app.py와 report_result.json을 같은 폴더에 두고 다시 실행해 주세요.")
    st.stop()
except (json.JSONDecodeError, UnicodeDecodeError) as error:
    st.error("report_result.json 형식이 올바르지 않습니다.")
    st.code(str(error), language=None)
    st.stop()
except (OSError, ValueError) as error:
    st.error("보고서를 불러오는 중 문제가 발생했습니다.")
    st.code(str(error), language=None)
    st.stop()

records_desc = sorted(records, key=sort_value, reverse=True)

with st.sidebar:
    st.markdown(
        """
        <div class="brand">
            <div class="brand-mark">W</div>
            <div><div class="brand-name">웹 보안 분석</div><div class="brand-sub">공격 탐지 보고서</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        f"""
        <div class="source-card">
            <div class="source-label">분석 파일</div>
            <div class="source-value">{safe(REPORT_PATH.name)}</div>
            <div class="source-status"><span class="status-dot"></span>정상 · 탐지 {len(records)}건</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

header_left, header_right = st.columns([3.8, 1.2])
with header_left:
    st.markdown(
        """
        <div id="overview" class="section-anchor"></div>
        <h1 class="page-title">웹 공격 탐지 현황</h1>
        <div class="page-copy">Burp Suite 요청 로그를 기준으로 탐지된 SQL 인젝션 및 XSS 시도를 정리했습니다.</div>
        """,
        unsafe_allow_html=True,
    )
with header_right:
    st.markdown(
        f'<div class="update-chip">기준 시각&nbsp; {safe(modified_at.strftime("%Y-%m-%d %H:%M"))}</div>',
        unsafe_allow_html=True,
    )

attack_counts = Counter(item["attack_type"] for item in records)
severity_counts = Counter(item["severity"] for item in records)
highest_severity = next((level for level in SEVERITY_ORDER if severity_counts.get(level)), "UNKNOWN")
sqli_count = sum(count for name, count in attack_counts.items() if "SQL" in name.upper())
xss_count = sum(count for name, count in attack_counts.items() if "XSS" in name.upper())

st.markdown('<div class="stats-grid-spacer"></div>', unsafe_allow_html=True)
stat_columns = st.columns(4, gap="medium")
with stat_columns[0]:
    stat_card("전체 탐지", f"{len(records)}건", "로그에서 확인된 요청", "#2563eb")
with stat_columns[1]:
    stat_card("SQL 인젝션", f"{sqli_count}건", "로그인 요청 탐지", "#7c3aed")
with stat_columns[2]:
    stat_card("XSS", f"{xss_count}건", "검색 요청 탐지", "#14b8a6")
with stat_columns[3]:
    stat_card(
        "최고 심각도",
        SEVERITY_LABEL.get(highest_severity, highest_severity),
        f"{highest_severity} · {severity_counts.get(highest_severity, 0)}건",
        SEVERITY_COLOR.get(highest_severity, "#94a3b8"),
    )

section_header("analytics", "탐지 추이", "발생 순서와 공격 유형별 건수를 표시합니다.")
chart_left, chart_right = st.columns([1.6, 1], gap="medium")
with chart_left:
    st.plotly_chart(
        cumulative_chart(records),
        width="stretch",
        config={"displayModeBar": False, "staticPlot": True, "scrollZoom": False},
    )
with chart_right:
    st.plotly_chart(
        attack_chart(records),
        width="stretch",
        config={"displayModeBar": False, "staticPlot": True, "scrollZoom": False},
    )

section_header(
    "detection-list",
    "탐지 내역",
    "행을 선택하면 아래 상세 내용이 변경됩니다.",
)
table_rows = [
    {
        "탐지 시각": format_kst(item.get("timestamp"), short=True),
        "공격 유형": item["attack_type"],
        "심각도": SEVERITY_LABEL.get(item["severity"], item["severity"]),
        "메서드": item["method"],
        "요청 경로": item["url_path"],
    }
    for item in records_desc
]
table_event = st.dataframe(
    pd.DataFrame(table_rows),
    width="stretch",
    height=min(42 + 35 * len(table_rows), 250),
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row",
    key="detection_table",
    column_config={
        "탐지 시각": st.column_config.TextColumn(width="small"),
        "공격 유형": st.column_config.TextColumn(width="medium"),
        "심각도": st.column_config.TextColumn(width="small"),
        "메서드": st.column_config.TextColumn(width="small"),
        "요청 경로": st.column_config.TextColumn(width="medium"),
    },
)
selected_rows = table_event.selection.rows
selected_index = selected_rows[0] if selected_rows else 0
selected_item = records_desc[selected_index]

section_header("finding-detail", "탐지 상세", "선택한 요청의 근거와 대응 내용을 확인합니다.")
render_detail(selected_item)

st.markdown(
    '<div class="footer-note">탐지 결과만으로 공격 성공 여부를 확정할 수 없습니다. 서버·인증 로그와 응답 내용을 함께 검증하세요.</div>',
    unsafe_allow_html=True,
)
