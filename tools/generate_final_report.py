#!/usr/bin/env python3
"""
generate_final_report.py — Confluence 게시용 최종 보안 진단 보고서 생성기

사용법:
    python3 tools/generate_final_report.py --run-id 20260506_2200 --repo ocb-webview-api
    python3 tools/generate_final_report.py --run-id 20260506_2200 --repo ocb-webview-api --publish
    python3 tools/generate_final_report.py --run-id 20260506_2200 --repo ocb-webview-api \
        --publish --parent 722832415 --title "OCB Webview API 보안 진단 결과"

입력:
    state/<repo>/<skill>/<RUN_ID>/findings_*.json  (llm_checked: true 파일만)
    testbed/<repo>/.clone_info.json                (레포 메타데이터)

출력:
    logs/final_<repo>_<RUN_ID>.md  (마크다운 — Confluence :::expand 매크로 포함)

섹션 구성:
    1. 진단 개요
    2. 취약점 요약 (조치 요약·파일:라인 포함)
    3. 취약점 상세 (스킬별 → 항목별 코드스니펫 + Taint Flow expand)
    4. 면책 사항
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

PALANTIR_DIR   = Path(__file__).resolve().parent.parent
STATE_DIR      = PALANTIR_DIR / "state"
LOGS_DIR       = PALANTIR_DIR / "logs"
TESTBED_DIR    = PALANTIR_DIR / "testbed"
DOCS_DIR       = PALANTIR_DIR / "docs"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_KR    = {
    "Critical":      "매우위험",
    "High":          "고위험",
    "Medium":        "중간위험",
    "Low":           "저위험",
    "Informational": "매우낮음",
}
SEV_GRADE = {
    "Critical":      5,
    "High":          4,
    "Medium":        3,
    "Low":           2,
    "Informational": 1,
}
_SEV_ALIAS = {"Info": "Informational", "info": "Informational"}

SKILL_LABEL = {
    "injection": "SQL/OS Command Injection",
    "xss":       "XSS",
    "file":      "파일 처리",
    "data":      "데이터 보호",
    "sca":       "SCA (오픈소스 CVE)",
}
# 2.2 요약표 · 3 취약점 상세 공통 정렬 순서 (depth1)
SKILL_ORDER = ["injection", "xss", "file", "data", "sca"]

DISCLAIMER = """본 보고서는 자동화 스크립트 및 LLM AI 에이전트를 통한 1차 분석 후, \
보안 진단 인력이 직접 검토한 결과입니다. \
분석 특성상 오탐(False Positive) 및 미탐(False Negative) 가능성이 일부 존재하므로, \
발견된 취약점은 소스코드 수정·패치 적용 등 조치 후 보안팀에 회신해 주시기 바랍니다. \
본 보고서에 포함된 소스코드 스니펫 및 취약점 정보는 내부 보안 목적으로만 사용되어야 합니다."""


# ── 유틸 ─────────────────────────────────────────────────────────────────────

_ACRONYMS = {"ocb", "skp", "api", "sdk", "ui", "sns", "sms", "mms", "id", "url", "html", "css", "js", "aos", "ios"}


def _repo_to_service_name(repo: str) -> str:
    parts = repo.split("-")
    result = []
    for p in parts:
        if p.lower() in _ACRONYMS:
            result.append(p.upper())
        else:
            result.append(p.capitalize())
    return " ".join(result)


def _norm_sev(sev: str) -> str:
    return _SEV_ALIAS.get(sev, sev)


def _sev_key(f: dict) -> int:
    sev = _norm_sev(f.get("severity", "Informational"))
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _esc(s: str) -> str:
    """마크다운 표 셀 내 파이프 이스케이프."""
    return str(s).replace("|", "｜")


_SEV_COLOR = {"Critical": "red", "High": "red", "Medium": "#FF8C00"}


def _sev_colored(sev: str) -> str:
    """위험도 숫자(1~5)만 표시. Critical/High=red, Medium=주황 색상 적용."""
    grade = SEV_GRADE.get(sev, "")
    label = f"**{grade}**" if grade else f"**{sev}**"
    color = _SEV_COLOR.get(sev)
    if color:
        return f"{{color:{color}}}{label}{{/color}}"
    return label


_NOMINAL_RE = [
    (re.compile(r'(?<=[가-힣])됨\.'), '됩니다.'),
    (re.compile(r'(?<=[가-힣])있음\.'), '있습니다.'),
    (re.compile(r'(?<=[가-힣])없음\.'), '없습니다.'),
    (re.compile(r'가능\.'), '가능합니다.'),
    (re.compile(r'필요\.'), '필요합니다.'),
    (re.compile(r'(?<=[가-힣])임\.'), '입니다.'),
    (re.compile(r'(?<=[가-힣])함\.'), '합니다.'),
    (re.compile(r'됨\.'), '됩니다.'),
    (re.compile(r'있음\.'), '있습니다.'),
    (re.compile(r'없음\.'), '없습니다.'),
    (re.compile(r'임\.'), '입니다.'),
    (re.compile(r'함\.'), '합니다.'),
]


def _normalize_desc(text: str) -> str:
    """명사형 어미(됨./있음. 등)를 서술형 구어체로 변환."""
    if not text:
        return text
    for pattern, replacement in _NOMINAL_RE:
        text = pattern.sub(replacement, text)
    return text


# SCA format 1: "SCA/CVE — {artifact} {ver} {vuln desc...}"
_SCA1_RE = re.compile(
    r'^SCA/CVE\s*[—\-–]\s*([\w.\-]+)\s+[\d.]+(?:\.Final|\.RELEASE)?\s+(.*)',
    re.IGNORECASE,
)
# SCA format 2: "[SCA] group:artifact {ver} — CVE-... ({desc})"
_SCA2_RE = re.compile(
    r'^\[SCA\]\s+(?:[\w.\-]+:)?([\w.\-]+)\s+[\d.]+(?:\.Final|\.RELEASE)?\s+—\s+'
    r'CVE-[\d-]+(?:\s*,\s*CVE-[\d-]+)*(?:\s+외\s+\d+건)?\s+\(([^)]+)\)',
    re.IGNORECASE,
)
_SEV_SUFFIX_RE = re.compile(
    r'\s*[—\-–]\s*(Critical|High|Medium|Low|Informational)\b.*$',
    re.IGNORECASE,
)
_COUNT_DASH_RE = re.compile(r'\s*[—\-–]\s*\d+[건개].*$')
_TRAILING_COUNT_RE = re.compile(r'\s+\d+[건개]\s*$')
_TRAILING_TECH_PAREN_RE = re.compile(
    r'\s*\((?:'
    r'[^)]*(?:\.kt|\.java|\.ts|\.js|\.py|Service|Controller|Util|Mapper|Repository|Manager|Handler|Config|StandardEval)[^)]*'  # class/file keywords
    r'|(?:[^)/]+/\s*){1,}[^)/]+'   # slash-separated list (endpoint names)
    r'|(?:[^)]+,\s*){2,}[^)]+'     # comma-separated list (3+ items)
    r')\)\s*$'
)
_TECH_DASH_RE = re.compile(
    r'\s*[—\-–]\s*[^—\-–]*(?:문자열\s*보간|StandardEvaluation|getOriginalFilename|\.kt\b|\.java\b)[^—\-–]*$'
)


def _clean_title(title: str) -> str:
    """제목 정규화: SCA 재포맷, verbose suffix 제거."""
    # SCA format 1: "SCA/CVE — artifact ver {vuln...}"
    m = _SCA1_RE.match(title)
    if m:
        artifact = m.group(1)
        rest = re.sub(r'\s*\[.*?\]\s*$', '', m.group(2)).strip()
        paren = re.search(r'\(([^)]+)\)\s*$', rest)
        if paren and not re.match(r'CVE-', paren.group(1).strip()):
            # Non-CVE paren = vuln description
            vuln = re.sub(r'\s*\d+건\s*$', '', paren.group(1)).strip()
        else:
            # CVE paren — vuln is text before the paren
            vuln = re.sub(r'\s*\(.*$', '', rest).strip()
            # Only strip 취약점 if it's the entire vuln text
            if re.fullmatch(r'취약점(?:\s+\d+건)?', vuln):
                return f"{artifact} CVE 취약점"
        return f"{artifact}에서 {vuln} 발생 가능성" if vuln else f"{artifact} CVE 취약점"
    # SCA format 2: "[SCA] group:artifact ver — CVE... ({desc})"
    m = _SCA2_RE.match(title)
    if m:
        artifact = m.group(1)
        vuln = re.sub(r'\s*\d+건\s*$', '', m.group(2)).strip()
        return f"{artifact}에서 {vuln} 발생 가능성" if vuln else f"{artifact} CVE 취약점"
    # General cleanup — apply _TECH_DASH_RE before paren removal so keywords are still present
    title = _SEV_SUFFIX_RE.sub('', title)
    title = _COUNT_DASH_RE.sub('', title)
    title = _TRAILING_COUNT_RE.sub('', title)
    title = _TECH_DASH_RE.sub('', title)
    title = _TRAILING_TECH_PAREN_RE.sub('', title)
    return title.strip()


# ── 데이터 수집 ───────────────────────────────────────────────────────────────

def load_clone_info(repo: str) -> dict:
    p = TESTBED_DIR / repo / ".clone_info.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


_EXPOSURE_ICON = {"대외": "🌐", "대내": "🔒", "대내외": "↔️"}

def load_service_exposure(repo: str) -> str:
    """docs/service_inventory.json에서 repo의 대외/대내/대내외 분류를 반환."""
    p = DOCS_DIR / "service_inventory.json"
    if not p.exists():
        return "—"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        for svc in data.get("services", []):
            if svc.get("repo") == repo:
                ko = svc.get("exposure_ko", "")
                icon = _EXPOSURE_ICON.get(ko, "")
                return f"{icon} {ko}".strip() if ko else "—"
    except Exception:
        pass
    return "—"


def collect_findings(run_id: str | None, repo: str) -> dict[str, list[dict]]:
    """
    run_id 지정 시: state/<repo>/<skill>/<run_id>/findings_*.json
    run_id=None 시: skill별 최신 RUN_ID 파일 하나씩 선택 (레포 단위 모드)
    llm_checked: true 파일만 읽어 { skill → [finding, ...] } 반환.
    """
    data: dict[str, list[dict]] = defaultdict(list)

    if run_id is not None:
        paths = sorted(STATE_DIR.glob(f"{repo}/*/{run_id}/findings_*.json"))
    else:
        # 레포 단위 모드 — skill별 최신 RUN_ID 선택
        paths = []
        repo_dir = STATE_DIR / repo
        for skill_dir in sorted(repo_dir.iterdir()):
            if not skill_dir.is_dir():
                continue
            candidates = sorted(skill_dir.glob("*/findings_*.json"), reverse=True)
            if candidates:
                paths.append(candidates[0])
                print(f"[최종보고서]   {skill_dir.name}: {candidates[0].parent.name}")

    for path in paths:
        skill = path.parts[-3]
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[WARN] 파싱 실패 {path}: {e}")
            continue

        if doc.get("llm_checked") is not True:
            continue

        for f in doc.get("findings", []):
            result = f.get("result", "취약")
            if result in ("취약", "정보"):
                data[skill].append(f)

    return data


# ── 위치 포매팅 ────────────────────────────────────────────────────────────────

_TESTBED_PREFIX_RE = re.compile(r'.*?testbed/[^/]+/(.*)')


def _to_relative_path(path: str) -> str:
    if not path:
        return path
    m = _TESTBED_PREFIX_RE.match(path)
    if m:
        return m.group(1)
    return path


def _location_cells(f: dict, omit_cve: bool = False) -> tuple[str, str, str]:
    """(endpoint, affected_file:line, handler) 3-tuple 반환."""
    raw   = f.get("scope") or {}
    scope = raw[0] if isinstance(raw, list) else raw

    ep      = scope.get("endpoint") or ""
    handler = scope.get("handler") or ""
    _ev     = f.get("evidence")
    _ev_d   = (_ev[0] if isinstance(_ev, list) and _ev else _ev) if _ev else {}
    if not isinstance(_ev_d, dict):
        _ev_d = {}
    af      = scope.get("affected_file") or _ev_d.get("file", "")
    line    = scope.get("affected_line") or _ev_d.get("lines", "")
    pkg     = scope.get("package") or ""

    if pkg:
        ver = scope.get("version", "")
        cve = scope.get("cve_id", "")
        af_str = f"{pkg} {ver}"
        if not omit_cve and cve:
            af_str += f" ({cve})"
        return ("—", af_str, "—")

    af = _to_relative_path(af)
    af_str = f"{af}:{line}" if af and line else af or "—"
    return (ep or "—", af_str, handler or "—")


# ── 마크다운 렌더링 ───────────────────────────────────────────────────────────

_CATEGORY_LABEL: dict[str, str] = {
    # XSS
    "PERSISTENT_XSS":       "Persistent XSS",
    "STORED_XSS":           "Stored XSS",
    "REFLECTED_XSS":        "Reflected XSS",
    "DOM_XSS":              "DOM XSS",
    "OPEN_REDIRECT":        "Open Redirect",
    # Injection
    "SQL_INJECTION":        "SQL Injection",
    "OS_COMMAND_INJECTION": "OS Command Injection",
    "COMMAND_INJECTION":    "Command Injection",
    "SSI_INJECTION":        "SSI Injection",
    "EXPRESSION_INJECTION": "Expression Injection",
    # File
    "FILE_UPLOAD":          "파일 업로드",
    "FILE_DOWNLOAD":        "파일 다운로드",
    "LFI":                  "Local File Inclusion",
    "RFI":                  "Remote File Inclusion",
    "PATH_TRAVERSAL":       "Path Traversal",
    # Data
    "DTO_EXPOSURE":         "PII 필드 노출",
    "CORS":                 "CORS 설정 점검",
    "SECRET_EXPOSURE":      "시크릿 노출",
    "JWT":                  "JWT 취약점",
    "CRYPTO_WEAK":          "취약 암호화",
    "SENSITIVE_LOGGING":    "민감정보 로그 노출",
    "INSECURE_RANDOM":      "취약 난수 생성",
}


def _check_item_label(skill: str, f: dict) -> str:
    """진단항목별 점검 세부 항목명 반환."""
    return _clean_title(f.get("title", "—"))[:50]


def _result_from_sev(sev: str) -> str:
    """위험도 → 보고서 결과 레이블 (Critical/High=취약, 그 외=정보)."""
    return "취약" if sev in ("Critical", "High") else "정보"


def _get_result(f: dict) -> str:
    """위험도 기반 결과 레이블 반환 — Section 2.2와 동일 로직 (Critical/High=취약, 그 외=정보)."""
    return _result_from_sev(_norm_sev(f.get("severity", "Informational")))


def _result_colored(result: str) -> str:
    """결과 레이블에 색상 마커 적용 (취약=빨강, 정보=주황)."""
    if result == "취약":
        return "{color:red}취약{/color}"
    if result == "정보":
        return "{color:#FF8C00}정보{/color}"
    return result


def _split_desc_threat(desc: str) -> tuple[str, str]:
    """설명 텍스트를 현황(첫 문장)과 보안위협(나머지)으로 분리.
    실제 문장 경계(마침표 뒤 공백)만 인식 — 버전번호/클래스명의 점은 무시."""
    m = re.search(r'(?<=\w)\.\s+', desc)
    if not m:
        return desc.strip(), ""
    hwang  = desc[:m.end()].strip()
    threat = desc[m.end():].strip()
    return hwang, threat


def _build_gemini_prompt_for_overview(
    repo: str,
    service_type: str,
    all_findings: list[tuple[str, dict]],
    global_counts: dict[str, int],
) -> str:
    """2.1 취약점 개요 섹션에 삽입할 Gemini용 프롬프트를 생성.

    findings 목록 (위험도별 정렬, 최대 20건)을 포함해
    LLM이 3~5문장 한국어 취약점 개요를 작성하도록 요청한다.
    """
    # 위험도별 건수 요약 문자열
    sev_parts = []
    for sev in SEVERITY_ORDER:
        cnt = global_counts.get(sev, 0)
        if cnt:
            kr = SEVERITY_KR.get(sev, sev)
            sev_parts.append(f"{kr}({sev}) {cnt}건")
    sev_summary = ", ".join(sev_parts) if sev_parts else "취약점 없음"

    # findings 정렬: 위험도 높은 순 → 취약 먼저
    def _sort_key(skill_f: tuple) -> tuple:
        _, f = skill_f
        return (_sev_key(f), 0 if _get_result(f) == "취약" else 1)

    sorted_findings = sorted(all_findings, key=_sort_key)
    display = sorted_findings[:20]

    p: list[str] = [
        "당신은 보안 전문가입니다. 아래 SAST(정적 분석) 진단 결과를 바탕으로",
        "취약점 개요 문단을 작성해주세요.",
        "",
        "## 진단 대상",
        f"- 레포: {repo}",
        f"- 서비스 유형: {service_type}",
        f"- 진단 방식: SAST (정적 분석) + LLM 교차검증",
        f"- 위험도별 현황: {sev_summary}",
        "",
        "## 발견된 취약점 목록",
        "",
    ]
    for i, (_, f) in enumerate(display, 1):
        sev    = _norm_sev(f.get("severity", "Informational"))
        title  = (f.get("title", "—") or "—").strip()
        cat    = f.get("category", "—")
        result = _get_result(f)
        raw    = f.get("description", "") or ""
        desc   = raw[:150].strip()
        if len(raw) > 150:
            desc += "…"
        p.append(f"{i}. [{sev}] {title}")
        p.append(f"   분류: {cat} | 결과: {result}")
        if desc:
            p.append(f"   설명: {desc}")
        p.append("")

    if len(sorted_findings) > 20:
        p.append(f"   ... 외 {len(sorted_findings) - 20}건 생략")
        p.append("")

    p += [
        "## 작성 요청",
        "",
        "위 취약점 목록을 기반으로 취약점 개요 문단을 작성해주세요.",
        "",
        "조건:",
        "1. 이번 진단에서 발견된 핵심 보안 위험 2~3가지를 중심으로 3~5문장으로 작성합니다.",
        "2. 대상 독자는 개발팀 리더 및 보안 담당자입니다.",
        "3. 기술적 세부사항보다 비즈니스 위험과 조치 우선순위 관점으로 기술합니다.",
        "4. 존댓말(합쇼체)을 사용합니다.",
        "5. 취약점이 없는 경우 '이번 진단에서 취약 항목이 발견되지 않았습니다.'로 시작합니다.",
        "",
        "출력 형식: 완성된 개요 문단만 출력합니다 (별도 설명이나 목록 없이 산문체).",
    ]
    return "\n".join(p)


def _recom_summary(recom: str) -> str:
    """recommendation에서 한 문장 요약 추출 — 문장 경계에서 자르고 중간 절단 없음.

    우선순위:
    1. 한글 또는 ')' 뒤 마침표(`.`) → 첫 문장 끝까지 반환 (영문 내부 `.Exclude` 등은 제외)
    2. 콜론(`:`) 끝 → 전체 라인 유지 (코드 예고 문장)
    3. 그 외 → 80자 초과 시 마지막 공백에서 절단 후 '…' 추가
    """
    for line in recom.splitlines():
        line = line.strip()
        if not line:
            continue
        # 선행 번호/기호 제거: "1. ", "- ", "• " 등
        line = re.sub(r'^[\d]+\.\s*', '', line)
        line = re.sub(r'^[-•]\s*', '', line)

        # 한국어 문장 경계: 한글 또는 ')' 뒤의 마침표 (영문 내부 '.Exclude' 등 제외)
        m = re.search(r'(?<=[가-힣\)])\.(?:\s|$)', line)
        if m:
            return line[:m.end()].rstrip()

        # 콜론 끝 (코드 블록 예고) — 전체 라인 유지
        if line.rstrip().endswith(':'):
            return line

        # 그 외: 80자 초과 시 마지막 공백에서 절단
        if len(line) > 80:
            idx = line.rfind(' ', 0, 80)
            if idx > 30:
                return line[:idx] + "…"
            return line[:80] + "…"

        return line
    return recom.strip()[:80]


def _recom_for_table_cell(recom: str) -> str:
    """recommendation 전체를 Confluence 마크다운 테이블 셀용으로 변환.
    줄바꿈은 <br>로 대체하고, 파이프(|)와 백슬래시는 이스케이프한다.
    """
    if not recom:
        return ""
    parts: list[str] = []
    for line in recom.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # 파이프와 백슬래시 이스케이프 (테이블 셀 안전)
        stripped = stripped.replace("\\", "\\\\").replace("|", "\\|")
        parts.append(stripped)
    return "<br>".join(parts)


def _recom_for_confluence(text: str) -> str:
    """Convert recommendation numbered lists to Confluence-safe Markdown.

    Confluence :::expand 블록 내 Markdown 렌더러는 번호 매기기 목록 항목 사이에
    펜스드 코드 블록(4-space-indented ```)이 오면 <ol>이 끊겨 다음 항목이 1부터
    재시작된다. 이를 방지하기 위해 연속 줄은 항상 인라인 백틱으로 처리한다:
    - Continuation ≤300 chars combined → inline backtick code appended to item text
    - Continuation >300 chars combined → 300자까지만 inline backtick + "..." 말줄임
    """
    if not re.search(r'^\d+\. ', text, re.MULTILINE):
        return text

    lines = text.split('\n')
    item_re = re.compile(r'^(\d+)\.\s+(.*)')
    cont_re = re.compile(r'^\s{2,}(.+)')
    result: list[str] = []
    i = 0

    while i < len(lines):
        line = lines[i]
        m = item_re.match(line)
        if m:
            num = m.group(1)
            text_part = m.group(2)
            cont_lines: list[str] = []
            j = i + 1
            while j < len(lines) and lines[j].strip():
                c = cont_re.match(lines[j])
                if c:
                    cont_lines.append(c.group(1).rstrip())
                    j += 1
                else:
                    break
            if not cont_lines:
                result.append(f"{num}. {text_part}")
            else:
                combined = ' '.join(cont_lines)
                if len(combined) > 300:
                    combined = combined[:300] + "..."
                result.append(f"{num}. {text_part} `{combined}`")
            i = j
        else:
            result.append(line)
            i += 1

    return '\n'.join(result)


def _render_finding_remedy(group_no: int, skill: str, findings: list[dict]) -> list[str]:
    """진단항목 findings를 참조 페이지 형식 가로 표로 렌더링.
    컬럼: Sub_No | 점검 항목 | 점검 방법 | 현황 | 결과 | 위험도 | 보안위협 | 대응방안 | 조치일자 | 조치계획(의견)
    """
    lines: list[str] = [
        "| Sub_No | 점검 항목 | 점검 방법 | 현황 | 결과 | 위험도 | 보안위협 | 대응방안 | 조치일자 | 조치계획(의견) |",
        "|--------|-----------|-----------|------|------|--------|----------|----------|----------|----------------|",
    ]
    for sub_idx, f in enumerate(findings, 1):
        sub_no      = f"{group_no}-{sub_idx}"
        check_item  = _esc(_check_item_label(skill, f))
        sev         = _norm_sev(f.get("severity", "—"))
        result      = _get_result(f)
        cwe         = f.get("cwe_id", "—")
        raw_desc    = _normalize_desc(f.get("description", "") or f.get("manual_review_note", ""))
        raw_recom   = _normalize_desc(f.get("recommendation", ""))

        hwang, threat = _split_desc_threat(raw_desc)
        if not threat:
            threat = f"{cwe} 취약점 악용 시 시스템 침해 또는 정보 유출 가능합니다."

        recom_cell = _recom_for_table_cell(raw_recom)

        lines.append(
            f"| {sub_no} | {check_item} | 소스코드 정적 분석 (SAST) "
            f"| {_esc(hwang)} | {_result_colored(result)} | {_sev_colored(sev)} "
            f"| {_esc(threat)} | {recom_cell} |  |  |"
        )
    lines.append("")
    return lines


def _extract_review_note_sections(review_note: str) -> str:
    """review_note 내용을 보고서용으로 반환.
    '## ' 마크다운 헤더가 있으면 첫 헤더 이후 섹션만 추출.
    없으면 평문 전체를 그대로 반환.
    """
    if not review_note:
        return ""
    idx = review_note.find("## ")
    if idx == -1:
        return review_note.strip()
    return review_note[idx:].strip()


def _render_taint_expand(evidence: dict) -> list[str]:
    """Taint flow 정보를 :::expand 블록으로 렌더링."""
    lines: list[str] = []
    taint_flow = evidence.get("taint_flow") or {}
    taint_evidence = evidence.get("taint_evidence") or []

    if not taint_flow and not taint_evidence:
        return lines

    lines.append(":::expand Taint Flow 상세")

    if taint_flow:
        source = taint_flow.get("source", "")
        sink   = taint_flow.get("sink", "")
        hops   = taint_flow.get("hops", "")
        chain  = taint_flow.get("call_chain") or []
        sanitized = taint_flow.get("sanitized", False)

        lines += [
            "| 항목 | 내용 |",
            "|------|------|",
        ]
        if source:
            lines.append(f"| Source | `{_esc(source)}` |")
        if sink:
            lines.append(f"| Sink | `{_esc(sink)}` |")
        if hops:
            lines.append(f"| Hops | {hops} |")
        lines.append(f"| 새니타이징 | {'예' if sanitized else '아니오'} |")

        if chain:
            lines += ["", "**호출 경로**", ""]
            for step in chain:
                lines.append(f"- `{step}`")
        lines.append("")

    for te in taint_evidence:
        title = te.get("title", "Taint Evidence")
        lines.append(f"**{title}**")
        lines.append("")

        for prefix in ("controller", "service", "repository", "mapper", "filter"):
            f_key  = f"{prefix}_file"
            l_key  = f"{prefix}_lines"
            s_key  = f"{prefix}_snippet"
            if te.get(f_key):
                layer_label = prefix.capitalize()
                lines.append(f"*{layer_label}* — `{te[f_key]}`:{te.get(l_key, '')}")
                lines.append("")
                if te.get(s_key):
                    lines.append("```java")
                    lines.append(te[s_key])
                    lines.append("```")
                    lines.append("")

    lines.append(":::")
    return lines


def _render_finding(sub_no: str, skill: str, f: dict) -> list[str]:
    """단일 finding 마크다운 블록 렌더링."""
    lines: list[str] = []

    title    = _clean_title(f.get("title", "—"))
    sev      = _norm_sev(f.get("severity", "—"))
    category = f.get("category", "—")
    cwe      = f.get("cwe_id", "—")
    owasp    = f.get("owasp_category", "—")
    desc     = f.get("description", "") or f.get("manual_review_note", "")
    recom    = f.get("recommendation", "")
    _ev_raw  = f.get("evidence")
    if isinstance(_ev_raw, list):
        evidence = _ev_raw[0] if _ev_raw else {}
    elif isinstance(_ev_raw, dict):
        evidence = _ev_raw
    else:
        evidence = {}
    snippet  = (evidence.get("code_snippet") or evidence.get("snippet")
                or f.get("code_snippet") or "")

    ep, af_str, handler = _location_cells(f)

    sev_badge    = _sev_colored(sev)
    result_badge = _result_colored(_get_result(f))
    desc  = _normalize_desc(desc)
    recom = _normalize_desc(recom)

    lines += [
        f"#### {sub_no} {title}",
        "",
        "| 항목 | 내용 |",
        "|------|------|",
        f"| 결과 | {result_badge} |",
        f"| 위험도 | {sev_badge} |",
        f"| 분류 | {_esc(category)} |",
    ]
    if ep != "—":
        lines.append(f"| 엔드포인트 | `{_esc(ep)}` |")
    if handler != "—":
        lines.append(f"| 핸들러 | `{_esc(handler)}` |")
    if af_str != "—":
        lines.append(f"| 영향 파일 | `{_esc(af_str)}` |")
    lines.append("")

    if desc:
        lines += ["**설명**", "", desc.strip(), ""]

    if recom:
        lines += ["**조치 권고**", "", _recom_for_confluence(recom), ""]

    if snippet:
        lang = "java"
        if af_str.endswith(".py"):
            lang = "python"
        elif af_str.endswith((".js", ".ts", ".tsx", ".jsx")):
            lang = "javascript"
        elif af_str.endswith(".php"):
            lang = "php"
        elif af_str.endswith(".kt"):
            lang = "kotlin"
        elif af_str.endswith((".xml", ".yaml", ".yml")):
            lang = "xml"
        lines += [f"**증거 코드** — `{_esc(af_str)}`", "", f"```{lang}", snippet, "```", ""]

    taint_lines = _render_taint_expand(evidence)
    if taint_lines:
        lines += taint_lines + [""]

    # report_expand: agent 생성 상세 검증 섹션 (없으면 review_note 폴백)
    report_expand_raw = f.get("report_expand", "")
    review_note_raw   = (f.get("review_note", "") or f.get("manual_review_note", "") or "").strip()

    expand_content = report_expand_raw or review_note_raw
    if expand_content:
        rn_sections = _extract_review_note_sections(expand_content)
        if rn_sections:
            lines += [":::expand 상세 검증 결과 (코드 직접 확인)", "", rn_sections, "", ":::"]
            lines.append("")

    # review_note: /sec-review 검토자 의견 — report_expand 있을 때도 별도 출력
    if report_expand_raw and review_note_raw:
        note_content = _extract_review_note_sections(review_note_raw)
        if note_content:
            if "\n" in note_content:
                lines += [":::expand 검토자 의견", "", note_content, "", ":::"]
            else:
                lines += [f"> **검토자 의견**: {note_content}"]
            lines.append("")

    lines.append("---")
    lines.append("")
    return lines


def render_markdown(
    run_id:     str,
    repo:       str,
    data:       dict[str, list[dict]],
    clone_info: dict,
) -> str:
    lines: list[str] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    all_findings = [(skill, f) for skill, findings in data.items() for f in findings]
    total_cnt    = len(all_findings)

    # 전체 severity 집계
    global_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for _, f in all_findings:
        sev = _norm_sev(f.get("severity", "Informational"))
        if sev in global_counts:
            global_counts[sev] += 1

    branch        = clone_info.get("branch", "—")
    commit        = clone_info.get("commit_hash", "—")
    clone_url     = clone_info.get("clone_url", "—")
    cloned_at     = (clone_info.get("cloned_at") or "")[:10] or "—"
    project       = clone_info.get("project", "—")
    maintainer    = clone_info.get("last_commit_author") or "—"
    exposure_type = load_service_exposure(repo)

    # ── 1. 진단 개요 ──────────────────────────────────────────────────────────
    lines += [
        f"# {repo}-진단결과",
        "",
        "## 1. 진단 개요",
        "",
        "| 항목 | 내용 |",
        "|------|------|",
        f"| 진단 대상 | {repo} |",
        f"| 서비스 유형 | {exposure_type} |",
        f"| Bitbucket 프로젝트 | {project} |",
        f"| 진단 브랜치 | {branch} |",
        f"| 커밋 해시 | `{commit[:12]}` |" if commit != "—" else f"| 커밋 해시 | — |",
        f"| 담당자 | {maintainer} |",
        f"| 보고서 생성일 | {now} |",
        f"| RUN_ID | `{run_id}` |",
        f"| 진단 유형 | SAST (정적 분석) + LLM 교차검증 |",
        f"| 진단 도구 | palantir (Claude Code 기반) |",
        f"| 전체 발견 건수 | {total_cnt}건 |",
        "",
    ]

    # ── 2. 취약점 요약 ────────────────────────────────────────────────────────
    gemini_prompt = _build_gemini_prompt_for_overview(
        repo, exposure_type, all_findings, global_counts
    )
    lines += [
        "## 2. 취약점 요약",
        "",
        "### 2.1 취약점 개요",
        "",
        ":::info LLM 작성 요청",
        "아래 프롬프트를 Gemini 등 LLM에 입력한 뒤, 생성된 문단으로 이 섹션을 교체하세요.",
        ":::",
        "",
        "```text",
        gemini_prompt,
        "```",
        "",
    ]

    # 섹션 3·4 공통 정렬 기준 및 skill 순서 (2.2보다 먼저 정의하여 Sub_No 사전 생성에 사용)
    ordered_skills = [s for s in SKILL_ORDER if s in data] + \
                     [s for s in sorted(data) if s not in SKILL_ORDER]

    def _detail_sort_key(f: dict) -> tuple:
        return (0 if _get_result(f) == "취약" else 1, _sev_key(f))

    # Sub_No 사전 생성: finding_id → "{skill_idx}-{sub_idx}" (섹션 4와 동일 기준)
    sub_no_map: dict[str, str] = {}
    _sk_idx = 1
    for _skill in ordered_skills:
        _fs = sorted(data[_skill], key=_detail_sort_key)
        if not _fs:
            continue
        for _si, _f in enumerate(_fs, 1):
            _fid = _f.get("finding_id", "")
            if _fid:
                sub_no_map[_fid] = f"{_sk_idx}-{_si}"
        _sk_idx += 1

    # 취약점 요약 표 (skill → 취약/정보 → severity 순)
    def _summary_sort_key(skill_f: tuple) -> tuple:
        skill, f = skill_f
        skill_rank  = SKILL_ORDER.index(skill) if skill in SKILL_ORDER else len(SKILL_ORDER)
        result_rank = 0 if _get_result(f) == "취약" else 1
        return (skill_rank, result_rank, _sev_key(f))

    lines += [
        "### 2.2 취약점 요약 표",
        "",
        "| Sub_No | 결과 | 위험도 | 제목 | 분류 | 파일:라인 | 조치 요약 |",
        "|--------|------|--------|------|------|----------|----------|",
    ]
    flat_sorted = sorted(all_findings, key=_summary_sort_key)
    for skill, f in flat_sorted:
        sub_no = sub_no_map.get(f.get("finding_id", ""), "—")
        sev    = _norm_sev(f.get("severity", "—"))
        result = _result_colored(_result_from_sev(sev))
        title  = _esc(_clean_title(f.get("title", "—")))
        cat    = _esc(f.get("category", "—"))
        ep, af_str, _ = _location_cells(f, omit_cve=True)
        file_loc      = _esc(af_str if af_str != "—" else ep)
        raw_recom     = _normalize_desc(f.get("recommendation", ""))
        recom_summary = _esc(_recom_summary(raw_recom)) if raw_recom else "—"
        lines.append(
            f"| {sub_no} | {result} | {_sev_colored(sev)} | {title} | {cat} | {file_loc} | {recom_summary} |"
        )
    lines.append("")

    if not all_findings:
        lines += ["> 발견된 취약점 없음 — 전 항목 양호", ""]
        _append_footer(lines)
        return "\n".join(lines)

    # ── 3. 취약점 상세 ────────────────────────────────────────────────────────
    lines += ["## 3. 취약점 상세", ""]

    for sec_no, skill in enumerate(ordered_skills, 1):
        findings = sorted(data[skill], key=_detail_sort_key)
        if not findings:
            continue
        label = SKILL_LABEL.get(skill, skill)
        lines += [f"### 3.{sec_no} {label}", ""]

        for f in findings:
            sub_no = sub_no_map.get(f.get("finding_id", ""), "—")
            lines += _render_finding(sub_no, skill, f)

    # ── 4. 면책 사항 ──────────────────────────────────────────────────────────
    _append_footer(lines)
    return "\n".join(lines)


def _append_footer(lines: list[str]) -> None:
    lines += [
        ":::note",
        DISCLAIMER,
        ":::",
        "",
        f"*생성: palantir generate_final_report.py — {datetime.now().strftime('%Y-%m-%d %H:%M')}*",
        "",
    ]


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="palantir Confluence 게시용 최종 보안 진단 보고서 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--run-id",  required=False, default=None,
                        help="파이프라인 RUN_ID (YYYYMMDD_HHMM); 생략 시 skill별 최신 파일 자동 선택")
    parser.add_argument("--repo",    required=True, help="진단 대상 레포 슬러그")
    parser.add_argument("--publish", action="store_true",
                        help="완료 후 Confluence에 자동 게시")
    parser.add_argument("--parent",  type=int, default=750459063, metavar="PAGE_ID",
                        help="Confluence 부모 페이지 ID (기본: 750459063 — SKP 보안진단 루트)")
    parser.add_argument("--title",   default=None,
                        help="Confluence 페이지 제목 (기본: '<repo>-진단결과')")
    args = parser.parse_args()

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    run_id_label = args.run_id or datetime.now().strftime("%Y%m%d")
    out_path = LOGS_DIR / f"final_{args.repo}_{run_id_label}.md"

    print(f"[최종보고서] RUN_ID={run_id_label}  repo={args.repo}")
    print(f"[최종보고서] findings 수집 중 (llm_checked: true 파일만)...")

    clone_info = load_clone_info(args.repo)
    data       = collect_findings(args.run_id, args.repo)

    total = sum(len(v) for v in data.values())
    print(f"[최종보고서] {len(data)}개 스킬  {total}건 findings")

    if not data:
        print("[WARN] llm_checked: true 파일이 없습니다. --type final 완료 후 실행하세요.")

    md = render_markdown(run_id_label, args.repo, data, clone_info)
    out_path.write_text(md, encoding="utf-8")
    print(f"[최종보고서] 저장 완료: {out_path}")

    if args.publish:
        publish_script = PALANTIR_DIR / "tools" / "publish_confluence.py"
        if not publish_script.exists():
            print(f"[WARN] publish_confluence.py 없음 — --publish 건너뜀")
            return 0
        title = args.title or f"{args.repo}-진단결과"
        print(f"\n[Confluence] 게시 중: {title}  (parent: {args.parent})")
        # 레지스트리에서 기존 page_id 조회 (prefix 매칭) — 없으면 CREATE, 있으면 UPDATE
        reg_path = PALANTIR_DIR / "docs" / ".confluence_pages.json"
        existing_page_id = None
        if reg_path.exists():
            import json as _json
            reg = _json.loads(reg_path.read_text(encoding="utf-8"))
            prefix = f"logs/final_{args.repo}_"
            existing_page_id = next((v for k, v in reg.items() if k.startswith(prefix)), None)
        cmd = [sys.executable, str(publish_script), str(out_path), "--title", title,
               "--parent", str(args.parent)]
        if existing_page_id:
            cmd += ["--page-id", str(existing_page_id)]
        subprocess.run(cmd, cwd=str(PALANTIR_DIR))

    return 0


if __name__ == "__main__":
    sys.exit(main())
