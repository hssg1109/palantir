"""
secret_gate.py — 시크릿(자격증명) 탐지/마스킹 공용 모듈.

palantir 파이프라인 내 시크릿 노출 방어의 단일 소스(single source of truth).
아래 세 지점에서 이 모듈을 재사용한다:
  - tools/secret_scan_gate.py  — Bitbucket(palantir_result) 업로드 직전 게이트 (얇은 wrapper)
  - tools/approve_report.py    — Confluence 게시 직전 게이트
  - tools/retroactive_secret_mask.py / tools/retroactive_cleanse.py — 소급 마스킹 및 검증

주의: palantir-jira-gateway/lambda/secret_gate.py는 별도 Lambda 배포 단위라
레포 간 import가 불가능해 로직이 별도로 존재한다. 이 파일의 정규식을 변경할
때는 그쪽도 함께 동기화해야 한다.

2026-08-07 ocb-nft-batch AWS Access Key ID 노출 사고, 2026-08-18 17개 레포
findings_DATA.json 자격증명 원문 노출 + Confluence 라이브 게시 사고 재발방지용.
"""

from __future__ import annotations

import re

# 값 포맷 자체로 식별 가능한 시크릿 (키 이름과 무관 — 오탐 위험이 매우 낮음)
_VALUE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key ID / STS Session Key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("PEM Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
]

# key = value / key: "value" 형태에서, 시크릿성 key 이름 뒤에 마스킹되지 않은
# 원문 값이 남아있는지 검사. 플레이스홀더/안전 패턴으로 시작하는 값은 스킵.
#
# 값 문자 클래스에서 백슬래시(\)를 반드시 제외해야 한다: JSON.dumps로 직렬화된
# 텍스트에서는 실제 개행이 리터럴 "\n"(백슬래시+n 두 글자)으로 표현되는데,
# 백슬래시가 제외되지 않으면 정규식이 이 경계를 넘어 다음 줄의 무관한 텍스트까지
# 값으로 삼켜버린다(2026-08-18 소급 마스킹 중 ocbx-transactor에서 실측 확인 —
# "password=hsm\nwallet.operator2.jce.provider=CloudHSM"이 하나의 43자 값으로
# 오매칭되어 실제 3자리 값 "hsm"이 마스킹되지 않고도 검증을 통과할 뻔했다).
#
# 최소 길이도 6→3으로 하향한다: 위 사고의 실제 원인 값 "hsm"처럼 3~5자의
# 짧은 값도 실존 자격증명일 수 있으므로, 오탐 방지보다 누락 방지를 우선한다
# (플레이스홀더 허용목록이 짧은 안전값을 이미 걸러낸다).
#
# 여는/닫는 따옴표 앞에 각각 선택적 백슬래시(\)를 허용한다: JSON.dumps로 직렬화된
# findings_*.json 텍스트에서는 필드 내부에 인용된 원본 설정줄이 `passwd=\"skp123\"`
# 처럼 이스케이프된 따옴표로 나타난다. 기존 quote 그룹은 실제 `"` 문자만 인식했고
# 값 문자 클래스는 백슬래시를 제외하므로, 이스케이프된 따옴표 앞에서 매치가 그냥
# 실패해 값이 스캔을 완전히 통과해버렸다(2026-08-25 ocbpass-newpg에서 실측 —
# push.apple.cert.passwd 운영 자격증명이 이 경로로 마스킹을 4곳 우회함).
# 값 문자 클래스 자체는 백슬래시를 계속 제외해 기존 2026-08-18 개행 이스케이프
# 방지 로직은 그대로 유지한다.
_KV_SECRET_RE = re.compile(
    r'(?i)(?P<prefix>\bthis\.)?\b(?P<key>password|passwd|pwd|secret|token|apikey|api[_-]key|'
    r'access[_-]?key(?:[_-]id)?|secret[_-]?key|client[_-]secret|'
    r'private[_-]key|signing[_-]key|hmac[_-]key|auth[_-]key)'
    r'\s*[=:]\s*\\?(?P<quote>["\']?)(?P<value>[^\s"\'\\,\]}]{3,})\\?(?P=quote)'
)

# [검토 후 폐기] 서술형 산문의 "`값`(라벨)" 패턴(예: `skp123`(APNS 인증서 패스워드))을
# 잡기 위해 2026-08-25에 백틱+괄호라벨 정규식을 시도했으나, 834개 파일 재스캔 결과
# 9개 매치 파일 중 8개(89%)가 오탐이었다 — 백틱으로 파일 경로(`src/utils/x.ts:27`),
# 메서드 참조(`Token.setToken`, `AdminUser.tempPassword()`), 환경변수 "이름"
# (`VITE_SAUCE_SECRET_KEY`, 값이 아닌 키 자체), 알고리즘명(`AES/GCM/NoPadding`),
# API 경로 등을 인용한 뒤 괄호로 "이게 뭔지 설명"하는 정상적인 보안 보고서 산문이
# 압도적으로 많아, "백틱 값 + 괄호에 key/secret/token/password 단어" 만으로는
# "실제 노출값"과 "식별자 설명"을 구분할 수 없었다. 이 게이트는 Confluence 게시
# 직전 차단(§5)에도 재사용되므로, 오탐이 정상 게시를 막는 것 자체가 새로운 사고
# 위험이라 판단해 공용 모듈에는 포함하지 않기로 결정했다. ocbpass-newpg처럼 이
# 패턴으로 실제 값이 노출된 개별 사례는 건별로 직접 확인 후 수동 마스킹한다.

# "this.<key> = <식별자>" 형태(따옴표 없는 값)는 Java 필드 대입문을 설명하는
# 코드 서술이지 리터럴 시크릿이 아니다 — Java에서 문자열 리터럴을 대입하려면
# 반드시 따옴표가 필요하므로, 따옴표 없는 값은 항상 변수/메서드 참조다.
# (2026-08-24 gws-admin-be-api DATA finding 서술 "this.password = tempPassword"
# 오탐 확인 — feedback_secret_gate_code_snippet_fp.md와 동일 오탐 계열.)
#
# _KV_SECRET_RE의 value 문자 클래스는 ")"/backtick/한글 등을 배제하지 않으므로
# 원문이 "...tempPassword)에서..." 처럼 공백 없이 이어지면 value에 후행
# 구두점·한글까지 그대로 캡처된다. 따라서 값 전체가 순수 식별자인지가 아니라,
# 값 앞부분에서 식별자를 추출한 뒤 나머지가 영문/숫자를 포함하지 않는지로 판단한다
# (나머지가 영문/숫자를 포함하면 식별자 뒤에 실제 시크릿 문자가 이어붙은 것일
# 수 있으므로 안전하지 않은 것으로 간주).
_JAVA_IDENTIFIER_PREFIX_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*")
_ALNUM_RE = re.compile(r"[A-Za-z0-9]")


def _is_code_field_reference(m: re.Match) -> bool:
    if not m.group("prefix") or m.group("quote"):
        return False
    value = m.group("value")
    ident = _JAVA_IDENTIFIER_PREFIX_RE.match(value)
    if not ident:
        return False
    remainder = value[ident.end():]
    return not _ALNUM_RE.search(remainder)

# 이미 마스킹됐거나 시크릿이 아닌 것으로 간주할 값 패턴 (플레이스홀더 허용목록).
# ENC(...) — Jasypt 암호화 값 표기, ${...}/$VAR — 환경변수 참조,
# 타입 키워드 — 코드/문서상의 타입 선언(실값 아님),
# 말줄임표(...) — 보고서 산문에서 "key=...&other=..." 형태로 URL/파라미터
# 형식을 예시할 때 쓰는 생략 표기(2026-08-20 okick-front DATA-001
# report_expand 오탐 확인 — 실제 값이 아닌 서술용 생략 부호),
# JS/TS 예약어 — 증거 코드 스니펫에 원문 그대로 인용되는 `token = await ...`
# 같은 변수 대입문에서 값 자리에 오는 언어 키워드(실값 아님. 2026-08-20
# okick-front DATA-001 evidence.code_snippet에서 실측 — 예약어를 시크릿으로
# 오인해 마스킹하면서 코드 자체가 손상되는 2차 사고가 이미 한 번 발생했다).
_PLACEHOLDER_PREFIX_RE = re.compile(
    r"(?i)^\[?redact|^\*{3,}|^n/?a$|^null$|^none$|^true$|^false$"
    r"|^enc\(|^\$\{|^\$[A-Za-z_]"
    r"|^(?:string|number|int|integer|long|boolean|bool|object|any)[\]\)\}]?$"
    r"|^\.{3,}$"
    r"|^(?:await|async|function|typeof|void|yield|new|this|undefined)[\]\)\},;]?$"
)


# --- 마크다운 표(real/stg/dev 비교표) 형태 자격증명 탐지 -----------------------
#
# feedback_hardcoded_credential_severity 정책의 교차검증 절차(운영/스테이징/개발
# 값을 표로 나란히 비교)로 작성된 review_note/report_expand에는 자격증명이
# `key=value` 형태가 아니라 `| 항목 | real | stg | dev |` 같은 마크다운 표 셀에
# 그대로 노출될 수 있다. _KV_SECRET_RE는 key=value 구문만 인식하므로 이 형태는
# 구조적으로 탐지 불가능하다(2026-08-25 ocbpass-newpg에서 실측 — 표 안의
# push.apple.cert.passwd 값 skp123가 세 환경 모두 노출).
#
# [1차 구현의 오탐 사고] "행에 시크릿성 key 이름 셀이 있으면 같은 행의 값처럼
# 보이는 셀을 위반으로 간주"하는 초기 버전은 findings_*.json 전체를 재스캔한
# 결과 62개 파일에서 최대 905건의 위반을 만들어냈다 — 실제로는 JSON 문자열
# 내부의 개행이 실제 개행(\n 바이트)이 아니라 이스케이프된 리터럴 "\n"(백슬래시+n
# 2글자)이므로, text.split("\n")으로는 표 전체(수십 행)가 통째로 "한 줄"이 되어
# 표 안의 모든 셀이 하나의 리스트로 섞여버렸다. 그 결과 "시크릿 키 이름이 등장하는
# 아무 표"(예: 발견된 설정키 목록 표, PII 로그 위치 표 등 — real/stg/dev 비교표가
# 아님)의 행 번호(100, 225...)나 파일명(OkiCardBatchFtpService.java) 같은 무관한
# 셀까지 "노출된 값"으로 오판정했다(2026-08-25 ocb-webview-api 재스캔에서 실측).
#
# [재설계] 이제 두 단계로 훨씬 보수적으로 판정한다:
#   1) JSON 이스케이프 개행(\n 리터럴)과 실제 개행을 모두 표 행 경계로 인식해
#      진짜 논리적 행 단위로 분리한다(_split_rows_with_seps).
#   2) 헤더 행에 real/stg/dev류 환경 라벨이 **2개 이상** 명시적으로 존재하는
#      표만 "자격증명 비교표"로 인정하고, 그 헤더의 환경 컬럼 위치에 해당하는
#      데이터 셀만 검사한다(_env_comparison_table_hits). "항목/키 이름" 컬럼이나
#      "비고/동일여부" 컬럼은 애초에 검사 대상에서 제외되므로, 시크릿 키 이름이
#      셀에 등장한다는 사실만으로는 더 이상 위반으로 이어지지 않는다.
_ENV_HEADER_CELL_RE = re.compile(
    r"(?i)^(real\s*\(운영\)|real|stg|dev|prod|production|staging|development|"
    r"운영|스테이징|개발|alpha)$"
)

_TABLE_SEPARATOR_RE = re.compile(r"^:?-{2,}:?$")

_KOREAN_RE = re.compile(r"[가-힣]")
# 최소 길이 3→5: "100"/"FTP"/"info" 같은 행 번호·짧은 영단어 오탐 방지
# (2026-08-25 재스캔 오탐 실측 — 모두 길이 3~4).
_TABLE_CELL_TOKEN_RE = re.compile(r"^[A-Za-z0-9!@#$%^&*()_+=./\-]{5,}$")
_PURE_DIGIT_RE = re.compile(r"^[0-9]+$")


def _looks_like_raw_secret_cell(cell: str) -> bool:
    c = cell.strip().strip("`").strip('\\"').strip("'").strip()
    if not c:
        return False
    if _PLACEHOLDER_PREFIX_RE.match(c):
        return False
    if "REDACTED" in c.upper():
        return False
    if _KOREAN_RE.search(c):
        return False
    if re.search(r"\s", c):
        return False
    if _PURE_DIGIT_RE.match(c):  # 순수 숫자(행 번호 등)는 값으로 보지 않음
        return False
    return bool(_TABLE_CELL_TOKEN_RE.match(c))


_ROW_SPLIT_RE = re.compile(r"(\r\n|\n|\\n)")


def _split_rows_with_seps(text: str) -> list[str]:
    """실제 개행과 JSON 문자열 내부 이스케이프 개행(리터럴 \\n) 모두를 표 행
    경계로 분리한다. 반환값은 [내용0, 구분자0, 내용1, 구분자1, ..., 내용N]
    형태(짝수 인덱스=행 내용, 홀수 인덱스=구분자 원문)이며, "".join(parts)로
    원문을 정확히 복원할 수 있다(re.split의 캡처 그룹 특성)."""
    return _ROW_SPLIT_RE.split(text)


def _physical_line_numbers(parts: list[str]) -> dict[int, int]:
    """parts의 각 내용 인덱스(짝수)에 대응하는 물리적 라인 번호(실제 개행 기준,
    이스케이프된 \\n은 라인 번호를 증가시키지 않음)."""
    mapping: dict[int, int] = {}
    line_no = 1
    for idx in range(0, len(parts), 2):
        mapping[idx] = line_no
        if idx + 1 < len(parts) and parts[idx + 1] in ("\n", "\r\n"):
            line_no += 1
    return mapping


def _env_comparison_table_hits(parts: list[str]) -> dict[int, list[int]]:
    """parts(짝수 인덱스=행 내용)에서 real/stg/dev 비교표로 확정된 표의 데이터
    행 중 '값처럼 보이는' 셀 위치를 {content_idx: [cell_idx, ...]} 로 반환.
    헤더 행에 환경 라벨이 2개 이상 있는 표만 대상으로 삼는다."""
    hits: dict[int, list[int]] = {}
    content_indices = list(range(0, len(parts), 2))
    n = len(content_indices)
    k = 0
    while k < n:
        idx = content_indices[k]
        line = parts[idx]
        if line.count("|") >= 3:
            cells = [c.strip() for c in line.split("|")]
            env_idxs = [ci for ci, c in enumerate(cells) if _ENV_HEADER_CELL_RE.match(c)]
            if len(env_idxs) >= 2:
                k2 = k + 1
                if k2 < n:
                    sep_cells = [c.strip() for c in parts[content_indices[k2]].split("|")]
                    if sep_cells and all(c == "" or _TABLE_SEPARATOR_RE.match(c) for c in sep_cells):
                        k2 += 1
                while k2 < n and parts[content_indices[k2]].count("|") >= 3:
                    data_idx = content_indices[k2]
                    data_cells = [c.strip() for c in parts[data_idx].split("|")]
                    row_hits = [
                        ci for ci in env_idxs
                        if ci < len(data_cells) and _looks_like_raw_secret_cell(data_cells[ci])
                    ]
                    if row_hits:
                        hits[data_idx] = row_hits
                    k2 += 1
                k = k2
                continue
        k += 1
    return hits


def mask_value(value: str) -> str:
    if not value:
        return value
    return "[REDACTED]"


def scan_text(text: str) -> list[str]:
    """text에서 발견된 위반 목록(사람이 읽을 메시지, 라인 정보 포함) 반환. 빈 리스트=통과."""
    messages: list[str] = []
    for label, pattern in _VALUE_PATTERNS:
        for m in pattern.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            messages.append(f"{label} (line {line_no})")
    for m in _KV_SECRET_RE.finditer(text):
        value = m.group("value")
        if _PLACEHOLDER_PREFIX_RE.match(value) or _is_code_field_reference(m):
            continue
        line_no = text.count("\n", 0, m.start()) + 1
        messages.append(f"미마스킹 자격증명 ({m.group('key')}) (line {line_no})")
    parts = _split_rows_with_seps(text)
    table_hits = _env_comparison_table_hits(parts)
    if table_hits:
        line_map = _physical_line_numbers(parts)
        for data_idx, cell_idxs in table_hits.items():
            for _ in cell_idxs:
                messages.append(f"미마스킹 자격증명 (표 형식) (line {line_map[data_idx]})")
    return messages


def scan_text_with_lines(text: str) -> list[tuple[str, int]]:
    """scan_text와 동일하지만 (label, line_no) 튜플로 반환 — 파일 경로 접두를 붙이는 호출자용."""
    hits: list[tuple[str, int]] = []
    for label, pattern in _VALUE_PATTERNS:
        for m in pattern.finditer(text):
            hits.append((label, text.count("\n", 0, m.start()) + 1))
    for m in _KV_SECRET_RE.finditer(text):
        value = m.group("value")
        if _PLACEHOLDER_PREFIX_RE.match(value) or _is_code_field_reference(m):
            continue
        hits.append((f"미마스킹 자격증명 ({m.group('key')})", text.count("\n", 0, m.start()) + 1))
    parts = _split_rows_with_seps(text)
    table_hits = _env_comparison_table_hits(parts)
    if table_hits:
        line_map = _physical_line_numbers(parts)
        for data_idx, cell_idxs in table_hits.items():
            for _ in cell_idxs:
                hits.append(("미마스킹 자격증명 (표 형식)", line_map[data_idx]))
    return hits


def mask_text(text: str) -> tuple[str, int]:
    """text 내 매치된 시크릿 값을 [REDACTED]로 치환. (치환된 텍스트, 치환 건수) 반환."""
    if not text:
        return text, 0

    count = 0

    def _mask_value_pattern(m: re.Match) -> str:
        nonlocal count
        count += 1
        return "[REDACTED]"

    result = text
    for _label, pattern in _VALUE_PATTERNS:
        result = pattern.sub(_mask_value_pattern, result)

    def _mask_kv(m: re.Match) -> str:
        nonlocal count
        value = m.group("value")
        if _PLACEHOLDER_PREFIX_RE.match(value) or _is_code_field_reference(m):
            return m.group(0)
        count += 1
        full = m.group(0)
        v_start = m.start("value") - m.start(0)
        v_end = m.end("value") - m.start(0)
        return full[:v_start] + "[REDACTED]" + full[v_end:]

    result = _KV_SECRET_RE.sub(_mask_kv, result)

    row_parts = _split_rows_with_seps(result)
    table_hits = _env_comparison_table_hits(row_parts)
    for data_idx, cell_idxs in table_hits.items():
        cells = row_parts[data_idx].split("|")
        for ci in cell_idxs:
            if ci < len(cells):
                stripped = cells[ci].strip()
                if stripped:
                    count += 1
                    cells[ci] = cells[ci].replace(stripped, "[REDACTED]", 1)
        row_parts[data_idx] = "|".join(cells)
    result = "".join(row_parts)

    return result, count
