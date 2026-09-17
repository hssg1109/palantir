#!/usr/bin/env python3
"""
scan_php_baseline.py v1.0.0
================================================================================
PHP (sec-scan-php) Auto-Scan — 판정 없는 후보 태깅 전용.

PHP는 라우터/프레임워크가 없는 레거시 flat 구조(파일 1개 = 웹 진입점 1개)이며
정적분석기가 별도로 없다. 이 스크립트는 TP/FP·category·severity를 전혀 판정하지
않는다. PHP 소스 디렉터리를 직접 순회하며 아래 8종 후보만 정규식으로 태깅하고,
전량 `needs_review: true` / `result: "정보"` 로 출력한다. 최종 판정은
`sec-scan-php/references/task_prompts/task_php_llm_review.md` 절차에 따라
LLM-Check(수동진단)가 전담한다.

태깅 후보:
  [SQLI_CANDIDATE]              mysql_query/mysqli_query 등에 변수 인자
  [CMD_INJECTION_CANDIDATE]     system/exec/shell_exec/passthru/백틱 연산자에 변수 인자
  [LFI_RFI_CANDIDATE]           include/require(_once) 인자가 변수 포함(리터럴 아님)
  [XSS_CANDIDATE]               echo/print 가 $_GET/$_POST/$_REQUEST/$_COOKIE 를
                                 htmlspecialchars/htmlentities 경유 없이 직접 출력
  [HARDCODED_SECRET_CANDIDATE]  pass/password/secret/apikey/token 등 변수·배열키에
                                 리터럴 문자열 대입
  [WEAK_CRYPTO_CANDIDATE]       md5()/sha1() 호출
  [PATH_TRAVERSAL_CANDIDATE]    fopen/file_get_contents/readfile/unlink 인자에
                                 $_GET/$_POST/$_REQUEST/$_COOKIE 직접 전달
  [EVAL_CANDIDATE]              eval()/assert()/create_function() 인자에 변수
  [INSECURE_TLS_CLIENT_CANDIDATE]  CURLOPT_SSL_VERIFYPEER/VERIFYHOST를 false/0으로
                                 설정(TLS 인증서 검증 비활성화) — 2026-09-16
                                 ocb_game_biz PHP-010(결제 danal 모듈 포함 25개
                                 파일 64개소)이 8종 후보에 없어 원본 스캔에서
                                 태깅조차 되지 않았던 것을 사용자 지시로 보완

사용법:
  python3 scan_php_baseline.py testbed/<repo>/ocb_php -o state/<prefix>/php.json
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

VERSION = "1.1.1"

# ============================================================
#  스캔 대상 제외 디렉터리 (vendor/JS 번들 등 비-PHP 자산)
# ============================================================

# PHPExcel/aci-tree: vendor/ 외 경로(예: lib/)에 번들된 서드파티 라이브러리가
# 2026-09-14 homeshopping/trend-ad/trend-cms/trendissue 4개 레포에서 동일하게
# WEAK_CRYPTO_CANDIDATE·LFI_RFI_CANDIDATE 오탐을 반복 생산한 것이 확인되어 추가.
_EXCLUDE_DIR_RE = re.compile(
    r"(^|/)(\.git|node_modules|vendor|styleup[^/]*|common/js|PHPExcel|aci-tree)(/|$)",
    re.IGNORECASE,
)

# ============================================================
#  탐지 패턴
# ============================================================

_SQLI_RE = re.compile(r"\b(mysql_query|mysqli_query)\s*\([^)]*\$[^)]*\)")

_CMD_FUNC_RE = re.compile(r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$[^)]*\)")

_LFI_RFI_RE = re.compile(r"\b(include|include_once|require|require_once)\b\s*\(?\s*[^;]*\$")

_XSS_SOURCE_RE = re.compile(r"\b(echo|print)\b[^;]*\$_(GET|POST|REQUEST|COOKIE)\b")
_XSS_SANITIZED_RE = re.compile(r"htmlspecialchars|htmlentities|htmlspecialchars_decode", re.IGNORECASE)

_SECRET_VAR_RE = re.compile(
    r"\$[A-Za-z_][A-Za-z0-9_]*(pass|passwd|password|secret|apikey|api_key|token|pwd)[A-Za-z0-9_]*"
    r"\s*=\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
_SECRET_ARRAYKEY_RE = re.compile(
    r"['\"](pass|passwd|password|secret|apikey|api_key|token|pwd)['\"]\s*=>\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)

_WEAK_CRYPTO_RE = re.compile(r"\b(md5|sha1)\s*\(")

_PATH_TRAVERSAL_RE = re.compile(
    r"\b(fopen|file_get_contents|readfile|unlink)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\b"
)

_EVAL_RE = re.compile(r"\b(eval|assert|create_function)\s*\([^)]*\$")

_INSECURE_TLS_RE = re.compile(
    r"\b(CURLOPT_SSL_VERIFYPEER|CURLOPT_SSL_VERIFYHOST)\s*(,|=>)\s*(false|0)\b",
    re.IGNORECASE,
)


def _scan_backtick_exec(line: str, in_squote: bool, in_dquote: bool) -> tuple:
    """PHP 백틱 shell-exec 연산자가 문자열 리터럴 '밖'에 실제로 존재하고, 그 안에
    변수가 포함되는지 확인한다. PHP는 따옴표 밖의 백틱만 shell_exec()와 동일한
    실행 연산자로 취급하며, 작은따옴표/큰따옴표 문자열 안의 백틱은 MySQL 식별자
    인용(``` `column_name` ```) 등 문자 그 자체일 뿐 실행과 무관하다. 단순
    `[^`]*\\$[^`]*` 정규식은 이 구분을 못 해 SQL 문자열 리터럴 안의 백틱까지
    전량 CMD_INJECTION 후보로 오탐 태깅하는 문제가 있어(v1.0.0), 따옴표 상태를
    추적하는 상태 기계로 대체한다.

    PHP 문자열(특히 SQL 조립용 `$query = "..."`)은 여러 줄에 걸쳐 이어지는 경우가
    흔하므로, 이 함수는 파일 스캔 루프가 이전 줄들로부터 넘겨준 인용부호 상태
    (in_squote/in_dquote)를 받아 이번 줄 끝의 상태까지 함께 반환한다(caller가 다음
    줄 호출 시 그대로 다시 넘겨 누적). 한 줄 단위로 상태를 매번 초기화하면 여는
    따옴표가 있는 줄과 백틱이 있는 줄이 다를 때(멀티라인 문자열) 여전히 오탐이
    발생한다(v1.1.0에서 처음 발견).

    반환값: (found: bool, in_squote: bool, in_dquote: bool) — found는 이번 줄에서
    실행 연산자로 쓰인 백틱을 발견했는지, 나머지 둘은 다음 줄에 넘길 종료 상태."""
    found = False
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if ch == "\\" and (in_squote or in_dquote):
            i += 2
            continue
        if in_squote:
            if ch == "'":
                in_squote = False
            i += 1
            continue
        if in_dquote:
            if ch == '"':
                in_dquote = False
            i += 1
            continue
        if ch == "'":
            in_squote = True
        elif ch == '"':
            in_dquote = True
        elif ch == "`":
            close = line.find("`", i + 1)
            if close == -1:
                # 줄 끝까지 닫히지 않음 — 이 줄에서는 실행 연산자로 판단하지 않음
                i = n
                continue
            if "$" in line[i + 1:close]:
                found = True
            i = close
        i += 1
    return found, in_squote, in_dquote


@dataclass
class PhpCandidate:
    """PHP 취약 패턴 후보 — 판정 없는 태깅 결과"""
    candidate_id: str
    candidate_type: str      # SQLI_CANDIDATE / CMD_INJECTION_CANDIDATE / LFI_RFI_CANDIDATE /
                              # XSS_CANDIDATE / HARDCODED_SECRET_CANDIDATE / WEAK_CRYPTO_CANDIDATE /
                              # PATH_TRAVERSAL_CANDIDATE / EVAL_CANDIDATE /
                              # INSECURE_TLS_CLIENT_CANDIDATE
    reason: str               # 태깅 근거 (매칭된 패턴)
    file: str
    line: int
    code_snippet: str
    result: str = "정보"
    needs_review: bool = True
    diagnosis_method: str = ""   # LLM-Check가 채운다 ("수동진단(LLM)")
    llm_task_ref: str = "sec-scan-php/references/task_prompts/task_php_llm_review.md"


@dataclass
class PhpScanResult:
    version: str = VERSION
    task_id: str = "php"
    status: str = "completed"
    source_dir: str = ""
    scanned_at: str = ""
    summary: dict = field(default_factory=dict)
    candidates: list = field(default_factory=list)
    findings: list = field(default_factory=list)  # 항상 빈 배열 — Auto-Scan은 판정하지 않음


def _iter_php_files(src_dir: Path):
    for path in sorted(src_dir.rglob("*.php")):
        rel = path.relative_to(src_dir).as_posix()
        if _EXCLUDE_DIR_RE.search(rel):
            continue
        yield path


def _tag_line(file_rel: str, lineno: int, line: str, in_squote: bool, in_dquote: bool) -> tuple:
    """한 줄에 대해 매칭되는 모든 candidate_type을 반환.

    in_squote/in_dquote는 이전 줄들로부터 이어지는 문자열 리터럴 인용부호 상태
    (멀티라인 PHP 문자열 대응, _scan_backtick_exec 참조)이며, 이번 줄 처리 후
    갱신된 상태와 함께 (tags, in_squote, in_dquote) 튜플로 반환한다."""
    tags = []
    stripped = line.strip()
    # in_squote/in_dquote가 이미 True면(이전 줄에서 이어지는 멀티라인 문자열 내부)
    # 이 줄이 "//"/"#"로 시작하더라도 실제 PHP 주석이 아니라 문자열 내용일 수
    # 있으므로 주석으로 간주해 건너뛰지 않는다 — 건너뛰면 이 줄에 있는 종료
    # 따옴표를 놓쳐 이후 모든 줄의 상태가 어긋난다.
    if not (in_squote or in_dquote):
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return tags, in_squote, in_dquote

    m = _SQLI_RE.search(line)
    if m:
        tags.append(("SQLI_CANDIDATE", f"쿼리 호출에 변수 인자 포함: {m.group(1)}()"))

    backtick_found, in_squote, in_dquote = _scan_backtick_exec(line, in_squote, in_dquote)
    m = _CMD_FUNC_RE.search(line)
    if m:
        tags.append(("CMD_INJECTION_CANDIDATE", f"OS 명령 실행 함수에 변수 인자 포함: {m.group(0)[:60]}"))
    elif backtick_found:
        tags.append(("CMD_INJECTION_CANDIDATE", "백틱 연산자(문자열 리터럴 밖)에 변수 인자 포함"))

    m = _LFI_RFI_RE.search(line)
    if m:
        tags.append(("LFI_RFI_CANDIDATE", f"{m.group(1)} 인자에 변수 포함(리터럴 아님)"))

    m = _XSS_SOURCE_RE.search(line)
    if m and not _XSS_SANITIZED_RE.search(line):
        tags.append(("XSS_CANDIDATE", f"$_{m.group(2)} 를 필터링 없이 직접 출력"))

    m = _SECRET_VAR_RE.search(line) or _SECRET_ARRAYKEY_RE.search(line)
    if m:
        tags.append(("HARDCODED_SECRET_CANDIDATE", f"자격증명 변수/키에 리터럴 문자열 대입: {m.group(1)}"))

    m = _WEAK_CRYPTO_RE.search(line)
    if m:
        tags.append(("WEAK_CRYPTO_CANDIDATE", f"약한 해시 알고리즘 사용: {m.group(1)}()"))

    m = _PATH_TRAVERSAL_RE.search(line)
    if m:
        tags.append(("PATH_TRAVERSAL_CANDIDATE", f"{m.group(1)}()에 $_{m.group(2)} 직접 전달"))

    m = _EVAL_RE.search(line)
    if m:
        tags.append(("EVAL_CANDIDATE", f"동적 코드 실행 함수에 변수 인자 포함: {m.group(1)}()"))

    m = _INSECURE_TLS_RE.search(line)
    if m:
        tags.append(("INSECURE_TLS_CLIENT_CANDIDATE", f"TLS 인증서 검증 비활성화: {m.group(1)}={m.group(3)}"))

    return tags, in_squote, in_dquote


def tag_candidates(src_dir: Path) -> tuple:
    candidates = []
    seq = 1
    total_files = 0

    def _next_id() -> str:
        nonlocal seq
        cid = f"PHP-CAND-{seq:03d}"
        seq += 1
        return cid

    for path in _iter_php_files(src_dir):
        total_files += 1
        rel = path.relative_to(src_dir).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"[경고] 파일 읽기 실패, skip: {rel} ({e})", file=sys.stderr)
            continue

        in_squote = False
        in_dquote = False
        for lineno, line in enumerate(text.splitlines(), start=1):
            tags, in_squote, in_dquote = _tag_line(rel, lineno, line, in_squote, in_dquote)
            for candidate_type, reason in tags:
                candidates.append(PhpCandidate(
                    candidate_id=_next_id(),
                    candidate_type=candidate_type,
                    reason=reason,
                    file=rel,
                    line=lineno,
                    code_snippet=line.strip()[:300],
                ))

    return candidates, total_files


def _build_summary(candidates: list, total_files: int) -> dict:
    by_type = {}
    for c in candidates:
        by_type[c.candidate_type] = by_type.get(c.candidate_type, 0) + 1
    return {
        "total_files_scanned": total_files,
        "total_candidates": len(candidates),
        "by_candidate_type": by_type,
        "note": "이 단계는 판정을 수행하지 않음 — 전 항목 result=정보, needs_review=true. "
                "최종 category/severity/TP-FP는 task_php_llm_review.md 절차로 LLM-Check가 판정. "
                "PHP는 라우터가 없어 파일 자체가 웹 진입점(1파일=1endpoint)이므로 "
                "asset 인벤토리는 task_php_asset_identification.md 절차로 별도 생성한다.",
    }


def main():
    parser = argparse.ArgumentParser(
        description="PHP Auto-Scan — 소스 디렉터리 직접 순회 기반 후보 태깅 (판정 없음)"
    )
    parser.add_argument(
        "src_dir",
        help="PHP 소스 디렉터리 경로 (예: testbed/<repo>/ocb_php)",
    )
    parser.add_argument(
        "--output", "-o",
        help="결과 출력 JSON 파일 경로",
        default=None,
    )
    parser.add_argument(
        "--quiet", "-q",
        help="요약만 출력",
        action="store_true",
    )
    args = parser.parse_args()

    src_path = Path(args.src_dir)
    if not src_path.exists() or not src_path.is_dir():
        print(f"Error: PHP 소스 디렉터리를 찾을 수 없습니다: {src_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[scan_php_baseline v{VERSION}] 진단 시작: {src_path}")

    candidates, total_files = tag_candidates(src_path)
    if total_files == 0:
        print("[경고] .php 파일을 찾지 못했습니다 — 경로 또는 제외 규칙을 확인하세요.", file=sys.stderr)

    summary = _build_summary(candidates, total_files)

    result = PhpScanResult(
        source_dir=str(src_path),
        scanned_at=datetime.now().isoformat(),
        summary=summary,
        candidates=[asdict(c) for c in candidates],
        findings=[],
    )
    result_dict = asdict(result)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result_dict, f, ensure_ascii=False, indent=2)
        print(f"[완료] 후보 {len(candidates)}건 태깅 (파일 {total_files}개 스캔) → {out_path}")
    else:
        json.dump(result_dict, sys.stdout, ensure_ascii=False, indent=2)
        print()

    if not args.quiet:
        for t, n in summary["by_candidate_type"].items():
            print(f"  {t}: {n}건")


if __name__ == "__main__":
    main()
