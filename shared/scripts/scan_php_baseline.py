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

VERSION = "1.0.0"

# ============================================================
#  스캔 대상 제외 디렉터리 (vendor/JS 번들 등 비-PHP 자산)
# ============================================================

_EXCLUDE_DIR_RE = re.compile(
    r"(^|/)(\.git|node_modules|vendor|styleup[^/]*|common/js)(/|$)",
    re.IGNORECASE,
)

# ============================================================
#  탐지 패턴
# ============================================================

_SQLI_RE = re.compile(r"\b(mysql_query|mysqli_query)\s*\([^)]*\$[^)]*\)")

_CMD_FUNC_RE = re.compile(r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$[^)]*\)")
_CMD_BACKTICK_RE = re.compile(r"`[^`]*\$[^`]*`")

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


@dataclass
class PhpCandidate:
    """PHP 취약 패턴 후보 — 판정 없는 태깅 결과"""
    candidate_id: str
    candidate_type: str      # SQLI_CANDIDATE / CMD_INJECTION_CANDIDATE / LFI_RFI_CANDIDATE /
                              # XSS_CANDIDATE / HARDCODED_SECRET_CANDIDATE / WEAK_CRYPTO_CANDIDATE /
                              # PATH_TRAVERSAL_CANDIDATE / EVAL_CANDIDATE
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


def _tag_line(file_rel: str, lineno: int, line: str) -> list:
    """한 줄에 대해 매칭되는 모든 candidate_type을 반환"""
    tags = []
    stripped = line.strip()
    if not stripped or stripped.startswith("//") or stripped.startswith("#"):
        return tags

    m = _SQLI_RE.search(line)
    if m:
        tags.append(("SQLI_CANDIDATE", f"쿼리 호출에 변수 인자 포함: {m.group(1)}()"))

    m = _CMD_FUNC_RE.search(line) or _CMD_BACKTICK_RE.search(line)
    if m:
        tags.append(("CMD_INJECTION_CANDIDATE", f"OS 명령 실행 함수/백틱에 변수 인자 포함: {m.group(0)[:60]}"))

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

    return tags


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

        for lineno, line in enumerate(text.splitlines(), start=1):
            for candidate_type, reason in _tag_line(rel, lineno, line):
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
