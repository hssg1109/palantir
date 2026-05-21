#!/usr/bin/env python3
"""
validate_findings.py — findings_*.json lint 스크립트

checks:
  - 필수 최상위 필드 (task_id, llm_checked, findings, evidence_trail)
  - findings[] 필수 필드 및 enum 값 검증
  - finding_id 형식: {SKILL}-{SEQ:03d}
  - severity ↔ risk_level 일치
  - owasp_category 존재 확인
  - scope.type 5종 enum
  - diagnosis_method / source / result enum

usage:
  python3 validate_findings.py state/<prefix>/findings_INJ.json [...]
  python3 validate_findings.py state/<prefix>/  # 디렉토리 내 findings_*.json 전체
"""

import json
import re
import sys
from pathlib import Path

# ── enum 정의 ────────────────────────────────────────────────────────────────

SKILL_PREFIXES = {"INJ", "XSS", "FILE", "DATA", "SCA"}

FINDING_ID_RE = re.compile(r"^(INJ|XSS|FILE|DATA|SCA)-\d{3}$")

VALID_SEVERITY = {"Critical", "High", "Medium", "Low", "Informational"}
SEVERITY_TO_RISK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}

VALID_RESULT = {"취약", "정보"}
VALID_DIAGNOSIS_METHOD = {"자동스캔(SAST)", "교차검증(수동)", "수동진단(LLM)"}
VALID_SOURCE = {"auto-scan", "llm-check", "llm-check(fn-detected)"}
VALID_SCOPE_TYPE = {"endpoint", "file", "config", "dependency", "global"}

VALID_CATEGORY = {
    # injection
    "SQL인젝션", "OS Command Injection", "SSI Injection", "SSTI",
    # xss
    "Persistent XSS", "Reflected XSS", "DOM XSS", "View XSS",
    "Open Redirect", "XSS 필터 미구현", "XSS 필터 불완전",
    # data
    "HARDCODED_SECRET", "SENSITIVE_LOGGING", "WEAK_CRYPTO", "JWT_INCOMPLETE",
    "DTO_EXPOSURE", "CORS_MISCONFIG", "SECURITY_HEADER", "INSECURE_TLS_CLIENT",
    "UNSAFE_DESERIALIZATION",
    # file
    "파일 업로드 취약점", "파일 다운로드 경로 조작", "원격 파일 포함", "파일 처리 범위 확인",
}

REQUIRED_TOP_LEVEL = {"task_id", "findings"}
REQUIRED_FINDING_FIELDS = {
    "finding_id", "title", "severity", "risk_level", "category",
    "result", "diagnosis_method", "source", "fn_detected", "fp_corrected",
    "scope", "description", "recommendation", "evidence", "needs_review",
}


# ── 검증 함수 ─────────────────────────────────────────────────────────────────

def validate_file(path: Path) -> list[str]:
    errors: list[str] = []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [f"JSON 파싱 오류: {e}"]

    # 최상위 필드
    for f in REQUIRED_TOP_LEVEL:
        if f not in data:
            errors.append(f"[TOP] 필수 필드 누락: {f}")

    if not data.get("llm_checked"):
        errors.append("[TOP] llm_checked 가 true 가 아님 — 1차 보고서 생성 불가")

    findings = data.get("findings", [])
    if not isinstance(findings, list):
        errors.append("[TOP] findings 가 배열이 아님")
        return errors

    seen_ids: set[str] = set()

    for i, f in enumerate(findings):
        prefix = f"[findings[{i}]]"

        # 필수 필드 존재 확인
        for field in REQUIRED_FINDING_FIELDS:
            if field not in f:
                errors.append(f"{prefix} 필수 필드 누락: {field}")

        fid = f.get("finding_id", "")
        if not FINDING_ID_RE.match(str(fid)):
            errors.append(
                f"{prefix} finding_id 형식 오류: '{fid}' "
                f"(허용: INJ-001, XSS-003, FILE-002, DATA-007, SCA-001)"
            )
        if fid in seen_ids:
            errors.append(f"{prefix} finding_id 중복: '{fid}'")
        seen_ids.add(fid)

        # severity enum
        severity = f.get("severity", "")
        if severity not in VALID_SEVERITY:
            errors.append(f"{prefix} severity 허용값 외: '{severity}'")

        # risk_level ↔ severity 일치
        risk = f.get("risk_level")
        expected_risk = SEVERITY_TO_RISK.get(severity)
        if expected_risk is not None and risk != expected_risk:
            errors.append(
                f"{prefix} risk_level 불일치: severity={severity} → 기대값 {expected_risk}, 실제값 {risk}"
            )

        # result enum
        result = f.get("result", "")
        if result not in VALID_RESULT:
            errors.append(
                f"{prefix} result 허용값 외: '{result}' "
                f"(허용: 취약, 정보 — FP는 evidence_trail에만 기록)"
            )

        # diagnosis_method enum
        dm = f.get("diagnosis_method", "")
        if dm not in VALID_DIAGNOSIS_METHOD:
            errors.append(
                f"{prefix} diagnosis_method 허용값 외: '{dm}' "
                f"(허용: {' / '.join(VALID_DIAGNOSIS_METHOD)})"
            )

        # source enum
        src = f.get("source", "")
        if src not in VALID_SOURCE:
            errors.append(
                f"{prefix} source 허용값 외: '{src}' "
                f"(허용: {' / '.join(VALID_SOURCE)})"
            )

        # category enum
        cat = f.get("category", "")
        if cat and cat not in VALID_CATEGORY:
            errors.append(
                f"{prefix} category 비표준값: '{cat}' "
                f"— vuln_taxonomy.md 참조 (예: SQL인젝션, Persistent XSS)"
            )

        # scope.type enum
        scope = f.get("scope", {})
        if isinstance(scope, dict):
            stype = scope.get("type", "")
            if stype not in VALID_SCOPE_TYPE:
                errors.append(
                    f"{prefix} scope.type 허용값 외: '{stype}' "
                    f"(허용: {' / '.join(sorted(VALID_SCOPE_TYPE))})"
                )
        else:
            errors.append(f"{prefix} scope 가 객체가 아님")

        # owasp_category 존재 확인
        if not f.get("owasp_category"):
            errors.append(f"{prefix} owasp_category 누락")

        # evidence.code_snippet 존재 확인
        evidence = f.get("evidence", {})
        if isinstance(evidence, dict):
            if not evidence.get("code_snippet") and not evidence.get("taint_evidence"):
                errors.append(
                    f"{prefix} evidence.code_snippet 누락 — finding 미완성 (taint_evidence도 없음)"
                )
            if not evidence.get("file"):
                errors.append(f"{prefix} evidence.file 누락")
        else:
            errors.append(f"{prefix} evidence 가 객체가 아님")

    return errors


# ── 진입점 ────────────────────────────────────────────────────────────────────

def main() -> int:
    if len(sys.argv) < 2:
        print("usage: validate_findings.py <findings_*.json | directory> [...]")
        return 1

    targets: list[Path] = []
    for arg in sys.argv[1:]:
        p = Path(arg)
        if p.is_dir():
            targets.extend(sorted(p.glob("findings_*.json")))
        elif p.is_file():
            targets.append(p)
        else:
            print(f"경고: 경로 없음 — {arg}")

    if not targets:
        print("검사할 파일 없음")
        return 1

    total_errors = 0
    for path in targets:
        errors = validate_file(path)
        if errors:
            print(f"\n❌  {path}")
            for e in errors:
                print(f"    {e}")
            total_errors += len(errors)
        else:
            print(f"✅  {path}")

    print(f"\n총 {len(targets)}개 파일, {total_errors}개 오류")
    return 0 if total_errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
