#!/usr/bin/env python3
"""
scan_auth_baseline.py v1.0.0
================================================================================
인증/인가/어뷰징(sec-scan-auth) Auto-Scan — 판정 없는 후보 인벤토리 보강 전용.

이 스크립트는 TP/FP·severity를 판정하지 않는다. `scan_api.py` 출력(endpoints[])을
읽어 아래 4종 후보만 기계적으로 태깅하고, 전량 `needs_review: true` / `result: "정보"`
로 출력한다. 최종 category/severity/TP-FP 판정은
`sec-scan-auth/references/task_prompts/task_26_auth_abuse_review.md` 절차에 따라
LLM-Check(수동진단)가 전담한다.

태깅 후보:
  [IDOR_CANDIDATE]              path parameter가 리소스 식별자({id}/{seq}/{no} 등)이고
                                 auth_required=true인 endpoint
  [MISSING_AUTH_CANDIDATE]      auth_required=false 이면서 HTTP 메서드가 POST/PUT/DELETE/PATCH
  [ABUSE_KEYWORD_CANDIDATE]     path/handler/파라미터명에 포인트·쿠폰·이벤트 등 금전/리워드
                                 키워드가 포함된 endpoint (Rate Limit/멱등성/Mass Assignment
                                 심층진단 대상)
  [NO_AUTHZ_ANNOTATION_CANDIDATE] auth_required=true인데 @PreAuthorize/@Secured/hasRole 등
                                 인가(역할/권한) 애노테이션이 확인되지 않는 endpoint
                                 (인증은 되어 있으나 세부 인가 체크 부재 가능성)

사용법:
  python3 scan_auth_baseline.py state/<prefix>/api_inventory.json -o state/<prefix>/auth.json
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
#  탐지 패턴
# ============================================================

# path parameter가 리소스 식별자로 보이는 패턴: {id}, {userId}, {mbrId}, {orderSeq}, {couponNo} 등
_ID_PATH_PARAM_RE = re.compile(
    r"\{[A-Za-z0-9_]*(?:[Ii]d|[Ss]eq|[Nn]o)\}"
)

_MUTATING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

# 금전적 가치·리워드 관련 키워드 (path/handler/파라미터명 대상, 대소문자 무시)
_ABUSE_KEYWORDS_RE = re.compile(
    r"\b(point|coupon|reward|event|gift|draw|lottery|mileage|cashback|voucher)\b",
    re.IGNORECASE,
)

# 인가(역할/권한) 애노테이션 — 인증 애노테이션(@LoginUser 등)과는 별개
_AUTHZ_ANNOTATION_RE = re.compile(
    r"PreAuthorize|PostAuthorize|Secured|RolesAllowed|hasRole|hasAuthority|hasPermission",
    re.IGNORECASE,
)


@dataclass
class AuthCandidate:
    """인증/인가/어뷰징 후보 endpoint — 판정 없는 태깅 결과"""
    candidate_id: str
    candidate_type: str      # IDOR_CANDIDATE / MISSING_AUTH_CANDIDATE /
                              # ABUSE_KEYWORD_CANDIDATE / NO_AUTHZ_ANNOTATION_CANDIDATE
    reason: str               # 태깅 근거 (매칭된 패턴/파라미터명)
    method: str
    api: str
    handler: str
    file: str
    line: int
    module: str
    auth_required: bool
    auth_detail: str
    auth_annotations: list
    parameters: list
    result: str = "정보"
    needs_review: bool = True
    diagnosis_method: str = ""   # LLM-Check가 채운다 ("수동진단(LLM)")
    llm_task_ref: str = "sec-scan-auth/references/task_prompts/task_26_auth_abuse_review.md"


@dataclass
class AuthScanResult:
    version: str = VERSION
    task_id: str = "auth"
    status: str = "completed"
    source_api_inventory: str = ""
    scanned_at: str = ""
    summary: dict = field(default_factory=dict)
    candidates: list = field(default_factory=list)
    findings: list = field(default_factory=list)  # 항상 빈 배열 — Auto-Scan은 판정하지 않음


def _param_names(ep: dict) -> list:
    return [p.get("name", "") for p in ep.get("parameters", []) if isinstance(p, dict)]


def _has_id_path_param(ep: dict) -> str:
    """리소스 식별자로 보이는 path parameter가 있으면 매칭된 파라미터명 반환, 없으면 빈 문자열"""
    api = ep.get("api", "") or ""
    m = _ID_PATH_PARAM_RE.search(api)
    if m:
        return m.group(0)
    for p in ep.get("parameters", []):
        if isinstance(p, dict) and p.get("type") == "path":
            name = p.get("name", "")
            if re.search(r"(?:^|[a-z])(?:Id|Seq|No)$", name) or re.match(r"^id$", name, re.IGNORECASE):
                return name
    return ""


def _matched_abuse_keyword(ep: dict) -> str:
    haystack = " ".join([
        ep.get("api", "") or "",
        ep.get("handler", "") or "",
        " ".join(_param_names(ep)),
    ])
    m = _ABUSE_KEYWORDS_RE.search(haystack)
    return m.group(0) if m else ""


def _has_authz_annotation(ep: dict) -> bool:
    annos = ep.get("auth_annotations", []) or []
    for a in annos:
        if _AUTHZ_ANNOTATION_RE.search(str(a)):
            return True
    detail = ep.get("auth_detail", "") or ""
    return bool(_AUTHZ_ANNOTATION_RE.search(detail))


def tag_candidates(endpoints: list) -> list:
    candidates = []
    seq = 1

    def _next_id() -> str:
        nonlocal seq
        cid = f"AUTH-CAND-{seq:03d}"
        seq += 1
        return cid

    for ep in endpoints:
        method = ep.get("method", "")
        auth_required = bool(ep.get("auth_required", False))
        base_kwargs = dict(
            method=method,
            api=ep.get("api", ""),
            handler=ep.get("handler", ""),
            file=ep.get("file", ""),
            line=ep.get("line", 0),
            module=ep.get("module", ""),
            auth_required=auth_required,
            auth_detail=ep.get("auth_detail", ""),
            auth_annotations=ep.get("auth_annotations", []) or [],
            parameters=ep.get("parameters", []) or [],
        )

        id_param = _has_id_path_param(ep)
        if id_param and auth_required:
            candidates.append(AuthCandidate(
                candidate_id=_next_id(),
                candidate_type="IDOR_CANDIDATE",
                reason=f"리소스 식별자 path parameter 매칭: {id_param}",
                **base_kwargs,
            ))

        if not auth_required and method in _MUTATING_METHODS:
            candidates.append(AuthCandidate(
                candidate_id=_next_id(),
                candidate_type="MISSING_AUTH_CANDIDATE",
                reason=f"auth_required=false + {method} (상태 변경 요청)",
                **base_kwargs,
            ))

        abuse_kw = _matched_abuse_keyword(ep)
        if abuse_kw:
            candidates.append(AuthCandidate(
                candidate_id=_next_id(),
                candidate_type="ABUSE_KEYWORD_CANDIDATE",
                reason=f"금전/리워드 키워드 매칭: {abuse_kw}",
                **base_kwargs,
            ))

        if auth_required and not _has_authz_annotation(ep):
            candidates.append(AuthCandidate(
                candidate_id=_next_id(),
                candidate_type="NO_AUTHZ_ANNOTATION_CANDIDATE",
                reason="auth_required=true 이나 인가(역할/권한) 애노테이션 미확인",
                **base_kwargs,
            ))

    return candidates


def _build_summary(candidates: list, total_endpoints: int) -> dict:
    by_type = {}
    for c in candidates:
        by_type[c.candidate_type] = by_type.get(c.candidate_type, 0) + 1
    return {
        "total_endpoints_scanned": total_endpoints,
        "total_candidates": len(candidates),
        "by_candidate_type": by_type,
        "note": "이 단계는 판정을 수행하지 않음 — 전 항목 result=정보, needs_review=true. "
                "최종 category/severity/TP-FP는 task_26_auth_abuse_review.md 절차로 LLM-Check가 판정.",
    }


def main():
    parser = argparse.ArgumentParser(
        description="인증/인가/어뷰징 Auto-Scan — scan_api.py 산출물 기반 후보 태깅 (판정 없음)"
    )
    parser.add_argument(
        "api_inventory",
        help="scan_api.py 출력 JSON 경로 (endpoints[] 포함)",
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

    inv_path = Path(args.api_inventory)
    if not inv_path.exists():
        print(f"Error: api_inventory 파일을 찾을 수 없습니다: {inv_path}", file=sys.stderr)
        sys.exit(1)

    try:
        inventory = json.loads(inv_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"Error: JSON 파싱 실패: {e}", file=sys.stderr)
        sys.exit(1)

    endpoints = inventory.get("endpoints", [])
    if not endpoints:
        print("[경고] api_inventory에 endpoints가 없습니다 — scan_api.py를 먼저 실행했는지 확인하세요.",
              file=sys.stderr)

    print(f"[scan_auth_baseline v{VERSION}] 진단 시작: {inv_path} (endpoint {len(endpoints)}건)")

    candidates = tag_candidates(endpoints)
    summary = _build_summary(candidates, len(endpoints))

    result = AuthScanResult(
        source_api_inventory=str(inv_path),
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
        print(f"[완료] 후보 {len(candidates)}건 태깅 → {out_path}")
    else:
        json.dump(result_dict, sys.stdout, ensure_ascii=False, indent=2)
        print()

    if not args.quiet:
        for t, n in summary["by_candidate_type"].items():
            print(f"  {t}: {n}건")


if __name__ == "__main__":
    main()
