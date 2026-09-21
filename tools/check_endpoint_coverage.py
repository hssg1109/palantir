#!/usr/bin/env python3
"""영향 엔드포인트 커버리지 가드.

Auto-Scan이 `취약`으로 판정한 엔드포인트 전건이 findings_*.json 어딘가에
(scope.endpoint / scope.affected_files[] / report_expand 표 / review_note /
description) 등장하는지 기계적으로 대조한다.

도입 배경 (2026-09-18 sample-game-backend XSS-002): root cause finding 검토가
"대표 샘플 3-5건"만 확인하도록 지시돼 있어, 실제 자유 텍스트 저장 API 24건 중
7건만 보고서에 기재되고 나머지는 어디에도 나타나지 않았다. 개발팀이 조치 범위를
특정할 수 없어 사후 보강·재게시가 필요했다. 절차 개선
(task_23_xss_review.md 전수 분류 의무, finding_writing_guide.md §7)의
기계적 백스톱으로, `/sec-review` §5b 자기일관성 검증에서 실행된다.

누락으로 보고된 엔드포인트는 "조치 대상"이라는 뜻이 아니라 "확정/제외 어느 쪽으로도
보고서에 언급되지 않았다"는 뜻이다. 확정이면 affected_files[]에, 제외면
report_expand 제외 표에 사유와 함께 추가하면 해소된다.

사용:
  python3 tools/check_endpoint_coverage.py --repo sample-game-backend --skill xss
  python3 tools/check_endpoint_coverage.py --repo <repo> --skill xss --run-id 20260916_2300 --strict
  python3 tools/check_endpoint_coverage.py --scan-json <path> --findings-json <path>
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 스캔 결과 JSON에서 엔드포인트 배열이 들어있는 키 후보 (skill별 상이)
ENDPOINT_LIST_KEYS = ("endpoint_diagnoses", "endpoints", "diagnoses", "api_list", "results")
# 엔드포인트 단위 취약 판정으로 간주할 result 값
VULN_RESULTS = ("취약", "정보", "수동검토필요", "정보(수동검토필요)")

METHOD_KEYS = ("http_method", "method", "httpMethod")
PATH_KEYS = ("request_mapping", "endpoint", "path", "url", "uri")
HANDLER_KEYS = ("handler", "handler_method", "method_name")


def norm_path(p: str) -> str:
    """경로 정규화 — 경로변수명 차이({seq} vs {partnerSeq})와 슬래시/대소문자 차이를 흡수."""
    if not p:
        return ""
    p = p.strip().strip("`\"' ")
    p = re.sub(r"^[A-Z]+\s+", "", p)           # 앞에 붙은 HTTP 메서드 제거
    p = re.sub(r"\{[^}]*\}", "{}", p)          # 경로변수 → {}
    p = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", "{}", p)  # :id 스타일도 {}
    p = re.sub(r"/+", "/", p)
    return "/" + p.strip("/").lower()


def pick(d: dict, keys) -> str:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def collect_scan_endpoints(scan: dict):
    """스캔 JSON에서 (no, method, raw_path, norm_path, handler, result) 목록 추출."""
    items = None
    for k in ENDPOINT_LIST_KEYS:
        v = scan.get(k)
        if isinstance(v, list) and v and isinstance(v[0], dict):
            items = v
            break
    if items is None:
        return []

    out = []
    for it in items:
        result = str(it.get("result", "")).strip()
        if result not in VULN_RESULTS:
            continue
        raw = pick(it, PATH_KEYS)
        if not raw:
            continue
        out.append({
            "no": str(it.get("no", "") or it.get("id", "")),
            "method": pick(it, METHOD_KEYS).upper(),
            "raw_path": raw,
            "norm_path": norm_path(raw),
            "handler": pick(it, HANDLER_KEYS),
            "result": result,
        })
    return out


def collect_finding_corpus(findings: dict):
    """finding 전체에서 엔드포인트가 언급될 수 있는 텍스트를 모아 하나의 코퍼스로 만든다."""
    parts = []
    norm_paths = set()

    def add_text(v):
        if isinstance(v, str) and v.strip():
            parts.append(v)

    def walk_scope(scope: dict):
        ep = pick(scope, ("endpoint",))
        if ep:
            norm_paths.add(norm_path(ep))
            add_text(ep)
        for af in scope.get("affected_files", []) or []:
            if isinstance(af, dict):
                e = pick(af, ("endpoint",))
                if e:
                    norm_paths.add(norm_path(e))
                    add_text(e)
                add_text(af.get("handler", ""))
                add_text(af.get("file", ""))
        for ae in scope.get("affected_endpoints", []) or []:
            if isinstance(ae, dict):
                e = pick(ae, PATH_KEYS)
                if e:
                    norm_paths.add(norm_path(e))
                    add_text(e)
            elif isinstance(ae, str):
                norm_paths.add(norm_path(ae))
                add_text(ae)

    for f in findings.get("findings", []) or []:
        for k in ("title", "description", "recommendation", "report_expand",
                  "review_note", "manual_review_note", "impact"):
            add_text(f.get(k, ""))
        sc = f.get("scope")
        if isinstance(sc, dict):
            walk_scope(sc)
        ev = f.get("evidence")
        if isinstance(ev, dict):
            for k in ("taint_flow", "code_snippet", "snippet", "note"):
                add_text(ev.get(k, ""))

    corpus = "\n".join(parts)
    # 코퍼스 안에 등장하는 경로 토큰도 정규화해 집합에 넣는다 (표 안의 `POST /a/b/{id}` 등)
    for m in re.finditer(r"/[A-Za-z0-9_\-./{}:]{3,}", corpus):
        norm_paths.add(norm_path(m.group(0)))
    return corpus, norm_paths


def handler_tokens(handler: str):
    """'AdminUserController.createAdminUser()' → ('AdminUserController', 'createAdminUser')"""
    h = handler.replace("()", "").strip()
    if "." in h:
        cls, _, mth = h.rpartition(".")
        return cls.strip(), mth.strip()
    return "", h


def resolve_paths(args):
    if args.scan_json and args.findings_json:
        return args.scan_json, args.findings_json
    if not args.repo:
        sys.exit("--repo 또는 --scan-json/--findings-json 조합이 필요합니다.")
    base = os.path.join(ROOT, "state", args.repo, args.skill)
    if args.run_id:
        run_dir = os.path.join(base, args.run_id)
    else:
        cands = sorted(d for d in glob.glob(os.path.join(base, "*")) if os.path.isdir(d))
        if not cands:
            sys.exit(f"스캔 디렉터리 없음: {base}")
        run_dir = cands[-1]
    scan = os.path.join(run_dir, f"{args.skill}.json")
    if not os.path.exists(scan):
        c = glob.glob(os.path.join(run_dir, "*.json"))
        c = [p for p in c if not os.path.basename(p).startswith("findings_")]
        if not c:
            sys.exit(f"스캔 JSON 없음: {run_dir}")
        scan = c[0]
    fnd = glob.glob(os.path.join(run_dir, "findings_*.json"))
    if not fnd:
        sys.exit(f"findings JSON 없음: {run_dir}")
    return scan, fnd[0]


def main():
    ap = argparse.ArgumentParser(description="Auto-Scan 취약 엔드포인트의 finding 커버리지 대조")
    ap.add_argument("--repo")
    ap.add_argument("--skill", default="xss")
    ap.add_argument("--run-id")
    ap.add_argument("--scan-json")
    ap.add_argument("--findings-json")
    ap.add_argument("--strict", action="store_true",
                    help="누락 엔드포인트가 1건이라도 있으면 exit 1")
    ap.add_argument("--json", action="store_true", help="결과를 JSON으로 출력")
    args = ap.parse_args()

    scan_path, findings_path = resolve_paths(args)
    scan = json.load(open(scan_path, encoding="utf-8"))
    findings = json.load(open(findings_path, encoding="utf-8"))

    eps = collect_scan_endpoints(scan)
    if not eps:
        print(f"[SKIP] 엔드포인트 단위 취약 판정이 없어 대조 생략 ({os.path.relpath(scan_path, ROOT)})")
        return 0

    corpus, norm_paths = collect_finding_corpus(findings)

    covered, missing = [], []
    for ep in eps:
        hit = ""
        if ep["norm_path"] in norm_paths:
            hit = "path"
        elif ep["norm_path"].strip("/") and ep["norm_path"].strip("/") in corpus.lower():
            hit = "path-substr"
        else:
            cls, mth = handler_tokens(ep["handler"])
            if mth and len(mth) > 3 and mth in corpus:
                hit = "handler-method"
            elif cls and cls in corpus:
                hit = "handler-class"
        (covered if hit else missing).append({**ep, "hit": hit})

    total = len(eps)
    rate = (len(covered) / total * 100) if total else 100.0

    if args.json:
        print(json.dumps({
            "scan_json": os.path.relpath(scan_path, ROOT),
            "findings_json": os.path.relpath(findings_path, ROOT),
            "total_vuln_endpoints": total,
            "covered": len(covered),
            "missing": len(missing),
            "coverage_rate": round(rate, 1),
            "missing_endpoints": missing,
        }, ensure_ascii=False, indent=2))
    else:
        print("=" * 72)
        print(f"[ENDPOINT-COVERAGE] {os.path.relpath(findings_path, ROOT)}")
        print(f"  Auto-Scan 취약 엔드포인트 : {total}건")
        print(f"  finding에 언급됨          : {len(covered)}건 ({rate:.1f}%)")
        print(f"  언급 없음(분류 누락 의심)  : {len(missing)}건")
        if missing:
            print("-" * 72)
            print("  아래 엔드포인트는 확정(affected_files) / 제외(report_expand 제외 표) 어느 쪽으로도")
            print("  보고서에 나타나지 않는다. 전수 분류 후 해당 위치에 추가할 것.")
            print("  (finding_writing_guide.md §7 / task_23_xss_review.md Root Cause 검토 절차)")
            print("-" * 72)
            for m in missing:
                print(f"   - [{m['no'] or '-'}] {m['method']} {m['raw_path']}"
                      f"{('  — ' + m['handler']) if m['handler'] else ''}")
        print("=" * 72)

    if missing and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
