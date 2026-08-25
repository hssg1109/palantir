#!/usr/bin/env python3
"""
redact_live_jira_issue.py — 라이브 Jira 이슈 description 내 미마스킹 자격증명 소급 마스킹.

2026-08-18 사고 재발방지 작업의 일부: 로컬 캐시(palantir-jira-gateway/data/tickets/*.json)를
신뢰하지 않고, 항상 라이브 이슈를 재조회(GET)한 뒤 shared/scripts/secret_gate.py로
검사·마스킹하고 PUT으로 갱신한다. 원문 시크릿 값은 이 스크립트의 어떤 출력에도
노출되지 않는다 (이슈 키/필드명/위반 건수만 출력).

사용법:
    python3 tools/redact_live_jira_issue.py --issue-key SECUFINDINGS-2151            # scan-only (기본, PUT 없음)
    python3 tools/redact_live_jira_issue.py --issue-key SECUFINDINGS-2151 --apply    # 실제 PUT 갱신
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import requests

PALANTIR_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PALANTIR_DIR / "tools"))
sys.path.insert(0, str(PALANTIR_DIR / "shared" / "scripts"))
from jira_utils import load_env, jira_headers  # noqa: E402
import secret_gate  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--issue-key", required=True, help="예: SECUFINDINGS-2151")
    ap.add_argument("--apply", action="store_true", help="실제 PUT 갱신 (기본: scan-only)")
    args = ap.parse_args()

    env = load_env()
    base = env["JIRA_URL"].rstrip("/")
    headers = jira_headers(env)

    r = requests.get(
        f"{base}/rest/api/2/issue/{args.issue_key}",
        params={"fields": "description,summary,status"},
        headers=headers,
        timeout=30,
    )
    if r.status_code != 200:
        print(f"[ERROR] 라이브 조회 실패 HTTP {r.status_code}: {args.issue_key}")
        return 1

    fields = r.json().get("fields", {})
    desc = fields.get("description") or ""
    status = (fields.get("status") or {}).get("name", "?")

    before_hits = secret_gate.scan_text(desc)
    print(f"[{args.issue_key}] status={status} 위반 {len(before_hits)}건")
    for h in before_hits:
        print("   ", h)

    if not before_hits:
        print("[SKIP] 위반 없음 — 조치 불필요")
        return 0

    masked, count = secret_gate.mask_text(desc)

    after_hits = secret_gate.scan_text(masked)
    if after_hits:
        print(f"[ERROR] 마스킹 후에도 위반 {len(after_hits)}건 잔존 — 수동 확인 필요, PUT 중단")
        return 1

    print(f"[MASK] {count}건 치환 완료, 재검증 0건 통과")

    if not args.apply:
        print("[DRY-RUN] --apply 없이 실행됨 — PUT 미수행")
        return 0

    put = requests.put(
        f"{base}/rest/api/2/issue/{args.issue_key}",
        json={"fields": {"description": masked}},
        headers=headers,
        timeout=30,
    )
    if put.status_code not in (200, 204):
        print(f"[ERROR] PUT 실패 HTTP {put.status_code}: {put.text[:300]}")
        return 1

    print(f"[OK] {args.issue_key} description 갱신 완료 (라이브 반영)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
