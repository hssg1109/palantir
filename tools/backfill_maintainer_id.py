#!/usr/bin/env python3
"""
backfill_maintainer_id.py — 손상된 repo_meta.json의 maintainer 필드를 사번 포함 형식으로 복구.

clone_repo.py::_normalize_maintainer_label()이 Jira user/search API 응답의
displayName(이미 "이름(영문)/팀/SKP" 완성형)에 "/미확인/SKP"를 중복 추가하고,
실제 Jira 계정명(name 필드 — 사번)을 캡처하지 않던 버그가 있었다(2026-09-04 수정).

이 스크립트는 이미 존재하는(그러나 손상된) repo_meta.json을 재clone/testbed 없이
그 자리에서 수정한다 — backfill_repo_meta.py(누락 전용, 재clone 필요)와는 별개 도구.

사용법:
    python3 tools/backfill_maintainer_id.py            # /미확인/SKP 패턴 전체 재탐색 후 처리
    python3 tools/backfill_maintainer_id.py --repo <repo>   # 단일 레포만
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PALANTIR_DIR = Path(__file__).resolve().parent.parent
STATE_DIR = PALANTIR_DIR / "state"

sys.path.insert(0, str(PALANTIR_DIR / "tools"))
from clone_repo import _normalize_maintainer_label  # noqa: E402

_EMAIL_RE = re.compile(r"<([^>]+)>")
_CORRUPTED_MARK = "/미확인/SKP"


def _find_corrupted_repos() -> list[str]:
    targets = []
    for meta_path in sorted(STATE_DIR.glob("*/repo_meta.json")):
        try:
            text = meta_path.read_text(encoding="utf-8")
        except Exception:
            continue
        if _CORRUPTED_MARK in text:
            targets.append(meta_path.parent.name)
    return targets


def backfill_one(repo: str) -> str:
    meta_path = STATE_DIR / repo / "repo_meta.json"
    if not meta_path.exists():
        print(f"[FAIL-없음] {repo} — repo_meta.json 없음")
        return "fail"

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    maintainer = meta.get("maintainer") or ""

    if _CORRUPTED_MARK not in maintainer:
        print(f"[SKIP-이미정상] {repo} — 손상 패턴 없음")
        return "skip"

    m = _EMAIL_RE.search(maintainer)
    if not m:
        print(f"[FAIL-이메일추출실패] {repo} — maintainer='{maintainer}'")
        return "fail"
    email = m.group(1).strip()

    # displayName은 이미 확보되어 있었던 값이므로 name(사번 원본 표기)은 불필요 —
    # _normalize_maintainer_label 재호출 시 name 인자는 참고용 폴백일 뿐이라 빈 문자열로 충분.
    new_label, _, status = _normalize_maintainer_label("", email)

    if _CORRUPTED_MARK in new_label:
        print(f"[FAIL-사번미확보] {repo} — 재조회에도 동일 패턴 지속 (Jira API 실패 가능): '{new_label}'")
        return "fail"

    meta["maintainer"] = new_label
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] {repo} — '{maintainer}' → '{new_label}' (status={status})")
    return "ok"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", help="단일 레포만 처리")
    args = parser.parse_args()

    targets = [args.repo] if args.repo else _find_corrupted_repos()
    if not targets:
        print("[OK] 손상된(/미확인/SKP) repo_meta.json 없음")
        return 0

    print(f"[대상] {len(targets)}개 레포")
    print("=" * 60)
    counts = {"ok": 0, "skip": 0, "fail": 0}
    for repo in targets:
        counts[backfill_one(repo)] += 1
        print("-" * 60)

    print(f"\n완료: OK {counts['ok']}건 / SKIP {counts['skip']}건 / FAIL {counts['fail']}건")
    return 0 if counts["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
