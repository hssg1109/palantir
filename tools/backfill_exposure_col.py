#!/usr/bin/env python3
"""
backfill_exposure_col.py — docs/ocb_scan_plan.md 체크리스트 '대내외' 컬럼 백필

배경 (2026-09-15): classify_exposure.py가 docs/service_inventory.json에 exposure
분류 결과를 생성하지만, 그 결과를 ocb_scan_plan.md 체크리스트 표에 반영하는 절차가
없었다 — Fortify(backfill_fortify_flags.py)와 달리 이 컬럼만 자동 동기화 스크립트가
빠져 있었음. 2026-08-12 P3-A~H 60레포 일괄 추가 시 전부 '❓ 미확인'으로 삽입된 뒤
한 번도 채워지지 않은 것이 원인 (clone_repo.py 절차와는 무관 — 이 스크립트는 애초에
대내외 컬럼을 다루지 않는다).

동작: '❓ 미확인' 행 중 service_inventory.json에 exposure(external/internal/hybrid)가
확정된 레포만 아이콘으로 교체한다. inventory에도 unknown인 행은 건드리지 않는다
(대부분 testbed 없이 이름 패턴만으로는 판단 불가 — 수동 검토 필요).

사용법:
    python3 tools/backfill_exposure_col.py            # 적용
    python3 tools/backfill_exposure_col.py --dry-run   # 변경될 행만 미리보기
"""

import argparse
import json
import re
import sys
from pathlib import Path

PALANTIR_DIR = Path(__file__).parent.parent
PLAN_MD      = PALANTIR_DIR / "docs" / "ocb_scan_plan.md"
INVENTORY    = PALANTIR_DIR / "docs" / "service_inventory.json"

_ICON = {"external": "🌐 대외", "internal": "🔒 대내", "hybrid": "↔️ 대내외"}
_ROW_RE = re.compile(r"^(\| `([^`]+)` \| )([^|]+)( \|)", re.MULTILINE)
_CHECKLIST_BLOCK_RE = re.compile(
    r'^:::expand 진단 체크리스트 전체 현황.*?\n(.*?)\n:::\s*$', re.DOTALL | re.MULTILINE
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    inv_raw = json.loads(INVENTORY.read_text(encoding="utf-8"))["services"]
    inv = {s["repo"]: s for s in inv_raw}

    text = PLAN_MD.read_text(encoding="utf-8")

    block_m = _CHECKLIST_BLOCK_RE.search(text)
    if not block_m:
        print("[ERROR] 체크리스트 expand 블록을 찾을 수 없음", file=sys.stderr)
        return 1
    block_start, block_end = block_m.span(1)
    checklist_body = block_m.group(1)

    resolved, still_unknown = [], []

    def _repl(m: re.Match) -> str:
        prefix, repo, col, suffix = m.group(1), m.group(2), m.group(3), m.group(4)
        if "미확인" not in col:
            return m.group(0)
        entry = inv.get(repo)
        exposure = entry.get("exposure") if entry else None
        if not entry or exposure not in _ICON:
            still_unknown.append(repo)
            return m.group(0)
        resolved.append((repo, _ICON[exposure], entry.get("confidence")))
        return f"{prefix}{_ICON[exposure]}{suffix}"

    new_checklist_body = _ROW_RE.sub(_repl, checklist_body)
    new_text = text[:block_start] + new_checklist_body + text[block_end:]

    print(f"채울 수 있음: {len(resolved)}건")
    for repo, icon, conf in resolved:
        print(f"  {repo:30s} -> {icon}  (confidence={conf})")
    print(f"\ninventory에도 미확인(수동 검토 필요): {len(still_unknown)}건")
    for repo in still_unknown:
        print(f"  {repo}")

    if args.dry_run:
        print("\n[DRY-RUN] 파일 변경 없음")
        return 0

    if resolved:
        PLAN_MD.write_text(new_text, encoding="utf-8")
        print(f"\n[OK] docs/ocb_scan_plan.md — {len(resolved)}개 행 갱신 완료")
    else:
        print("\n[INFO] 갱신할 행 없음")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
