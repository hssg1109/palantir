#!/usr/bin/env python3
"""
sync_ocb_confluence.py — OCB 진단 현황 관련 Confluence 페이지 일괄 동기화

동기화 대상:
  docs/ocb_scan_plan.md            → pageId=746439687 (보안진단 체크리스트 전체 현황)
  docs/llm_data_cleansing_registry.md → pageId=750095285 (LLM 클렌징 레지스트리)

인증: .env의 CONFLUENCE_TOKEN (Personal Access Token, Bearer 방식)
네트워크: wiki.skplanet.com 사내망 전용 → Windows PowerShell 경유 (WSL 자동 우회)

사용법:
  python3 tools/sync_ocb_confluence.py            # 두 페이지 모두 갱신
  python3 tools/sync_ocb_confluence.py --dry-run  # API 호출 없이 변환 결과만 출력
  python3 tools/sync_ocb_confluence.py --only scan_plan  # 체크리스트만
  python3 tools/sync_ocb_confluence.py --only cleansing  # 클렌징 레지스트리만
"""

import argparse
import sys
from pathlib import Path

PALANTIR_DIR = Path(__file__).parent.parent

# publish 함수 import
sys.path.insert(0, str(PALANTIR_DIR / "tools"))
from publish_confluence import publish, _load_env, _load_registry, _save_registry

TARGETS = [
    {
        "key":     "scan_plan",
        "md_path": PALANTIR_DIR / "docs" / "ocb_scan_plan.md",
        "page_id": "746439687",
        "title":   "OCB 서비스 군 보안진단 체크리스트 전체 현황",
    },
    {
        "key":     "cleansing",
        "md_path": PALANTIR_DIR / "docs" / "llm_data_cleansing_registry.md",
        "page_id": "750095285",
        "title":   "LLM 데이터 클렌징 이력 레지스트리",
    },
]


def main() -> int:
    parser = argparse.ArgumentParser(description="OCB Confluence 페이지 일괄 동기화")
    parser.add_argument("--dry-run", action="store_true", help="API 호출 없이 변환 결과만 출력")
    parser.add_argument("--only", choices=["scan_plan", "cleansing"],
                        default=None, help="특정 페이지만 동기화")
    args = parser.parse_args()

    env = _load_env()
    base_url  = env.get("CONFLUENCE_BASE_URL", "https://wiki.skplanet.com").rstrip("/")
    token     = env.get("CONFLUENCE_TOKEN", "")
    space_key = env.get("CONFLUENCE_SPACE_KEY", "SECDIG")

    if not token:
        print("[ERROR] CONFLUENCE_TOKEN이 .env에 없습니다.", file=sys.stderr)
        return 1

    targets = [t for t in TARGETS if args.only is None or t["key"] == args.only]
    reg = _load_registry()
    errors = 0

    for t in targets:
        md_path = t["md_path"]
        if not md_path.exists():
            print(f"[SKIP] 파일 없음: {md_path}", file=sys.stderr)
            errors += 1
            continue

        print(f"\n{'[DRY-RUN] ' if args.dry_run else ''}▶ {md_path.name} → pageId={t['page_id']}")

        result = publish(
            md_path   = md_path,
            title     = t["title"],
            parent_id = None,
            page_id   = t["page_id"],
            space_key = space_key,
            base_url  = base_url,
            token     = token,
            dry_run   = args.dry_run,
        )

        if result and not args.dry_run:
            reg_key = str(md_path.relative_to(PALANTIR_DIR))
            reg[reg_key] = result
        elif not result and not args.dry_run:
            errors += 1

    if not args.dry_run:
        _save_registry(reg)

    print(f"\n{'완료' if errors == 0 else f'오류 {errors}건'} — {len(targets)}개 페이지 처리")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
