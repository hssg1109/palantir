#!/usr/bin/env python3
"""
sync_ocb_confluence.py — OCB 진단 현황 관련 Confluence 페이지 일괄 동기화

동기화 대상:
  docs/ocb_scan_plan.md (체크리스트 expand 블록만 추출) → pageId=<YOUR_CHECKLIST_PAGE_ID> (26년 진단결과)
  docs/llm_data_cleansing_registry.md                  → pageId=<YOUR_REGISTRY_PAGE_ID> (LLM 클렌징 레지스트리)

# 2026-07-22: scan_plan 타겟은 전체 문서가 아닌 ":::expand 진단 체크리스트 전체 현황" 블록만
# 추출하여 반영한다 (체크리스트 표만 별도 페이지에서 유지하기 위함). 기존 대상 페이지는
# 폐기하고 신규 페이지로 이관했으며, 페이지 제목은 덮어쓰지 않는다(title=None → 기존 제목 유지).

인증: .env의 CONFLUENCE_TOKEN (Personal Access Token, Bearer 방식)
네트워크: wiki.skplanet.com 사내망 전용 → Windows PowerShell 경유 (WSL 자동 우회)

사용법:
  python3 tools/sync_ocb_confluence.py            # 두 페이지 모두 갱신
  python3 tools/sync_ocb_confluence.py --dry-run  # API 호출 없이 변환 결과만 출력
  python3 tools/sync_ocb_confluence.py --only scan_plan  # 체크리스트만
  python3 tools/sync_ocb_confluence.py --only cleansing  # 클렌징 레지스트리만
"""

import argparse
import re
import sys
import tempfile
from pathlib import Path

PALANTIR_DIR = Path(__file__).parent.parent

# publish 함수 import
sys.path.insert(0, str(PALANTIR_DIR / "tools"))
from publish_confluence import publish, _load_env, _load_registry, _save_registry

_CHECKLIST_RE = re.compile(
    r'^:::expand 진단 체크리스트 전체 현황.*?\n(.*?)\n:::\s*$',
    re.DOTALL | re.MULTILINE,
)


def _extract_checklist_section(md_text: str) -> str:
    """docs/ocb_scan_plan.md 전체 중 ':::expand 진단 체크리스트 전체 현황' 블록만 추출.

    750459063 페이지는 전체 진단 계획 문서가 아니라 체크리스트 표만 유지하는 용도이므로,
    원본 문서가 갱신될 때마다 이 블록만 뽑아 별도 페이지로 반영한다.
    """
    m = _CHECKLIST_RE.search(md_text)
    if not m:
        raise RuntimeError(
            "체크리스트 expand 블록을 찾을 수 없음 — docs/ocb_scan_plan.md 구조가 "
            "변경되었는지 확인 필요 (':::expand 진단 체크리스트 전체 현황' 헤더 기준 탐색)"
        )
    return (
        "# OCB 서비스 군 보안진단 체크리스트 전체 현황\n\n"
        f"{m.group(1)}\n\n"
        "---\n"
        "*자동 동기화: `tools/sync_ocb_confluence.py` (원본: `docs/ocb_scan_plan.md`)*\n"
    )


TARGETS = [
    {
        "key":     "scan_plan",
        "md_path": PALANTIR_DIR / "docs" / "ocb_scan_plan.md",
        "page_id": "750459063",
        "title":   None,  # 페이지 제목은 덮어쓰지 않고 기존 제목("26년 진단결과") 유지
        "extract": _extract_checklist_section,
    },
    {
        "key":     "cleansing",
        "md_path": PALANTIR_DIR / "docs" / "llm_data_cleansing_registry.md",
        "page_id": "750095285",
        "title":   "LLM 데이터 클렌징 이력 레지스트리",
        "extract": None,
    },
]


def main() -> int:
    parser = argparse.ArgumentParser(description="OCB Confluence 페이지 일괄 동기화")
    parser.add_argument("--dry-run", action="store_true", help="API 호출 없이 변환 결과만 출력")
    parser.add_argument("--only", choices=["scan_plan", "cleansing"],
                        default=None, help="특정 페이지만 동기화")
    parser.add_argument("--force", action="store_true",
                        help="라이브 페이지 대비 row 축소 감지 가드를 무시하고 강제 덮어쓰기")
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

    tmp_files: list[Path] = []  # 추출본 임시 파일 — 종료 시 정리
    try:
        for t in targets:
            md_path = t["md_path"]
            if not md_path.exists():
                print(f"[SKIP] 파일 없음: {md_path}", file=sys.stderr)
                errors += 1
                continue

            extract_fn = t.get("extract")
            if extract_fn:
                try:
                    extracted = extract_fn(md_path.read_text(encoding="utf-8"))
                except RuntimeError as e:
                    print(f"[ERROR] {t['key']} 추출 실패: {e}", file=sys.stderr)
                    errors += 1
                    continue
                tmp = Path(tempfile.mkstemp(suffix=f"_{t['key']}.md")[1])
                tmp.write_text(extracted, encoding="utf-8")
                tmp_files.append(tmp)
                publish_path = tmp
                reg_key_path = md_path  # 레지스트리 키는 원본 경로 기준 유지
            else:
                publish_path = md_path
                reg_key_path = md_path

            print(f"\n{'[DRY-RUN] ' if args.dry_run else ''}▶ {md_path.name}"
                  f"{' (체크리스트 블록만 추출)' if extract_fn else ''} → pageId={t['page_id']}")

            result = publish(
                md_path   = publish_path,
                title     = t["title"],
                parent_id = None,
                page_id   = t["page_id"],
                space_key = space_key,
                base_url  = base_url,
                token     = token,
                dry_run   = args.dry_run,
                force     = args.force,
            )

            if result and not args.dry_run:
                reg_key = str(reg_key_path.relative_to(PALANTIR_DIR))
                reg[reg_key] = result
            elif not result and not args.dry_run:
                errors += 1
    finally:
        for tmp in tmp_files:
            tmp.unlink(missing_ok=True)

    if not args.dry_run:
        _save_registry(reg)

    print(f"\n{'완료' if errors == 0 else f'오류 {errors}건'} — {len(targets)}개 페이지 처리")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
