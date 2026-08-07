#!/usr/bin/env python3
"""
backfill_fortify_flags.py — docs/ocb_scan_plan.md 체크리스트에 "Fortify" 열 추가 +
122개 레포 전체에 대해 과거 Fortify 정기진단 여부를 소급 반영한다.

1. 구조 변경: 11개 서브섹션(P1-A~P2-K) 헤더/구분선에 공통으로 "Fortify" 열 추가
   (모든 섹션이 완전히 동일한 헤더/구분선 문자열을 쓰므로 str.replace 1회로 전체 반영)
2. 값 반영: :::expand ... ::: 체크리스트 블록 내 각 데이터 행에 대해
   load_repo_project_map() + find_fortify_ticket()으로 Fortify 매칭 여부를 조회해
   [JIRA:FORTIFY-nnnn] 또는 — 셀을 행 끝에 추가.
   (블록 밖의 '## 2. 서비스 그룹별 레포 목록' 표는 레포 슬러그로 시작하는 행 패턴이
   같아 보일 수 있으나, 값 반영은 반드시 체크리스트 블록 범위로 한정한다.)

사용법:
    python3 tools/backfill_fortify_flags.py              # dry-run (기본, 파일 미변경)
    python3 tools/backfill_fortify_flags.py --execute    # 실제로 ocb_scan_plan.md 갱신

필요 환경변수: jira_utils.load_env() 참고 (JIRA_URL, JIRA_TOKEN, ...)
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.jira_utils import load_env, load_repo_project_map, find_fortify_ticket

PALANTIR_DIR = Path(__file__).resolve().parent.parent
SCAN_PLAN = PALANTIR_DIR / "docs" / "ocb_scan_plan.md"

OLD_HEADER = "| 레포 | ↔️ 대내외 | INJ | XSS | FILE | DATA | SCA | 보고서 | Jira 티켓 |"
NEW_HEADER = "| 레포 | ↔️ 대내외 | INJ | XSS | FILE | DATA | SCA | 보고서 | Jira 티켓 | Fortify |"
OLD_SEP    = "|---|---|---|---|---|---|---|---|---|"
NEW_SEP    = "|---|---|---|---|---|---|---|---|---|---|"

CHECKLIST_RE = re.compile(
    r'^:::expand 진단 체크리스트 전체 현황.*?\n(.*?)\n:::\s*$',
    re.DOTALL | re.MULTILINE,
)
DATA_ROW_RE = re.compile(r'^\| `([^`]+)`')


def _compute_fortify_cells(block: str, repo_to_project: dict, env: dict, jira_url: str) -> dict[str, tuple[str, str]]:
    """체크리스트 블록 내 데이터 행 repo마다 (셀 값, 판정 사유) 계산."""
    results: dict[str, tuple[str, str]] = {}
    for line in block.splitlines():
        m = DATA_ROW_RE.match(line)
        if not m:
            continue
        repo = m.group(1)
        if repo in results:
            continue
        project_key = repo_to_project.get(repo)
        if not project_key:
            results[repo] = ("—", "매핑없음")
            continue
        fortify_key = find_fortify_ticket(env, jira_url, project_key, repo)
        if fortify_key:
            results[repo] = (f"[JIRA:{fortify_key}]", "매칭")
        else:
            results[repo] = ("—", "미매칭")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="ocb_scan_plan.md에 Fortify 진단 여부 열 추가 + 소급 반영")
    parser.add_argument("--execute", action="store_true", help="실제로 파일 갱신 (미지정 시 dry-run)")
    args = parser.parse_args()

    env = load_env()
    jira_url = env.get("JIRA_URL", "").rstrip("/")
    if not jira_url or not env.get("JIRA_TOKEN"):
        print("[ERROR] .env에 JIRA_URL/JIRA_TOKEN이 없습니다.")
        return 1

    text = SCAN_PLAN.read_text(encoding="utf-8")

    if OLD_HEADER not in text:
        print("[ERROR] 예상 헤더 문자열을 찾지 못했습니다 — 이미 변경되었거나 파일 구조가 다릅니다.")
        return 1
    if NEW_HEADER in text:
        print("[WARN] 이미 Fortify 열이 추가되어 있는 것으로 보입니다. 계속 진행합니다.")

    m = CHECKLIST_RE.search(text)
    if not m:
        print("[ERROR] 체크리스트 expand 블록을 찾을 수 없습니다.")
        return 1
    block = m.group(1)

    repo_to_project = load_repo_project_map()
    print(f"[INFO] 프로젝트 키 매핑 {len(repo_to_project)}건")
    print(f"[INFO] 모드: {'EXECUTE (실제 파일 갱신)' if args.execute else 'DRY-RUN (미리보기만)'}")
    print()

    fortify_cells = _compute_fortify_cells(block, repo_to_project, env, jira_url)

    n_matched, n_no_map, n_no_match = 0, 0, 0
    for repo, (cell_value, reason) in fortify_cells.items():
        if reason == "매핑없음":
            print(f"[SKIP ] {repo:35s} — §2 프로젝트 키 매핑 없음 -> {cell_value}")
            n_no_map += 1
        elif reason == "미매칭":
            print(f"[  —  ] {repo:35s} — Fortify 매칭 티켓 없음 -> {cell_value}")
            n_no_match += 1
        else:
            print(f"[MATCH] {repo:35s} -> {cell_value}")
            n_matched += 1

    print()
    print("=" * 60)
    print(f"  총 레포: {len(fortify_cells)}건")
    print(f"  Fortify 매칭: {n_matched}건")
    print(f"  매핑 없음: {n_no_map}건")
    print(f"  미매칭(—): {n_no_match}건")
    if not args.execute:
        print("  (dry-run — 실제 반영하려면 --execute 옵션 추가)")
    print("=" * 60)

    if not args.execute:
        return 0

    # 1) 구조 변경: 헤더/구분선 (11개 섹션 전체 동시 반영, 체크리스트 블록에만 등장하는
    #    고유 문자열이므로 전체 텍스트에 대해 replace해도 안전)
    new_text = text.replace(OLD_HEADER, NEW_HEADER).replace(OLD_SEP, NEW_SEP)

    # 2) 값 반영: 체크리스트 블록 범위 내 데이터 행에만 Fortify 셀 추가
    #    (§2 서비스 그룹별 레포 목록 표는 블록 밖이므로 절대 건드리지 않음)
    m2 = CHECKLIST_RE.search(new_text)
    if not m2:
        print("[ERROR] 구조 변경 후 체크리스트 블록을 다시 찾지 못했습니다 — 파일을 갱신하지 않았습니다.")
        return 1
    block2 = m2.group(1)
    new_block_lines = []
    for line in block2.splitlines():
        dm = DATA_ROW_RE.match(line)
        if dm and dm.group(1) in fortify_cells:
            cell_value, _ = fortify_cells[dm.group(1)]
            line = line.rstrip() + f" {cell_value} |"
        new_block_lines.append(line)
    new_block = "\n".join(new_block_lines)
    new_text = new_text[:m2.start(1)] + new_block + new_text[m2.end(1):]

    SCAN_PLAN.write_text(new_text, encoding="utf-8")
    print(f"[OK] {SCAN_PLAN} 갱신 완료")
    return 0


if __name__ == "__main__":
    sys.exit(main())
