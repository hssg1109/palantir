#!/usr/bin/env python3
"""
add_system_code_col_to_plan.py — docs/ocb_scan_plan.md 체크리스트 표에 "시스템코드" 열 추가

대상: `:::expand 진단 체크리스트 전체 현황 ... :::` 블록 내부의 모든 표.
기존 헤더(10열): 레포 | 대내외 | INJ | XSS | FILE | DATA | SCA | 보고서 | Jira 티켓 | Fortify
신규 헤더(11열): 위 10열 + 시스템코드 (맨 끝에 추가)

주의: update_ocb_plan.py(SKILL_COL_IDX=3~7, REPORT_COL_IDX=8), build_service_history_table.py
(cols[:9] 고정 언팩), compare_ocb_audit.py(cells[0..4])가 인덱스 0~9를 고정 참조하므로
반드시 맨 끝(11번째)에 추가해야 회귀가 없다. 재실행 가능 — 이미 "시스템코드" 열이 있으면 값만 갱신.

사용법:
  python3 tools/add_system_code_col_to_plan.py
  python3 tools/sync_ocb_confluence.py --only scan_plan   # Confluence(750459063) 반영
"""
import re
import sys
from pathlib import Path

PALANTIR_DIR = Path(__file__).parent.parent
PLAN_PATH = PALANTIR_DIR / "docs" / "ocb_scan_plan.md"

sys.path.insert(0, str(PALANTIR_DIR / "tools"))
from system_code_lookup import build_repo_to_codes  # noqa: E402

HEADER_RE = re.compile(r"^\|\s*레포\s*\|.*\|\s*Fortify\s*\|")
SEP_RE = re.compile(r"^\|(\s*---\s*\|){10,}\s*$")
DATA_RE = re.compile(r"^\|\s*`([^`]+)`\s*\|")


def _append_cell(line: str, cell_text: str) -> str:
    """마지막 열 뒤에 새 셀을 추가한다 (기존 10열 → 11열).

    split("|")는 선행/후행 "|"로 인해 첫/끝 원소가 빈 문자열이 되므로,
    끝에서 두 번째 위치(마지막 실제 셀 뒤)에 새 셀을 삽입하면 파이프 구조가 깨지지 않는다.
    이미 11열(시스템코드 열 존재)이면 마지막 셀 값만 갱신 — 재실행 안전(idempotent).
    """
    cells = line.rstrip("\n").split("|")
    if len(cells) - 2 >= 11:
        cells[-2] = f" {cell_text} "
    else:
        cells = cells[:-1] + [f" {cell_text} "] + [cells[-1]]
    return "|".join(cells)


def main() -> int:
    repo_to_codes = build_repo_to_codes()
    text = PLAN_PATH.read_text(encoding="utf-8")
    lines = text.split("\n")

    block_start = block_end = None
    for i, line in enumerate(lines):
        if line.startswith(":::expand 진단 체크리스트 전체 현황"):
            block_start = i
        elif block_start is not None and line.strip() == ":::":
            block_end = i
            break

    if block_start is None or block_end is None:
        print("[ERROR] 체크리스트 블록(:::expand 진단 체크리스트 전체 현황 ... :::)을 찾지 못함")
        return 1

    n_header = n_sep = n_data = 0
    for i in range(block_start, block_end):
        line = lines[i]

        if HEADER_RE.match(line):
            lines[i] = _append_cell(line, "시스템코드")
            n_header += 1
            continue

        if SEP_RE.match(line):
            cells = line.rstrip("\n").split("|")
            if len(cells) - 2 >= 11:
                cells[-2] = "---"
            else:
                cells = cells[:-1] + ["---"] + [cells[-1]]
            lines[i] = "|".join(cells)
            n_sep += 1
            continue

        m = DATA_RE.match(line)
        if m:
            slug = m.group(1)
            codes = repo_to_codes.get(slug, [])
            code_cell = "—" if not codes else ", ".join(f"`{c}`" for c in codes)
            lines[i] = _append_cell(line, code_cell)
            n_data += 1

    PLAN_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OK] {PLAN_PATH} 갱신 완료")
    print(f"  헤더 행 {n_header}개 / 구분선 행 {n_sep}개 / 데이터 행 {n_data}개 처리")
    return 0


if __name__ == "__main__":
    sys.exit(main())
