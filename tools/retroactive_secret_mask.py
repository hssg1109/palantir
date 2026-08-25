"""
retroactive_secret_mask.py — state/**/findings_*.json 내 미마스킹 자격증명 소급 마스킹.

2026-08-18 사고 재발방지: scan_data_protection.py가 evidence.code_snippet을
생성할 때 원본 소스 텍스트를 마스킹 없이 그대로 캡처해왔고, 이 값이
description/review_note/recommendation/report_expand 등에도 그대로 인용되면서
17개+ 레포의 findings_*.json에 실제 자격증명 원문이 남은 채 이미 Confluence에
게시됐다. 이 스크립트는 shared/scripts/secret_gate.py(공용 게이트)를 이용해
state/ 전체 findings_*.json 파일을 스캔하고, 위반이 있는 파일의 대상 필드를
[REDACTED]로 치환한다.

사용법:
    python3 tools/retroactive_secret_mask.py --scan-only   # 위반 파일/건수만 보고, 수정 없음
    python3 tools/retroactive_secret_mask.py --apply        # 실제 마스킹 적용 + 재검증

원문 시크릿 값은 이 스크립트의 어떤 출력에도 노출되지 않는다 (파일 경로/필드명/건수만 출력).
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

PALANTIR_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PALANTIR_DIR / "shared" / "scripts"))
import secret_gate  # noqa: E402

def _mask_recursive(obj):
    """JSON 구조 전체(dict/list/str)를 재귀 순회하며 모든 문자열 리프에 mask_text 적용.
    스캐너 버전마다 evidence가 str/dict로 스키마가 갈리는 등 필드 구조 편차가 있어
    특정 필드명을 하드코딩하지 않고 전체를 순회한다 (fp_reason/evidence_trail 포함).
    치환 총 건수 반환. obj는 in-place로 변경된다."""
    total = 0
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and v:
                masked, n = secret_gate.mask_text(v)
                if n:
                    obj[k] = masked
                    total += n
            elif isinstance(v, (dict, list)):
                total += _mask_recursive(v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str) and v:
                masked, n = secret_gate.mask_text(v)
                if n:
                    obj[i] = masked
                    total += n
            elif isinstance(v, (dict, list)):
                total += _mask_recursive(v)
    return total


def process_file(fp: Path, apply: bool) -> tuple[int, int]:
    """(치환건수, 재검증후잔존위반건수) 반환. apply=False면 dry-run(치환건수만 계산, 저장 안 함)."""
    try:
        text = fp.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return 0, 0

    before_hits = secret_gate.scan_text(text)
    if not before_hits:
        return 0, 0

    try:
        data = json.loads(text)
    except Exception:
        print(f"  [SKIP] JSON 파싱 실패 — 수동 확인 필요: {fp}")
        return 0, len(before_hits)

    total = _mask_recursive(data)

    if not apply:
        return total, 0

    if total > 0:
        fp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    after_text = fp.read_text(encoding="utf-8", errors="ignore")
    after_hits = secret_gate.scan_text(after_text)
    return total, len(after_hits)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true", help="실제 마스킹 적용 (기본: dry-run)")
    ap.add_argument("--scan-only", action="store_true", help="위반 파일/건수만 보고")
    args = ap.parse_args()
    apply = args.apply and not args.scan_only

    files = sorted(glob.glob(str(PALANTIR_DIR / "state" / "**" / "findings_*.json"), recursive=True))
    flagged = 0
    remaining = 0
    for fp_str in files:
        fp = Path(fp_str)
        n_masked, n_remaining = process_file(fp, apply)
        if n_masked or n_remaining:
            flagged += 1
            repo = fp.relative_to(PALANTIR_DIR / "state").parts[0]
            status = "APPLIED" if apply else "DRY-RUN"
            print(f"[{status}] {repo:30s} {fp.relative_to(PALANTIR_DIR)}  masked={n_masked}  remaining_after={n_remaining}")
            remaining += n_remaining

    print(f"\n스캔 파일: {len(files)}  위반 발견 파일: {flagged}  {'적용 후 잔존 위반' if apply else '적용시 예상 치환 건수 합계'}: {remaining if apply else '(dry-run — --apply로 실행)'}")
    if apply and remaining > 0:
        print("[WARN] 마스킹 후에도 위반이 남은 파일이 있습니다 — 위 목록에서 remaining_after > 0 인 파일을 수동 확인하세요.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
