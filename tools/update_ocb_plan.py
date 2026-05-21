#!/usr/bin/env python3
"""
update_ocb_plan.py — OCB 진단 체크리스트 갱신 + Confluence 동기화

사용법:
    # state/ 자동 스캔 → 완료 항목 체크리스트 갱신 + Confluence 동기화 (권장)
    python3 tools/update_ocb_plan.py --auto

    # 특정 repo/skill 수동 완료 표시 후 Confluence 갱신
    python3 tools/update_ocb_plan.py --done ocb-webview-api injection
    python3 tools/update_ocb_plan.py --done ocb-webview-api xss file data sca

    # Confluence만 갱신 (체크리스트 변경 없이)
    python3 tools/update_ocb_plan.py --sync

    # 현재 완료 현황 출력
    python3 tools/update_ocb_plan.py --status

동작 (--auto):
    1. state/<skill>/<repo>/<timestamp>/ 에서 findings_*.json 존재 확인
    2. 완료된 항목의 체크리스트 셀 ❌/🔄 → ✅ YYYY-MM-DD 로 갱신
    3. publish_confluence.py 호출 → Confluence 페이지 갱신

완료 기준:
    findings_INJ.json  → INJ 컬럼 완료
    findings_XSS.json  → XSS 컬럼 완료
    findings_FILE.json → FILE 컬럼 완료
    findings_DATA.json → DATA 컬럼 완료
    findings_SCA.json  → SCA 컬럼 완료
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PALANTIR_DIR  = Path(__file__).parent.parent
PLAN_MD       = PALANTIR_DIR / "docs" / "ocb_scan_plan.md"
STATE_DIR     = PALANTIR_DIR / "state"
STATUS_JSON   = PALANTIR_DIR / "docs" / ".ocb_scan_status.json"

VALID_SKILLS  = ["injection", "xss", "file", "data", "sca"]

# skill → findings 파일명 매핑
SKILL_FINDINGS = {
    "injection": "findings_INJ.json",
    "xss":       "findings_XSS.json",
    "file":      "findings_FILE.json",
    "data":      "findings_DATA.json",
    "sca":       "findings_SCA.json",
}

# 체크리스트 테이블의 컬럼 인덱스 (split("|") 기준)
# "| `repo` | INJ | XSS | FILE | DATA | SCA |" → split 시 cells[0]=""(공백), cells[1]=repo, cells[2]=INJ ...
SKILL_COL_IDX = {"injection": 2, "xss": 3, "file": 4, "data": 5, "sca": 6}

# Confluence 페이지 제목
CF_TITLE     = "OCB 서비스 군 보안 진단 계획"
CF_PARENT_ID = "722832415"


# ── 상태 파일 ─────────────────────────────────────────────────────────────────

def _load_status() -> dict:
    if STATUS_JSON.exists():
        return json.loads(STATUS_JSON.read_text(encoding="utf-8"))
    return {"completed": {}, "last_updated": None}


def _save_status(status: dict) -> None:
    status["last_updated"] = datetime.now().isoformat()
    STATUS_JSON.write_text(
        json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8"
    )


# ── 체크박스 갱신 ─────────────────────────────────────────────────────────────

def mark_done(repo: str, skills: list[str], date: str | None = None) -> int:
    """
    ocb_scan_plan.md 내 해당 repo + skill 체크리스트 셀을 완료로 변경.
    date: YYYY-MM-DD 형식. 미지정 시 오늘 날짜.
    반환: 변경된 셀 수.
    """
    if not date:
        date = datetime.now().strftime("%Y-%m-%d")
    done_mark = f"✅ {date}"

    text = PLAN_MD.read_text(encoding="utf-8")
    changed = 0

    lines = text.splitlines()
    new_lines = []
    for line in lines:
        if f"`{repo}`" in line and "|" in line:
            cells = line.split("|")
            for skill in skills:
                idx = SKILL_COL_IDX.get(skill)
                if idx and idx < len(cells):
                    cell = cells[idx].strip()
                    if "❌" in cell or "🔄" in cell:
                        cells[idx] = f" {done_mark} "
                        changed += 1
            line = "|".join(cells)
        new_lines.append(line)
    text = "\n".join(new_lines)

    if changed > 0:
        PLAN_MD.write_text(text, encoding="utf-8")
    return changed


# ── state/ 자동 스캔 ──────────────────────────────────────────────────────────

def sync_from_state(no_sync: bool = False) -> int:
    """
    state/<repo>/<skill>/<timestamp>/ 에서 findings_*.json 존재 여부로
    완료된 진단을 감지해 체크리스트를 자동 갱신한다.

    반환: 갱신된 (repo, skill) 쌍 수.
    """
    status     = _load_status()
    total      = 0
    changed_md = False

    for repo_dir in sorted(STATE_DIR.iterdir()):
        if not repo_dir.is_dir() or repo_dir.name.startswith("."):
            continue
        repo_slug = repo_dir.name

        for skill in VALID_SKILLS:
            skill_dir = repo_dir / skill
            if not skill_dir.exists():
                continue

            findings_file = SKILL_FINDINGS[skill]

            # 이미 완료로 기록된 경우 건너뜀
            already = status.get("completed", {}).get(repo_slug, {}).get(skill)
            if already:
                continue

            # 타임스탬프 디렉터리를 최신순으로 탐색
            ts_dirs = sorted(
                [d for d in skill_dir.iterdir() if d.is_dir()],
                reverse=True,
            )
            for ts_dir in ts_dirs:
                if (ts_dir / findings_file).exists():
                    # YYYYMMDD_HHMM → YYYY-MM-DD
                    ts = ts_dir.name
                    try:
                        date_str = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
                    except Exception:
                        date_str = datetime.now().strftime("%Y-%m-%d")

                    n = mark_done(repo_slug, [skill], date=date_str)
                    if n > 0:
                        print(f"  [AUTO] {repo_slug:<35s} {skill:<10s} → ✅ {date_str}")
                        status.setdefault("completed", {}) \
                              .setdefault(repo_slug, {})[skill] = date_str
                        changed_md = True
                        total += 1
                    break  # 가장 최신 타임스탬프만 사용

    if changed_md:
        _save_status(status)
        print(f"[OK] {total}개 항목 갱신 완료 → docs/ocb_scan_plan.md")
    else:
        print("[INFO] 새로 완료된 진단 없음 (state/ 기준)")

    if not no_sync and (changed_md or True):
        # 변경 없어도 Confluence는 최신 상태 유지
        sync_confluence()

    return total


# ── Confluence 동기화 ─────────────────────────────────────────────────────────

def sync_confluence() -> bool:
    registry_path = PALANTIR_DIR / "docs" / ".confluence_pages.json"
    reg = {}
    if registry_path.exists():
        reg = json.loads(registry_path.read_text(encoding="utf-8"))

    md_key  = str(PLAN_MD.relative_to(PALANTIR_DIR))
    page_id = reg.get(md_key)
    parent  = CF_PARENT_ID if not page_id else None

    cmd = [
        sys.executable, str(PALANTIR_DIR / "tools" / "publish_confluence.py"),
        str(PLAN_MD),
        "--title", CF_TITLE,
    ]
    if page_id:
        cmd += ["--page-id", page_id]
    elif parent:
        cmd += ["--parent", parent]

    print(f"[SYNC] Confluence 게시 중 ... (title: {CF_TITLE})")
    result = subprocess.run(cmd, cwd=PALANTIR_DIR)
    return result.returncode == 0


# ── 현황 출력 ─────────────────────────────────────────────────────────────────

def print_status() -> None:
    status    = _load_status()
    completed = status.get("completed", {})
    print(f"=== OCB 진단 완료 현황 (last_updated: {status.get('last_updated','?')}) ===\n")

    if not completed:
        print("  (완료 항목 없음)")
    else:
        for repo, skills in sorted(completed.items()):
            done = [(s, v) for s, v in skills.items() if v]
            todo = [s for s in VALID_SKILLS if not skills.get(s)]
            print(f"  {repo}")
            for s, d in done:
                print(f"    ✅ {s:<12s} {d}")
            if todo:
                print(f"    ❌ 미완: {', '.join(todo)}")

    # plan.md 체크박스 현황
    text      = PLAN_MD.read_text(encoding="utf-8")
    checked   = len(re.findall(r'✅', text))
    unchecked = len(re.findall(r'❌', text))
    total_chk = checked + unchecked
    if total_chk:
        pct = int(checked / total_chk * 100)
        print(f"\n  체크리스트: {checked}/{total_chk} 완료 ({pct}%)")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OCB 진단 체크리스트 갱신 + Confluence 동기화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--auto", action="store_true",
        help="state/ 디렉터리 스캔 → 완료 항목 자동 갱신 + Confluence 동기화 (권장)",
    )
    parser.add_argument(
        "--done", nargs="+", metavar="ARG",
        help="수동 완료 표시. 형식: <repo> <skill1> [skill2 ...]\n"
             "예: --done ocb-webview-api injection xss",
    )
    parser.add_argument(
        "--date", default=None,
        help="완료 날짜 (YYYY-MM-DD). 미지정 시 오늘 날짜 자동 사용.",
    )
    parser.add_argument(
        "--sync", action="store_true",
        help="체크리스트 변경 없이 Confluence만 갱신",
    )
    parser.add_argument(
        "--status", action="store_true",
        help="현재 완료 현황 출력",
    )
    parser.add_argument(
        "--no-sync", action="store_true",
        help="체크리스트 갱신 후 Confluence 동기화 생략",
    )
    args = parser.parse_args()

    # ── --status ──────────────────────────────────────────────────────────────
    if args.status:
        print_status()
        return

    # ── --sync ────────────────────────────────────────────────────────────────
    if args.sync:
        sync_confluence()
        return

    # ── --auto ────────────────────────────────────────────────────────────────
    if args.auto:
        sync_from_state(no_sync=args.no_sync)
        return

    # ── --done ────────────────────────────────────────────────────────────────
    if args.done:
        if len(args.done) < 2:
            print(
                "[ERROR] --done 형식: <repo> <skill1> [skill2 ...]\n"
                f"  유효한 skill: {', '.join(VALID_SKILLS)}",
                file=sys.stderr,
            )
            sys.exit(1)

        repo    = args.done[0]
        skills  = args.done[1:]
        invalid = [s for s in skills if s not in VALID_SKILLS]
        if invalid:
            print(
                f"[ERROR] 유효하지 않은 skill: {invalid}\n"
                f"  유효한 skill: {', '.join(VALID_SKILLS)}",
                file=sys.stderr,
            )
            sys.exit(1)

        date = args.date or datetime.now().strftime("%Y-%m-%d")

        n = mark_done(repo, skills, date=date)
        if n > 0:
            print(f"[OK] {repo} — {', '.join(skills)} 완료 표시 ({n}개 셀, {date})")
        else:
            print(f"[WARN] {repo} / {skills}: 갱신할 항목을 찾지 못했습니다.")

        # 상태 파일 갱신
        status = _load_status()
        status["completed"].setdefault(repo, {})
        for s in skills:
            status["completed"][repo][s] = date
        _save_status(status)
        print(f"[OK] 상태 저장: docs/.ocb_scan_status.json")

        if not args.no_sync:
            sync_confluence()
        return

    parser.print_help()


if __name__ == "__main__":
    main()
