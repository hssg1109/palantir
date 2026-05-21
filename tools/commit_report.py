#!/usr/bin/env python3
"""
commit_report.py — 1차 보고서(final)를 palantir-reports 레포에 커밋합니다.

사용법:
    python3 tools/commit_report.py --run-id 20260506_2200 --repo ocb-webview-api
    python3 tools/commit_report.py --run-id 20260506_2200  # 전체 레포 자동 감지

동작:
    1. ~/palantir-reports/ 가 없으면 git init 후 생성
    2. logs/report_final_<RUN_ID>.md 를
       palantir-reports/<repo>/<RUN_ID>/report_final_<RUN_ID>.md 로 복사
    3. git add + git commit
       커밋 메시지: "report: <repo> <RUN_ID> 1차보고서(final)"

generate_report.py --type final 이 완료된 후 자동 호출됩니다.
"""

import argparse
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PALANTIR_DIR  = Path(__file__).resolve().parent.parent
LOGS_DIR      = PALANTIR_DIR / "logs"
STATE_DIR     = PALANTIR_DIR / "state"
REPORTS_REPO  = Path.home() / "palantir-reports"


# ── git 헬퍼 ─────────────────────────────────────────────────────────────────

def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git"] + args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _ensure_repo(path: Path) -> None:
    """path 가 git repo가 아니면 init."""
    if (path / ".git").exists():
        return
    path.mkdir(parents=True, exist_ok=True)
    r = _git(["init"], cwd=path)
    if r.returncode != 0:
        print(f"[ERROR] git init 실패: {r.stderr}", file=sys.stderr)
        sys.exit(1)
    # 초기 커밋 없이 main 브랜치 설정
    _git(["checkout", "-b", "main"], cwd=path)
    print(f"[INFO] palantir-reports 레포 초기화: {path}")


# ── 레포 목록 자동 감지 ────────────────────────────────────────────────────────

def _detect_repos(run_id: str) -> list[str]:
    """state/ 에서 run_id 에 해당하는 레포 목록을 반환한다."""
    repos = set()
    for p in STATE_DIR.glob(f"*/*/{run_id}/findings_*.json"):
        repos.add(p.parts[-4])
    return sorted(repos)


# ── 커밋 ────────────────────────────────────────────────────────────────────

def commit_report(run_id: str, repo: str) -> bool:
    """
    1차 보고서를 palantir-reports/<repo>/<run_id>/ 에 복사하고 커밋한다.
    성공 시 True, 실패 시 False 반환.
    """
    src = LOGS_DIR / f"report_final_{run_id}.md"
    if not src.exists():
        print(f"[WARN] 보고서 파일 없음: {src}  (--type final 먼저 실행)")
        return False

    _ensure_repo(REPORTS_REPO)

    dest_dir  = REPORTS_REPO / repo / run_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / f"report_final_{run_id}.md"

    shutil.copy2(src, dest_file)
    print(f"[INFO] 복사: {src.name} → {dest_file.relative_to(REPORTS_REPO)}")

    # git add
    r = _git(["add", str(dest_file.relative_to(REPORTS_REPO))], cwd=REPORTS_REPO)
    if r.returncode != 0:
        print(f"[WARN] git add 실패: {r.stderr}", file=sys.stderr)
        return False

    # git commit
    msg = f"report: {repo} {run_id} 1차보고서(final)"
    r = _git(["commit", "-m", msg], cwd=REPORTS_REPO)
    if r.returncode != 0:
        # 변경사항 없는 경우(already up to date) → 경고만 출력
        if "nothing to commit" in r.stdout + r.stderr:
            print(f"[INFO] 변경 없음 — 이미 커밋된 보고서: {dest_file.name}")
            return True
        print(f"[WARN] git commit 실패: {r.stderr}", file=sys.stderr)
        return False

    print(f"[OK] 커밋 완료: {msg}")
    print(f"     경로: {dest_file}")
    return True


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="palantir-reports 레포에 1차 보고서(final)를 커밋합니다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--run-id", required=True, help="파이프라인 RUN_ID (YYYYMMDD_HHMM)")
    parser.add_argument("--repos", nargs="+", metavar="REPO",
                        help="커밋할 레포 (생략 시 state/ 에서 자동 감지)")
    args = parser.parse_args()

    repos = args.repos or _detect_repos(args.run_id)
    if not repos:
        print(f"[WARN] run_id={args.run_id} 에 해당하는 레포를 찾지 못했습니다.")
        return 1

    success = 0
    for repo in repos:
        if commit_report(args.run_id, repo):
            success += 1

    print(f"\n[commit_report] {success}/{len(repos)}개 레포 커밋 완료")
    return 0 if success == len(repos) else 1


if __name__ == "__main__":
    sys.exit(main())
