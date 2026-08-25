#!/usr/bin/env python3
"""
backfill_repo_meta.py — state/<repo>/repo_meta.json 누락 시 재clone으로 메타데이터만 복구.

approve_report.py --publish 가 repo_meta.json/.clone_info.json 누락 상태에서
Bitbucket 프로젝트/브랜치/커밋/담당자를 빈칸('-')으로 최종 보고서·Jira 티켓에
게시하는 사고를 막기 위한 절차 (2026-08-25, gws-admin-fe에서 확인).

clone_repo.py를 재실행해 repo_meta.json을 다시 생성한 뒤, 이 실행은 진단 목적이
아니므로 재clone된 testbed 소스는 즉시 삭제한다 (사람이 코드를 보거나 LLM이
접근하는 일이 없으므로 클렌징 절차 대상 아님).

PROJECT 키는 docs/system_code_to_repo_20260729_v3.json의 "PROJECT/repo" 표기에서
조회한다. 매핑에 없으면 자동 추정하지 않고 사람이 --project로 직접 지정해야 한다.

사용법:
    python3 tools/backfill_repo_meta.py --repo <repo>
    python3 tools/backfill_repo_meta.py --repo <repo> --project <PROJECT>   # 매핑에 없을 때
    python3 tools/backfill_repo_meta.py --all                              # 누락된 전체 레포 일괄 처리
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

_RUN_ID_RE = re.compile(r"^\d{8}_\d{4}$")

PALANTIR_DIR = Path(__file__).resolve().parent.parent
STATE_DIR = PALANTIR_DIR / "state"
TESTBED_DIR = PALANTIR_DIR / "testbed"
REPO_MAP_PATH = PALANTIR_DIR / "docs" / "system_code_to_repo_20260729_v3.json"


def _lookup_project(repo: str) -> str | None:
    """docs/system_code_to_repo_*.json의 'PROJECT/repo' 표기에서 PROJECT 키를 조회."""
    if not REPO_MAP_PATH.exists():
        return None
    data = json.loads(REPO_MAP_PATH.read_text(encoding="utf-8"))
    for entry in data:
        for r in entry.get("repos", []):
            if "/" in r and r.rsplit("/", 1)[-1] == repo:
                return r.split("/", 1)[0]
    return None


def backfill_one(repo: str, project: str | None = None) -> bool:
    meta_path = STATE_DIR / repo / "repo_meta.json"
    if meta_path.exists():
        print(f"[SKIP] {repo} — repo_meta.json 이미 존재")
        return True

    proj = project or _lookup_project(repo)
    if not proj:
        print(f"[FAIL] {repo} — PROJECT 키를 찾을 수 없음 "
              f"(docs/system_code_to_repo_*.json 매핑에 없음).")
        print(f"       수동 실행 필요: python3 tools/backfill_repo_meta.py --repo {repo} --project <PROJECT>")
        return False

    testbed_path = TESTBED_DIR / repo
    pre_existing = testbed_path.exists()
    if pre_existing:
        print(f"[SKIP] {repo} — testbed/{repo} 가 이미 존재함 (미완료 진단/미클렌징 잔존 가능성).")
        print(f"       clone_repo.py는 기존 testbed가 있으면 재clone 대신 git pull을 시도하므로,")
        print(f"       이 스크립트가 임의로 삭제하면 클렌징 감사 기록(retroactive_cleanse.py 미실행)을 우회하게 됨.")
        print(f"       내용을 확인 후 정상 클렌징 절차를 거치거나, 무관함이 확실하면 수동 삭제 후 재실행할 것.")
        return False

    print(f"[INFO] {repo} — project={proj} 로 메타데이터 전용 재clone 시도")
    r = subprocess.run(
        [sys.executable, "tools/clone_repo.py", proj, repo],
        cwd=str(PALANTIR_DIR),
    )
    if testbed_path.exists():
        shutil.rmtree(testbed_path)
        print(f"[INFO] {repo} — 메타데이터 전용 목적이므로 재clone된 testbed 즉시 삭제")

    if r.returncode != 0:
        print(f"[FAIL] {repo} — clone_repo.py 실패 (returncode={r.returncode})")
        return False

    if meta_path.exists():
        print(f"[OK] {repo} — repo_meta.json 복구 완료")
        return True

    print(f"[FAIL] {repo} — clone은 성공했으나 repo_meta.json이 생성되지 않음 (원인 확인 필요)")
    return False


def _looks_like_real_repo(repo_dir: Path) -> bool:
    """
    실제 레포 state 디렉터리는 state/<repo>/<skill>/<RUN_ID>/findings_*.json 구조다.
    state/old, state/_archived_failed_runs 같은 아카이브 컨테이너는 <skill>/<repo>/<RUN_ID>/...
    로 한 단계 더 깊어 RUN_ID 패턴(YYYYMMDD_HHMM)이 skill 바로 아래에 나오지 않는다.
    """
    skill_dirs = [c for c in repo_dir.iterdir() if c.is_dir()]
    if not skill_dirs:
        return False
    for skill_dir in skill_dirs:
        sub_dirs = [c for c in skill_dir.iterdir() if c.is_dir()]
        if any(_RUN_ID_RE.match(c.name) for c in sub_dirs):
            return True
    return False


def _repos_missing_meta() -> list[str]:
    if not STATE_DIR.is_dir():
        return []
    targets = []
    for repo_dir in sorted(STATE_DIR.iterdir()):
        if not repo_dir.is_dir():
            continue
        if (repo_dir / "repo_meta.json").exists():
            continue
        if _looks_like_real_repo(repo_dir):
            targets.append(repo_dir.name)
    return targets


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--repo", help="단일 레포만 처리")
    parser.add_argument("--project", help="PROJECT 키 직접 지정 (매핑 조회 생략/실패 시 사용)")
    parser.add_argument("--all", action="store_true",
                        help="state/*/ 중 repo_meta.json 누락된 모든 레포 일괄 처리")
    args = parser.parse_args()

    if args.all:
        targets = _repos_missing_meta()
        if not targets:
            print("[OK] repo_meta.json 누락 레포 없음")
            return 0
        print(f"[대상] {len(targets)}개 레포: {', '.join(targets)}")
        print("=" * 60)
        ok, fail = 0, 0
        for repo in targets:
            if backfill_one(repo):
                ok += 1
            else:
                fail += 1
            print("-" * 60)
        print(f"\n완료: {ok}건 / 실패: {fail}건 (매핑 없는 실패는 --project로 수동 재실행)")
        return 0 if fail == 0 else 1

    if not args.repo:
        parser.error("--repo 또는 --all 중 하나는 필수")

    return 0 if backfill_one(args.repo, args.project) else 1


if __name__ == "__main__":
    sys.exit(main())
