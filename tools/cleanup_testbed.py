#!/usr/bin/env python3
"""
cleanup_testbed.py — 진단 완료 후 testbed 소스코드 삭제 (용량 확보)

사용법:
    # 특정 repo 삭제
    python3 tools/cleanup_testbed.py my-service

    # 전체 testbed 삭제 (모든 repo)
    python3 tools/cleanup_testbed.py --all

    # 삭제 전 목록만 확인
    python3 tools/cleanup_testbed.py --list

주의:
    - state/ 결과 파일은 삭제하지 않습니다.
    - 삭제 전 확인 프롬프트가 표시됩니다 (--force로 건너뜀).
"""

import argparse
import shutil
import sys
from pathlib import Path

PALANTIR_DIR = Path(__file__).parent.parent
TESTBED_DIR  = PALANTIR_DIR / "testbed"


def _repo_size(path: Path) -> str:
    total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    if total >= 1_073_741_824:
        return f"{total / 1_073_741_824:.1f}GB"
    if total >= 1_048_576:
        return f"{total / 1_048_576:.1f}MB"
    return f"{total / 1024:.1f}KB"


def list_repos() -> list[Path]:
    if not TESTBED_DIR.exists():
        return []
    return sorted(p for p in TESTBED_DIR.iterdir() if p.is_dir() and p.name != ".git")


def cleanup(repo_path: Path, force: bool = False) -> bool:
    size = _repo_size(repo_path)
    print(f"  대상: {repo_path.name}  ({size})")

    if not force:
        ans = input("  삭제하시겠습니까? [y/N] ").strip().lower()
        if ans != "y":
            print("  → 건너뜀")
            return False

    shutil.rmtree(repo_path)
    print(f"  → 삭제 완료 ({size} 회수)")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="testbed 소스코드 삭제 (진단 완료 후 용량 확보)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("repo", nargs="?", help="삭제할 repo 슬러그 (예: my-service)")
    group.add_argument("--all",  action="store_true", help="testbed 전체 삭제")
    group.add_argument("--list", action="store_true", help="testbed 내 repo 목록 출력")

    parser.add_argument("--force", "-f", action="store_true",
                        help="확인 프롬프트 없이 즉시 삭제")
    args = parser.parse_args()

    # 목록 출력
    if args.list:
        repos = list_repos()
        if not repos:
            print("testbed가 비어 있습니다.")
            return
        print(f"testbed/ 내 repo ({len(repos)}개):")
        for p in repos:
            print(f"  {p.name}  ({_repo_size(p)})")
        return

    # 전체 삭제
    if args.all:
        repos = list_repos()
        if not repos:
            print("testbed가 비어 있습니다.")
            return
        total_size = sum(
            sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) for p in repos
        )
        size_str = f"{total_size / 1_048_576:.1f}MB"
        print(f"testbed 전체 삭제  ({len(repos)}개 repo, {size_str})")
        if not args.force:
            ans = input("모두 삭제하시겠습니까? [y/N] ").strip().lower()
            if ans != "y":
                print("취소되었습니다.")
                return
        for p in repos:
            shutil.rmtree(p)
            print(f"  삭제: {p.name}")
        print(f"\n완료 — {size_str} 회수")
        return

    # 단일 repo 삭제
    repo_path = TESTBED_DIR / args.repo
    if not repo_path.exists():
        print(f"[ERROR] 경로 없음: {repo_path}", file=sys.stderr)
        sys.exit(1)

    print(f"testbed 삭제:")
    cleanup(repo_path, args.force)


if __name__ == "__main__":
    main()
