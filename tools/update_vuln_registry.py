#!/usr/bin/env python3
"""
update_vuln_registry.py — findings_*.json → vuln_registry.json 갱신 CLI

사용법:
  python3 tools/update_vuln_registry.py --repo <repo> [--run-id <run_id>] [--confluence-url <url>]
  python3 tools/update_vuln_registry.py --all              # state/ 하위 모든 레포 일괄 갱신
"""

import argparse
import json
import sys
from pathlib import Path

PALANTIR_DIR = Path(__file__).resolve().parent.parent
STATE_DIR    = PALANTIR_DIR / "state"

sys.path.insert(0, str(PALANTIR_DIR))
from tools.audit_utils import update_registry_from_findings, load_vuln_registry, log_report_published


def _update_one(repo: str, run_id: str | None, confluence_url: str = "") -> dict:
    stats = update_registry_from_findings(
        repo=repo,
        run_id=run_id,
        report_url=confluence_url,
    )
    return stats


def _print_summary(repo: str, stats: dict, registry_path: Path) -> None:
    total = len(load_vuln_registry(repo).get("findings", []))
    print(
        f"[{repo}] registry 갱신 완료 — "
        f"신규 +{stats['added']} / 업데이트 {stats['updated']} / 변경없음 {stats['unchanged']} "
        f"| 전체 누적 {total}건 → {registry_path}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog="update_vuln_registry.py")
    parser.add_argument("--repo",           help="대상 레포명")
    parser.add_argument("--run-id",         help="특정 RUN_ID (미지정 시 skill별 최신)")
    parser.add_argument("--confluence-url", default="", help="Confluence 게시 URL (이력 기록용)")
    parser.add_argument("--all",            action="store_true", help="state/ 하위 모든 레포 일괄 갱신")
    args = parser.parse_args()

    if not args.all and not args.repo:
        parser.error("--repo 또는 --all 을 지정하세요.")

    repos: list[str] = []
    if args.all:
        if STATE_DIR.is_dir():
            repos = [
                d.name for d in sorted(STATE_DIR.iterdir())
                if d.is_dir() and not d.name.startswith(".")
            ]
        if not repos:
            print("[update_vuln_registry] state/ 디렉터리에 레포가 없습니다.")
            return
        print(f"[update_vuln_registry] 일괄 갱신 대상: {len(repos)}개 레포")
    else:
        repos = [args.repo]

    for repo in repos:
        repo_dir = STATE_DIR / repo
        if not repo_dir.is_dir():
            print(f"[{repo}] state 디렉터리 없음 — 스킵")
            continue
        stats = _update_one(repo, args.run_id, args.confluence_url)
        registry_path = STATE_DIR / repo / "vuln_registry.json"
        _print_summary(repo, stats, registry_path)


if __name__ == "__main__":
    main()
