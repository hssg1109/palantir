#!/usr/bin/env python3
"""
backfill_jira_project_labels.py — 기발급 SECUFINDINGS-* 티켓에 프로젝트 키 라벨 추가

docs/ocb_scan_plan.md '## 1.' 체크리스트 표에서 (repo, ticket) 쌍을 추출하고,
'## 2. 서비스 그룹별 레포 목록' 표에서 repo -> 프로젝트 키(OCBWEBVIEW/LIVECM/OB/OEP 등)
매핑을 읽어, 각 티켓에 프로젝트 키 라벨을 추가(append)한다. 기존 라벨(repo명 등)은
보존하며, 이미 프로젝트 키 라벨이 붙어 있으면 skip 한다.

사용법:
    python3 tools/backfill_jira_project_labels.py              # dry-run (기본)
    python3 tools/backfill_jira_project_labels.py --execute    # 실제 Jira 라벨 추가

필요 환경변수: jira_utils.load_env() 참고 (JIRA_URL, JIRA_TOKEN, ...)
"""

import argparse
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.jira_utils import load_env, jira_headers, load_repo_project_map, load_ticket_repo_pairs


def _get_labels(env: dict, jira_url: str, ticket: str) -> list[str] | None:
    resp = requests.get(
        f"{jira_url}/rest/api/2/issue/{ticket}",
        headers=jira_headers(env),
        params={"fields": "labels"},
        timeout=15,
    )
    if resp.status_code != 200:
        print(f"[ERROR] {ticket}: 라벨 조회 실패 (HTTP {resp.status_code})")
        return None
    return resp.json().get("fields", {}).get("labels", [])


def _add_label(env: dict, jira_url: str, ticket: str, label: str) -> bool:
    resp = requests.put(
        f"{jira_url}/rest/api/2/issue/{ticket}",
        headers=jira_headers(env),
        json={"update": {"labels": [{"add": label}]}},
        timeout=15,
    )
    if resp.status_code in (200, 204):
        return True
    print(f"[ERROR] {ticket}: 라벨 추가 실패 (HTTP {resp.status_code}) — {resp.text[:300]}")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="SECUFINDINGS 티켓에 프로젝트 키 라벨 백필")
    parser.add_argument("--execute", action="store_true", help="실제로 Jira에 라벨 추가 (미지정 시 dry-run)")
    args = parser.parse_args()

    env = load_env()
    jira_url = env.get("JIRA_URL", "").rstrip("/")
    if not jira_url or not env.get("JIRA_TOKEN"):
        print("[ERROR] .env에 JIRA_URL/JIRA_TOKEN이 없습니다.")
        return 1

    repo_to_project = load_repo_project_map()
    ticket_repo_pairs = load_ticket_repo_pairs()

    if not ticket_repo_pairs:
        print("[ERROR] docs/ocb_scan_plan.md 에서 티켓 목록을 찾지 못했습니다.")
        return 1

    print(f"[INFO] 대상 티켓 {len(ticket_repo_pairs)}건, 프로젝트 키 매핑 {len(repo_to_project)}건")
    print(f"[INFO] 모드: {'EXECUTE (실제 Jira 업데이트)' if args.execute else 'DRY-RUN (미리보기만)'}")
    print()

    n_add, n_skip_has_label, n_skip_no_map, n_error = 0, 0, 0, 0

    for repo, ticket in ticket_repo_pairs:
        project_key = repo_to_project.get(repo)
        if not project_key:
            print(f"[SKIP] {ticket:20s} {repo:35s} — §2에 프로젝트 키 매핑 없음")
            n_skip_no_map += 1
            continue

        if not args.execute:
            print(f"[DRY-RUN] {ticket:20s} {repo:35s} -> add label '{project_key}'")
            n_add += 1
            continue

        current_labels = _get_labels(env, jira_url, ticket)
        if current_labels is None:
            n_error += 1
            continue
        if project_key in current_labels:
            print(f"[SKIP] {ticket:20s} {repo:35s} — 이미 '{project_key}' 라벨 있음")
            n_skip_has_label += 1
            continue

        if _add_label(env, jira_url, ticket, project_key):
            print(f"[OK] {ticket:20s} {repo:35s} -> '{project_key}' 라벨 추가 (기존: {current_labels})")
            n_add += 1
        else:
            n_error += 1

    print()
    print("=" * 60)
    print(f"  추가: {n_add}건")
    print(f"  스킵(매핑없음): {n_skip_no_map}건")
    if args.execute:
        print(f"  스킵(이미있음): {n_skip_has_label}건")
        print(f"  실패: {n_error}건")
    else:
        print("  (dry-run — 실제 반영하려면 --execute 옵션 추가)")
    print("=" * 60)

    return 1 if n_error else 0


if __name__ == "__main__":
    sys.exit(main())
