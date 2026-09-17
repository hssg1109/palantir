#!/usr/bin/env python3
"""
add_jira_project_role.py — Jira 프로젝트 role(멤버십)에 사용자를 추가한다.

배경: 외주사 계정(P사번 등)이 담당자(assignee)로 지정 가능한 프로젝트 role에
소속돼 있지 않으면 티켓이 "pending" 상태로 남고 담당자 배정이 안 된다. 이 스크립트는
ADMINISTER_PROJECTS 권한을 가진 JIRA_TOKEN으로 대상 사용자를 지정 role(기본
Users)에 추가해 담당자 배정이 가능하도록 만든다.

주의: role은 프로젝트 권한 스킴에서 실제로 ASSIGNABLE_USER 권한을 보유한 role이어야
효과가 있다. SECUFINDINGS 기준 ASSIGNABLE_USER는 "Users"/"Administrators" role에만
부여돼 있고 "Developers" role에는 없다 (2026-09-15 확인 — 최초 버전은 기본값이
Developers였으나 assignable/search로 재확인한 결과 효과가 없어 Users로 수정됨).
다른 프로젝트에 적용할 때도 실행 전 권한 스킴을 확인할 것 (--role 인자로 조정 가능).

주의: 이 스크립트는 Jira 프로젝트 권한(멤버십)을 실제로 변경하는 쓰기 작업이다.
항상 실행 전 사람이 대상 사용자/프로젝트/role을 확인한 뒤 수동으로 호출해야 하며,
다른 skill/스크립트에서 자동 호출하지 않는다 (Jira 쓰기는 매번 별도 승인 필요).

사용:
    python3 tools/add_jira_project_role.py --project SECUFINDINGS --user PP56062
    python3 tools/add_jira_project_role.py --project SECUFINDINGS --user PP56062 --role Users
    python3 tools/add_jira_project_role.py --project SECUFINDINGS --user PP56062 --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from jira_utils import load_env, jira_headers  # noqa: E402


def get_user(env: dict, jira_url: str, username: str) -> dict | None:
    resp = requests.get(
        f"{jira_url}/rest/api/2/user",
        headers=jira_headers(env),
        params={"username": username},
        timeout=15,
    )
    if resp.status_code != 200:
        return None
    return resp.json()


def get_project_roles(env: dict, jira_url: str, project_key: str) -> dict:
    resp = requests.get(
        f"{jira_url}/rest/api/2/project/{project_key}/role",
        headers=jira_headers(env),
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def get_role_detail(env: dict, role_url: str) -> dict:
    resp = requests.get(role_url, headers=jira_headers(env), timeout=15)
    resp.raise_for_status()
    return resp.json()


def role_actor_usernames(role_detail: dict) -> set[str]:
    names = set()
    for actor in role_detail.get("actors", []):
        actor_user = actor.get("actorUser") or {}
        name = actor_user.get("name") or actor.get("name")
        if name:
            names.add(name.lower())
    return names


def add_user_to_role(env: dict, role_url: str, username: str) -> requests.Response:
    return requests.post(
        role_url,
        headers=jira_headers(env),
        json={"user": [username]},
        timeout=15,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project", required=True, help="Jira 프로젝트 키 (예: SECUFINDINGS)")
    ap.add_argument("--user", required=True, help="추가할 사용자 계정 (예: PP56062)")
    ap.add_argument("--role", default="Users", help="추가할 role 이름 (기본: Users — ASSIGNABLE_USER 권한 보유 role)")
    ap.add_argument("--dry-run", action="store_true", help="실제 POST 없이 확인만 수행")
    args = ap.parse_args()

    env = load_env()
    jira_url = env.get("JIRA_URL", "").rstrip("/")
    if not jira_url or not env.get("JIRA_TOKEN"):
        print("[ERROR] JIRA_URL / JIRA_TOKEN 미설정 (.env 확인 필요)")
        return 1

    user = get_user(env, jira_url, args.user)
    if not user:
        print(f"[ERROR] Jira에 존재하지 않는 사용자: {args.user}")
        return 1
    print(f"[OK] 사용자 확인: {user.get('name')} ({user.get('displayName')}, {user.get('emailAddress')}), active={user.get('active')}")

    roles = get_project_roles(env, jira_url, args.project)
    if args.role not in roles:
        print(f"[ERROR] '{args.project}' 프로젝트에 '{args.role}' role 없음. 가능한 role: {list(roles.keys())}")
        return 1
    role_url = roles[args.role]
    print(f"[OK] role 확인: {args.role} -> {role_url}")

    detail = get_role_detail(env, role_url)
    existing = role_actor_usernames(detail)
    if args.user.lower() in existing:
        print(f"[SKIP] {args.user}는 이미 '{args.role}' role에 소속되어 있음. 변경 없음.")
        return 0

    if args.dry_run:
        print(f"[DRY-RUN] {args.user}를 '{args.project}'/'{args.role}' role에 추가 예정 (실제 POST 생략)")
        return 0

    resp = add_user_to_role(env, role_url, args.user)
    if resp.status_code not in (200, 201):
        print(f"[ERROR] role 추가 실패: HTTP {resp.status_code} — {resp.text[:500]}")
        return 1

    detail_after = get_role_detail(env, role_url)
    if args.user.lower() in role_actor_usernames(detail_after):
        print(f"[DONE] {args.user} ({user.get('displayName')})를 '{args.project}' 프로젝트 '{args.role}' role에 추가 완료.")
        print(f"       이제 이 프로젝트 티켓의 담당자(assignee)로 배정 가능합니다.")
        return 0

    print("[WARN] POST는 성공(200/201)했으나 재조회 시 사용자가 role에서 확인되지 않음 — 수동 확인 필요")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
