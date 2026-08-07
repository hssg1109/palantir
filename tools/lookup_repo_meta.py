#!/usr/bin/env python3
"""
lookup_repo_meta.py — repo 슬러그로 프로젝트 키 / Fortify 티켓 키를 조회해
stdout에 한 줄 JSON으로 출력한다.

palantir-jira-gateway(별도 배포 단위, palantir 소스를 import하지 않음)가
SECUFINDINGS 티켓 발급 직후 subprocess로 호출해 Fortify 이슈링크 생성 여부와
체크리스트 Fortify 열 갱신값을 판단하는 데 사용한다 (기존 _sync_jira_to_plan()이
update_ocb_plan.py를 subprocess로 호출하는 관례와 동일).

사용법:
    python3 tools/lookup_repo_meta.py --repo ocb-webview-api
    -> {"repo": "ocb-webview-api", "project_key": "OCBWEBVIEW", "fortify_key": "FORTIFY-678"}

필요 환경변수: jira_utils.load_env() 참고 (JIRA_URL, JIRA_TOKEN, ...)
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.jira_utils import load_env, load_repo_project_map, find_fortify_ticket


def main() -> int:
    parser = argparse.ArgumentParser(description="repo -> project_key / fortify_key 조회")
    parser.add_argument("--repo", required=True, help="레포 슬러그 (예: ocb-webview-api)")
    args = parser.parse_args()

    env = load_env()
    jira_url = env.get("JIRA_URL", "").rstrip("/")

    repo_to_project = load_repo_project_map()
    project_key = repo_to_project.get(args.repo)

    fortify_key = None
    if project_key and jira_url and env.get("JIRA_TOKEN"):
        fortify_key = find_fortify_ticket(env, jira_url, project_key, args.repo)

    print(json.dumps({
        "repo": args.repo,
        "project_key": project_key,
        "fortify_key": fortify_key,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
