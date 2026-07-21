#!/usr/bin/env python3
"""
jira_utils.py — Jira/Confluence 인증 및 REST 조회 공유 유틸리티

create_jira_ticket.py(티켓 생성)와 fetch_jira_remediation_targets.py(이행점검
대상 조회)가 공통으로 쓰는 .env 로더 / 인증 헤더 생성 로직을 모아둔다.

필요 환경변수 (.env):
    JIRA_URL, JIRA_EMAIL, JIRA_TOKEN, JIRA_PROJECT_KEY
    CONFLUENCE_BASE_URL, CONFLUENCE_TOKEN
"""

from __future__ import annotations

import base64
import re
from pathlib import Path

PALANTIR_DIR = Path(__file__).resolve().parent.parent
_ENV_PATH = PALANTIR_DIR / ".env"


def load_env(path: Path = _ENV_PATH) -> dict:
    env: dict = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            # 인라인 주석 제거를 strip() 전에 수행 — "   # comment" 패턴도 처리
            v = re.sub(r"\s+#.*$", "", v)
            env[k.strip()] = v.strip()
    return env


def jira_headers(env: dict, token_var: str = "JIRA_TOKEN") -> dict:
    """Cloud(email+token Basic Auth) 또는 Server/DC(PAT Bearer) 자동 선택.

    token_var로 다른 env 키(예: 개인 PAT를 담은 JIRA_TOKEN_REMEDIATION)를 지정하면
    그 토큰으로 인증한다 — REST API로 게시하는 코멘트/전이는 항상 인증 주체의 이름으로
    기록되므로, 특정 사용자 명의로 남겨야 하는 작업(예: 이행점검 코멘트)은 그 사용자의
    개인 PAT를 별도 env 키에 넣고 이 인자로 지정한다.
    """
    token = env.get(token_var, "") or env.get("JIRA_TOKEN", "")
    email = env.get("JIRA_EMAIL", "").strip()
    if email:
        creds = base64.b64encode(f"{email}:{token}".encode()).decode()
        return {"Authorization": f"Basic {creds}", "Content-Type": "application/json"}
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def cf_headers(env: dict) -> dict:
    token = env.get("CONFLUENCE_TOKEN", "")
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
