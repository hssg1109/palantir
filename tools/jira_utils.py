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

import requests

PALANTIR_DIR = Path(__file__).resolve().parent.parent
_ENV_PATH = PALANTIR_DIR / ".env"
_SCAN_PLAN_PATH = PALANTIR_DIR / "docs" / "ocb_scan_plan.md"


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


def load_repo_project_map(scan_plan_path: Path = _SCAN_PLAN_PATH) -> dict[str, str]:
    """docs/ocb_scan_plan.md '## 2. 서비스 그룹별 레포 목록' 섹션을 파싱해
    레포 슬러그 -> 프로젝트 키(대문자, 예: OCBWEBVIEW/LIVECM/OB/OEP) dict 반환.

    대부분 섹션은 '#### <PROJECT> — ...' 헤더 아래 3열(레포 슬러그|유형|설명) 표를
    쓰지만, OCBE+OB+OEP처럼 하나의 헤더가 여러 Bitbucket 프로젝트를 포괄하는 경우
    4열(프로젝트|레포 슬러그|유형|설명) 표로 개별 프로젝트 키를 명시한다 — 이 경우
    헤더가 아닌 표의 첫 컬럼을 프로젝트 키로 사용한다.
    """
    if not scan_plan_path.exists():
        return {}
    lines = scan_plan_path.read_text(encoding="utf-8").splitlines()

    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == "## 2. 서비스 그룹별 레포 목록")
    except StopIteration:
        return {}

    repo_to_project: dict[str, str] = {}
    current_project: str | None = None
    in_exclude = False

    for line in lines[start:]:
        if re.match(r"^## 3\.|^### Phase 1", line):
            break
        m = re.match(r"^#### (.+?) — ", line)
        if m:
            current_project = m.group(1).strip()
            in_exclude = False
            continue
        if re.match(r"^\*\*제외", line):
            in_exclude = True
            continue
        if in_exclude or not line.startswith("|") or re.match(r"^\|[\s\-:|]+\|$", line):
            continue
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if len(cells) >= 4 and cells[1].startswith("`"):
            # 프로젝트 | 레포 슬러그 | 유형 | 설명
            proj, repo = cells[0].strip(), cells[1].strip("`")
            if proj and repo:
                repo_to_project[repo] = proj
        elif len(cells) >= 3 and cells[0].startswith("`") and current_project:
            # 레포 슬러그 | 유형 | 설명
            repo_to_project[cells[0].strip("`")] = current_project

    return repo_to_project


def load_ticket_repo_pairs(scan_plan_path: Path = _SCAN_PLAN_PATH) -> list[tuple[str, str]]:
    """docs/ocb_scan_plan.md '## 1.' 체크리스트 표(P1-A/P1-B/... 섹션)를 파싱해
    [(repo, SECUFINDINGS-nnnn), ...] 목록 반환. Jira 티켓 컬럼이 없는 행은 제외."""
    if not scan_plan_path.exists():
        return []
    lines = scan_plan_path.read_text(encoding="utf-8").splitlines()

    pairs: list[tuple[str, str]] = []
    for line in lines:
        if re.match(r"^## 2\.", line):
            break
        if not line.startswith("|") or "SECUFINDINGS" not in line:
            continue
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if not cells or not cells[0].startswith("`"):
            continue
        repo = cells[0].strip("`")
        m = re.search(r"SECUFINDINGS-(\d+)", cells[-1])
        if m:
            pairs.append((repo, f"SECUFINDINGS-{m.group(1)}"))

    return pairs


_FORTIFY_TITLE_RE = re.compile(r"^\[([^/\]]+)/([^/\]]+)/[^\]]*\]")
_FORTIFY_CYCLE_LABELS = [f"26{m:02d}" for m in range(1, 13)]  # 2601~2612


def _fortify_candidate_priority(labels: list[str], summary: str) -> int:
    """낮을수록 우선순위 높음. 정기(REGU/정기) > 요청(REQS/요청) > 미분류,
    각 유형 내에서는 '안내'(리포트) 티켓을 raw("Fortify 점검 결과")보다 우선.

    FOTI/'정기' 라벨이 일부 정기진단 티켓에 누락되는 경우가 확인되어(2026-08
    Fortify issue-link 조사), REGU 라벨(또는 '정기' 텍스트) 유무만으로 정기/요청을
    판별한다 — FOTI 유무는 더 이상 조건에 넣지 않는다.
    """
    is_periodic = "REGU" in labels or "정기" in labels
    is_request = "REQS" in labels or "요청" in labels
    is_guided = "안내" in summary
    if is_periodic:
        return 0 if is_guided else 1
    if is_request:
        return 2 if is_guided else 3
    return 4 if is_guided else 5


def find_fortify_ticket(env: dict, jira_url: str, project_key: str, repo: str) -> str | None:
    """FORTIFY 프로젝트에서 '26XX'(2601~2612, 해당연도 월별 사이클) 라벨이 붙은
    티켓 중, 제목이 '[project_key/repo/...]' 패턴으로 시작하는 티켓 키를 반환한다
    (없으면 None). 기존에는 FOTI/REGU/정기 라벨을 모두 요구했으나, 정기진단
    티켓 중 상당수가 FOTI 또는 '정기' 라벨이 누락되어 있는 것이 확인되어(2026-08
    조사) 라벨 조건을 26XX 사이클 라벨로 완화했다.

    한 (project_key, repo) 조합에 여러 사이클/타입의 티켓이 섞여 있을 수 있어
    _fortify_candidate_priority()로 정기>요청>미분류, 각 유형 내 안내>raw 순으로
    최적 후보를 고르고, 동순위면 이슈 번호가 가장 큰(=최근) 티켓을 선택한다.
    """
    label_clause = " OR ".join(f'labels = "{l}"' for l in _FORTIFY_CYCLE_LABELS)
    jql = (
        f'project = FORTIFY AND ({label_clause}) '
        f'AND labels = "{project_key}" ORDER BY created DESC'
    )
    try:
        resp = requests.get(
            f"{jira_url}/rest/api/2/search",
            headers=jira_headers(env),
            params={"jql": jql, "maxResults": 50, "fields": "summary,labels"},
            timeout=15,
        )
    except requests.exceptions.RequestException:
        return None
    if resp.status_code != 200:
        return None

    candidates: list[tuple[str, list[str], str]] = []
    for issue in resp.json().get("issues", []):
        fields = issue.get("fields", {})
        summary = fields.get("summary", "")
        labels = fields.get("labels", [])
        m = _FORTIFY_TITLE_RE.match(summary)
        if not m:
            continue
        proj, r = m.group(1).strip(), m.group(2).strip()
        if proj == project_key and r == repo:
            candidates.append((issue["key"], labels, summary))

    if not candidates:
        return None

    best_priority = min(_fortify_candidate_priority(labels, summary) for _, labels, summary in candidates)
    pool = [key for key, labels, summary in candidates if _fortify_candidate_priority(labels, summary) == best_priority]
    pool.sort(key=lambda k: int(re.search(r"-(\d+)$", k).group(1)), reverse=True)
    return pool[0]


def create_issue_link(env: dict, jira_url: str, inward_key: str, outward_key: str, link_type: str = "Relates") -> bool:
    """inward_key <-> outward_key 사이에 issue link 생성 (기본 'Relates')."""
    payload = {
        "type": {"name": link_type},
        "inwardIssue": {"key": inward_key},
        "outwardIssue": {"key": outward_key},
    }
    try:
        resp = requests.post(
            f"{jira_url}/rest/api/2/issueLink",
            headers=jira_headers(env),
            json=payload,
            timeout=15,
        )
    except requests.exceptions.RequestException:
        return False
    return resp.status_code == 201
