#!/usr/bin/env python3
"""
clone_repo.py — Bitbucket Server(code.skplanet.com)에서 소스코드를 clone합니다.

사용법:
    python3 tools/clone_repo.py <PROJECT_KEY> <REPO_SLUG> [--branch BRANCH]

예시:
    python3 tools/clone_repo.py PROJ my-service
    python3 tools/clone_repo.py PROJ my-service --branch develop

출력:
    testbed/<repo_slug>/  (팔란티어 진단 대상 디렉터리)

환경변수 (.env):
    BITBUCKET_BASE_URL  = https://code.skplanet.com
    CUSTOMER_BB_TOKEN   = BBDC-...  (고객사 Bitbucket Personal Access Token)
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import jira_utils  # noqa: E402

# ── .env 로드 ────────────────────────────────────────────────────────────────
_ENV_PATH = Path(__file__).parent.parent / ".env"


def _load_env(path: Path = _ENV_PATH) -> dict:
    env: dict = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        env[key.strip()] = val.strip()
    return env


_ENV = _load_env()

BITBUCKET_BASE_URL: str = _ENV.get("BITBUCKET_BASE_URL", "https://code.skplanet.com").rstrip("/")
CUSTOMER_BB_TOKEN: str  = _ENV.get("CUSTOMER_BB_TOKEN", "")
TESTBED_DIR: Path        = Path(__file__).parent.parent / "testbed"
STATE_DIR: Path          = Path(__file__).parent.parent / "state"

# ── 담당자 표기 정규화 ─────────────────────────────────────────────────────────
INTERNAL_EMAIL_DOMAINS = {"sk.com", "howser.co.kr"}
MAINTAINER_CACHE_PATH: Path = Path(__file__).parent.parent / "shared" / "references" / "maintainer_directory_cache.json"


# ── Bitbucket Server REST API ─────────────────────────────────────────────────

def _build_clone_url(project: str, repo: str) -> str:
    """Bitbucket Server HTTP clone URL을 PROJECT/REPO로 직접 조합한다."""
    return f"{BITBUCKET_BASE_URL}/scm/{project.lower()}/{repo}.git"


def _get_clone_url(project: str, repo: str) -> str:
    """
    Bitbucket Server REST API로 HTTP clone URL을 조회한다.
    API: GET /rest/api/1.0/projects/{project}/repos/{repo}

    네트워크 오류(No route to host 등) 발생 시 URL을 직접 조합하여 계속 진행한다.
    권한 오류(401/404)는 즉시 종료한다.
    """
    import urllib.request
    import json

    api_url = f"{BITBUCKET_BASE_URL}/rest/api/1.0/projects/{project}/repos/{repo}"
    req = urllib.request.Request(
        api_url,
        headers={"Authorization": f"Bearer {CUSTOMER_BB_TOKEN}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        # HTTP clone link 추출
        for link in data.get("links", {}).get("clone", []):
            if link.get("name") == "http":
                return link["href"]

        # API는 성공했지만 clone link가 없는 경우
        return _build_clone_url(project, repo)

    except urllib.error.HTTPError as e:
        print(f"[ERROR] Bitbucket API 오류 {e.code}: {e.reason}", file=sys.stderr)
        if e.code == 401:
            print("  → CUSTOMER_BB_TOKEN이 만료되었거나 권한이 없습니다.", file=sys.stderr)
            sys.exit(1)
        elif e.code == 404:
            print(f"  → 프로젝트 '{project}' 또는 레포 '{repo}'를 찾을 수 없습니다.", file=sys.stderr)
            sys.exit(1)
        # 그 외 HTTP 오류는 fallback
        url = _build_clone_url(project, repo)
        print(f"[WARN] API 오류 — URL 직접 조합으로 진행: {url}", file=sys.stderr)
        return url

    except Exception as e:
        # 네트워크 오류(No route to host, timeout 등) → fallback
        url = _build_clone_url(project, repo)
        print(f"[WARN] API 접근 불가 ({e.__class__.__name__}: {e})")
        print(f"[INFO] clone URL 직접 조합: {url}")
        return url


def _inject_token_to_url(clone_url: str, token: str) -> str:
    """
    clone URL에 Bearer Token을 Basic Auth 형태로 삽입.
    https://code.skplanet.com/scm/... → https://x-token-auth:<token>@code.skplanet.com/scm/...
    """
    parsed = urlparse(clone_url)
    authed = parsed._replace(netloc=f"x-token-auth:{token}@{parsed.hostname}"
                             + (f":{parsed.port}" if parsed.port else ""))
    return authed.geturl()


def _bb_get_json_via_powershell(api_url: str) -> object | None:
    """
    WSL에서는 Bitbucket에 직접 네트워크 접근이 불가능하므로(No route to host — clone 시
    _git_clone_via_powershell/_detect_default_branch_via_powershell과 동일한 제약),
    PowerShell(Windows 네트워크 스택)의 Invoke-RestMethod로 REST GET을 대신 호출하고
    JSON 결과를 stdout으로 받아 파싱한다. 실패 시 None 반환 (호출부에서 best-effort 처리).
    """
    import base64 as _base64
    import json as _json

    # PowerShell(5.1)이 파이프로 리다이렉트될 때 stdout을 콘솔 OEM 코드페이지(예: 한글 Windows의
    # cp949)로 쓰는 경우가 있어, UTF-8로 직접 디코드하면 한글 등 비-ASCII 문자가 깨진다
    # (errors="replace"로 조용히 U+FFFD로 치환되어 원본 복구 불가).
    # → PowerShell 쪽에서 결과를 UTF-8 바이트로 인코딩한 뒤 Base64(ASCII-safe)로 감싸 출력하고,
    #   Python 쪽에서 Base64 디코드 후 UTF-8로 해석해 코드페이지 문제를 원천 차단한다.
    ps_cmd = (
        _GIT_PATH_PREAMBLE
        + f"$h = @{{Authorization='Bearer {CUSTOMER_BB_TOKEN}'; Accept='application/json'}}; "
        f"try {{ $j = (Invoke-RestMethod -Uri '{api_url}' -Headers $h -TimeoutSec 15) | ConvertTo-Json -Depth 12 -Compress; "
        f"[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($j)) }} "
        f"catch {{ exit 1 }}"
    )
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, encoding="ascii", errors="ignore", timeout=30,
        )
        if r.returncode != 0 or not r.stdout.strip():
            return None
        raw = _base64.b64decode(r.stdout.strip()).decode("utf-8")
        return _json.loads(raw)
    except Exception:
        return None


def _bb_get_reviewers_hint(project: str, repo: str) -> list | None:
    """
    Bitbucket Server default-reviewers 플러그인 API로 지정 리뷰어를 best-effort 조회한다.
    GET /rest/default-reviewers/1.0/projects/{project}/repos/{repo}/conditions
    플러그인 미설치(404) 등 어떤 실패든 조용히 None을 반환한다 (참고용 보조 신호이므로).
    """
    api_url = (
        f"{BITBUCKET_BASE_URL}/rest/default-reviewers/1.0/projects/{project}"
        f"/repos/{repo}/conditions"
    )
    try:
        conditions = _bb_get_json_via_powershell(api_url)
        if conditions is None:
            return None
        # Invoke-RestMethod가 top-level JSON 배열을 반환하는 엔드포인트인데,
        # PowerShell ConvertTo-Json은 원소가 1개(또는 0개)면 배열을 스칼라로 축약하는 경우가 있어 방어적으로 정규화
        if isinstance(conditions, dict):
            conditions = [conditions]
        seen = set()
        hint = []
        for cond in conditions:
            for reviewer in cond.get("reviewers", []):
                email = reviewer.get("emailAddress")
                name = reviewer.get("displayName") or reviewer.get("name")
                label = f"{name} <{email}>" if email else (name or None)
                if label and label not in seen:
                    seen.add(label)
                    hint.append(label)
                if len(hint) >= 5:
                    return hint
        return hint or None
    except Exception:
        return None


def _determine_maintainer(project: str, repo: str, months: int = 6) -> dict | None:
    """
    Bitbucket Server API로 최근 N개월 커밋 빈도를 집계해 실제 담당자를 판별한다.
    GET /rest/api/1.0/projects/{project}/repos/{repo}/commits (페이지네이션, limit=100)

    - cutoff 기준점은 "지금(now)"이 아니라 **해당 레포의 최신 커밋(HEAD) 시각**이다.
      오랫동안 방치된 레포는 마지막 커밋 자체가 6개월보다 앞설 수 있어, now 기준으로 자르면
      빈 결과(counts={})가 나와 last_commit_author로만 폴백하게 된다.
      "최신 커밋 기준 최근 N개월"로 앵커링하면 이런 레포도 항상 유효한 빈도 집계가 나온다.
    - authorTimestamp(ms) 기준 cutoff 이전 커밋을 만나면 페이지 순회를 중단한다.
    - 안전장치: 최대 20페이지(2000커밋)까지만 조회.
    - 저자 키는 emailAddress 우선, 없으면 name.
    - 최다 커밋 저자를 1순위 담당자로 반환.
    - default-reviewers API 결과가 있으면 참고용 reviewers_hint로 병기 (우선순위에는 영향 없음).

    실패(네트워크/HTTP 오류) 시 None 반환 → 호출부에서 last_commit_author로 폴백한다.
    """
    import urllib.parse
    from datetime import datetime as _dt

    counts: dict = {}   # key(email or name) -> count
    labels: dict = {}   # key -> display label "name <email>"
    total = 0
    start = 0
    limit = 100
    MAX_PAGES = 20
    anchor_ts = None    # HEAD(최신) 커밋의 authorTimestamp — 첫 페이지 첫 커밋에서 확정
    cutoff_ms = None

    try:
        for _ in range(MAX_PAGES):
            params = urllib.parse.urlencode({"start": start, "limit": limit})
            api_url = (
                f"{BITBUCKET_BASE_URL}/rest/api/1.0/projects/{project}"
                f"/repos/{repo}/commits?{params}"
            )
            data = _bb_get_json_via_powershell(api_url)
            if data is None:
                raise RuntimeError("PowerShell relay(Invoke-RestMethod) 호출 실패 — commits API")

            values = data.get("values", [])
            if anchor_ts is None and values:
                # Bitbucket commits API는 최신 커밋이 첫 값으로 온다 → 이를 "지금" 대신 앵커로 사용
                anchor_ts = values[0].get("authorTimestamp") or int(_dt.now().timestamp() * 1000)
                cutoff_ms = anchor_ts - (30 * months * 24 * 60 * 60 * 1000)

            reached_cutoff = False
            for commit in values:
                ts = commit.get("authorTimestamp") or 0
                if cutoff_ms is not None and ts < cutoff_ms:
                    reached_cutoff = True
                    break
                author = commit.get("author", {})
                email = author.get("emailAddress")
                name = author.get("name") or "알수없음"
                key = email or name
                counts[key] = counts.get(key, 0) + 1
                labels[key] = f"{name} <{email}>" if email else name
                total += 1

            if reached_cutoff or data.get("isLastPage", True):
                break
            start = data.get("nextPageStart", start + limit)

        if not counts:
            return None

        top_key = max(counts, key=counts.get)
        anchor_date = (
            _dt.fromtimestamp(anchor_ts / 1000).strftime("%Y-%m-%d") if anchor_ts else None
        )
        raw_label = labels[top_key]
        raw_name, raw_email = _split_name_email(raw_label)
        normalized_label, unresolved_team, maintainer_status = _normalize_maintainer_label(raw_name, raw_email)
        return {
            "maintainer": normalized_label,
            "maintainer_raw": raw_label,
            "maintainer_unresolved_team": unresolved_team,
            "maintainer_status": maintainer_status,
            "maintainer_commit_count": counts[top_key],
            "maintainer_window_months": months,
            "maintainer_window_anchor": anchor_date,
            "sample_commit_total": total,
            "reviewers_hint": _bb_get_reviewers_hint(project, repo),
        }
    except Exception as e:
        print(f"[WARN] 담당자 판별 API 실패 — last_commit_author로 폴백: {e.__class__.__name__}: {e}")
        return None


def _split_name_email(label: str) -> tuple[str, str]:
    """"이름 <email>" 또는 "이름"(이메일 없음) 형태의 라벨을 (name, email)로 분리한다."""
    m = re.match(r"^(?P<name>.*?)\s*<(?P<email>[^>]+)>\s*$", label or "")
    if m:
        return m.group("name").strip(), m.group("email").strip()
    return (label or "").strip(), ""


_MAINTAINER_CACHE: dict | None = None


def _load_maintainer_cache() -> dict:
    global _MAINTAINER_CACHE
    if _MAINTAINER_CACHE is None:
        try:
            _MAINTAINER_CACHE = json.loads(MAINTAINER_CACHE_PATH.read_text(encoding="utf-8"))
        except Exception:
            _MAINTAINER_CACHE = {}
    return _MAINTAINER_CACHE


def _jira_lookup_display_name(email: str) -> str | None:
    """Jira 사용자 검색 API로 이메일 기준 displayName을 best-effort 조회한다. 실패 시 None."""
    if not email:
        return None
    try:
        import requests

        env = jira_utils.load_env()
        jira_url = env.get("JIRA_URL", "").rstrip("/")
        if not jira_url:
            return None
        headers = jira_utils.jira_headers(env)
        resp = requests.get(
            f"{jira_url}/rest/api/2/user/search",
            params={"username": email},
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        results = resp.json()
        if results:
            return results[0].get("displayName")
        return None
    except Exception:
        return None


def _normalize_maintainer_label(name: str, email: str) -> tuple[str, bool, str]:
    """
    (name, email) 원시 조합을 통일된 표기로 변환한다.

    - 사내(INTERNAL_EMAIL_DOMAINS): "{이름}({영문명})/{팀명}/SKP <{이메일}>"
      1) 캐시에 status="퇴사"(또는 "departed") 마킹 → "{이름} <{이메일}> (퇴사 확인됨)"
      2) shared/references/maintainer_directory_cache.json 이메일 매칭(+팀 정보 존재) → 이름/영문명/팀 사용
      3) 캐시(팀 없음) 또는 Jira user/search API(best-effort)로 실제 displayName 확보 성공 → 팀은 "미확인"
      4) 캐시/Jira 모두 실패(사람 자체를 확인할 수 없음 — 퇴사/조직변경 등 가능성) → "(확인불가)" 태그, 원본 name/사번을 그대로 노출
    - 외주(그 외 도메인): "{이름 또는 git계정} <{이메일}> (외주)"

    반환값: (정규화된 라벨, 소속팀 미확인 여부, 상태 태그)
      상태 태그: "resolved" | "unresolved_team" | "unconfirmed" | "departed" | "external" | "invalid"
    """
    email = (email or "").strip()
    name = (name or "").strip()

    if not email:
        return (f"{name or '알수없음'} (확인불가)", True, "invalid")

    domain = email.split("@")[-1].lower()
    if domain not in INTERNAL_EMAIL_DOMAINS:
        return (f"{name or email} <{email}> (외주)", False, "external")

    cache = _load_maintainer_cache()
    entry = cache.get(email.lower())

    if entry and entry.get("status") in ("퇴사", "departed"):
        display = entry.get("name_kr") or name or email.split("@")[0]
        return (f"{display} <{email}> (퇴사 확인됨)", True, "departed")

    if entry and entry.get("team"):
        name_kr = entry.get("name_kr") or name
        name_en = entry.get("name_en")
        team = entry["team"]
        label = f"{name_kr}({name_en})/{team}/SKP <{email}>" if name_en else f"{name_kr}/{team}/SKP <{email}>"
        return (label, False, "resolved")

    # 캐시(이름만) 또는 Jira 조회로 "실존이 확인된 이름"을 얻은 경우에 한해 미확인 처리.
    # (주의: name은 git commit author의 raw 표기 — 사번 등 신뢰할 수 없는 값일 수 있어 fallback으로 쓰지 않는다)
    resolved_display_name = (entry or {}).get("name_kr") or _jira_lookup_display_name(email)
    if resolved_display_name:
        return (f"{resolved_display_name}/미확인/SKP <{email}>", True, "unresolved_team")

    # 캐시/Jira 모두 미매칭 — 사내 도메인이지만 이 사람의 실존 자체를 확인할 수 없음(퇴사 가능성 포함)
    fallback_display = name or email.split("@")[0]
    return (f"{fallback_display} <{email}> (확인불가)", True, "unconfirmed")


# ── Clone 실행 ────────────────────────────────────────────────────────────────

def _is_wsl() -> bool:
    """현재 환경이 WSL(Windows Subsystem for Linux)인지 확인한다."""
    if sys.platform != "linux":
        return False
    try:
        return "microsoft" in Path("/proc/version").read_text().lower()
    except Exception:
        return False


def _wsl_to_windows_path(path: Path) -> str:
    """WSL 경로를 Windows UNC 경로로 변환한다 (wslpath -w)."""
    result = subprocess.run(
        ["wslpath", "-w", str(path)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"wslpath 변환 실패: {path}")
    return result.stdout.strip()


_GIT_PATH_PREAMBLE = (
    "$env:PATH = 'C:\\Program Files\\Git\\bin;C:\\Program Files\\Git\\cmd;' + $env:PATH; "
)


def _detect_default_branch_via_powershell(
    token: str,
    bare_url: str,
    project: str = "",
    repo_slug: str = "",
    bb_base: str = "",
) -> str | None:
    """
    가장 최근 커밋된 안정 브랜치를 자동 감지한다.

    1차: Bitbucket REST API (orderBy=MODIFICATION) via PowerShell
         → 슬래시 없는 안정 브랜치(main/master/develop 등) 중 최신 커밋 순 1위 반환
    2차 fallback: git ls-remote → main/master/dev/alpha 우선순위
    """
    _STABLE = {"main", "master", "develop", "dev", "alpha"}

    # ── 1차: Bitbucket REST API ───────────────────────────────────────────────
    if project and repo_slug and bb_base:
        api_url = (
            f"{bb_base}/rest/api/1.0/projects/{project}/repos/{repo_slug}"
            f"/branches?orderBy=MODIFICATION&limit=20"
        )
        ps_api = (
            _GIT_PATH_PREAMBLE
            + f"$h = @{{Authorization='Bearer {token}'; Accept='application/json'}}; "
            f"try {{ "
            f"  $r = Invoke-RestMethod -Uri '{api_url}' -Headers $h; "
            f"  $r.values | ForEach-Object {{ Write-Output $_.displayId }} "
            f"}} catch {{ exit 1 }}"
        )
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_api],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
        if r.returncode == 0 and r.stdout.strip():
            # API 반환 순서: 최신 커밋 → 오래된 커밋
            all_branches = [b.strip() for b in r.stdout.strip().splitlines() if b.strip()]
            # '/' 없는 안정 브랜치 우선 (feature/release/hotfix 제외)
            stable = [b for b in all_branches if "/" not in b]
            chosen = stable[0] if stable else (all_branches[0] if all_branches else None)
            if chosen:
                print(f"[INFO] 브랜치 자동 감지 (API 최신 커밋 기준): {chosen}")
                if stable and chosen not in _STABLE:
                    print(f"[INFO]  → '{chosen}' (비표준 트렁크 브랜치 — 필요시 --branch로 지정)")
                return chosen

    # ── 2차 fallback: git ls-remote ──────────────────────────────────────────
    ps_ls = (
        _GIT_PATH_PREAMBLE
        + f"git -c credential.helper= "
        f"-c http.extraHeader='Authorization: Bearer {token}' "
        f"ls-remote --heads '{bare_url}'"
    )
    r = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_ls],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
    )
    branches = []
    for line in (r.stdout or "").splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[1].startswith("refs/heads/"):
            branches.append(parts[1].replace("refs/heads/", ""))
    if not branches:
        return None  # ls-remote 실패 또는 빈 레포 → --branch 없이 clone
    print(f"[INFO] 브랜치 자동 감지 (ls-remote 우선순위 fallback): {branches}")
    for preferred in ("main", "master", "dev", "alpha"):
        if preferred in branches:
            return preferred
    return branches[0]


def _git_clone_via_powershell(token: str, bare_url: str, dest: Path, branch: str | None) -> subprocess.CompletedProcess:
    """
    WSL에서 PowerShell(Windows git)을 통해 git clone을 실행한다.
    WSL의 git은 회사 Bitbucket에 네트워크 접근 불가(No route to host)이므로
    Windows git + Bearer 헤더 인증으로 WSL 경로에 직접 clone한다.
    branch=None 이면 --branch 플래그 생략 (원격 기본 브랜치 사용).
    """
    win_dest = _wsl_to_windows_path(dest)
    branch_flag = f"--branch '{branch}' " if branch else ""
    ps_cmd = (
        _GIT_PATH_PREAMBLE
        + f"git -c credential.helper= "
        f"-c http.extraHeader='Authorization: Bearer {token}' "
        f"clone {branch_flag}--depth 1 '{bare_url}' '{win_dest}'"
    )
    branch_label = branch if branch else "(원격 기본 브랜치)"
    print(f"[INFO] WSL 환경 감지 — PowerShell(Windows git) Bearer 인증 경유 clone")
    print(f"[INFO] 브랜치: {branch_label}  |  대상 경로(Windows): {win_dest}")
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
        capture_output=True, text=True,
    )


def clone_repo(project: str, repo: str, branch: str | None = None, force: bool = False) -> Path:
    """
    레포를 testbed/<repo>/ 에 clone하고 경로를 반환한다.
    이미 존재하면 pull로 업데이트 (force=True이면 삭제 후 재clone).
    WSL 환경에서는 PowerShell(Windows git)을 경유하여 clone한다.

    branch=None (기본) → 가장 최근 커밋된 안정 브랜치 자동 선택
    branch 명시       → 해당 브랜치 강제 사용
    """
    if not CUSTOMER_BB_TOKEN:
        print("[ERROR] CUSTOMER_BB_TOKEN이 .env에 설정되지 않았습니다.", file=sys.stderr)
        sys.exit(1)

    dest: Path = TESTBED_DIR / repo
    TESTBED_DIR.mkdir(parents=True, exist_ok=True)

    branch_label = branch if branch else "(자동 감지)"
    print(f"[INFO] 대상 레포: {project}/{repo}  (브랜치: {branch_label})")
    print(f"[INFO] Bitbucket API 조회 중: {BITBUCKET_BASE_URL}")

    clone_url  = _get_clone_url(project, repo)
    authed_url = _inject_token_to_url(clone_url, CUSTOMER_BB_TOKEN)
    safe_url   = clone_url  # 로그 출력용 (토큰 미포함)

    if dest.exists() and (dest / ".git").exists():
        if force:
            print(f"[INFO] 기존 디렉터리 삭제 후 재clone: {dest}")
            import shutil
            shutil.rmtree(dest)
        else:
            print(f"[INFO] 이미 존재 — git pull: {dest}")
            result = subprocess.run(
                ["git", "-C", str(dest), "pull", "--ff-only"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                print(f"[WARN] pull 실패, 수동 확인 필요:\n{result.stderr}", file=sys.stderr)
            else:
                print(f"[OK] 업데이트 완료: {dest}")
                # pull로 HEAD가 바뀌었을 수 있으므로 커밋 해시/담당자 갱신 후 repo_meta.json 재동기화
                rev = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                                      capture_output=True, text=True)
                info_path = dest / ".clone_info.json"
                if rev.returncode == 0 and info_path.exists():
                    import json as _json
                    try:
                        info = _json.loads(info_path.read_text(encoding="utf-8"))
                        info["commit_hash"] = rev.stdout.strip()

                        log = subprocess.run(
                            ["git", "-C", str(dest), "log", "-1", "--format=%an <%ae>"],
                            capture_output=True, text=True,
                        )
                        if log.returncode == 0 and log.stdout.strip():
                            info["last_commit_author"] = log.stdout.strip()

                        maintainer_info = _determine_maintainer(project, repo)
                        maintainer = (maintainer_info or {}).get("maintainer") or info.get("last_commit_author")
                        info["maintainer"] = maintainer
                        info["maintainer_commit_count"] = (maintainer_info or {}).get("maintainer_commit_count")
                        info["maintainer_window_months"] = (maintainer_info or {}).get("maintainer_window_months")
                        info["maintainer_window_anchor"] = (maintainer_info or {}).get("maintainer_window_anchor")
                        info["sample_commit_total"] = (maintainer_info or {}).get("sample_commit_total")
                        info["reviewers_hint"] = (maintainer_info or {}).get("reviewers_hint")
                        if maintainer_info:
                            print(
                                f"[INFO] 담당자(최근 커밋 {maintainer_info['maintainer_window_anchor']} 기준 "
                                f"{maintainer_info['maintainer_window_months']}개월 이내 커밋 "
                                f"{maintainer_info['maintainer_commit_count']}건/{maintainer_info['sample_commit_total']}건 중): "
                                f"{maintainer_info['maintainer']}"
                            )

                        info_path.write_text(_json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
                        _write_repo_meta(repo, info)
                        _update_inventory_maintainer(repo, maintainer)
                    except Exception:
                        pass
            return dest

    # WSL이면 PowerShell(Windows git) 경유로 clone, 아니면 Windows git 직접 실행
    if _is_wsl():
        # 브랜치 자동 감지 (branch=None이면 자동 감지, 명시 지정이면 그대로 사용)
        if branch is None:
            detected_branch = _detect_default_branch_via_powershell(
                CUSTOMER_BB_TOKEN, clone_url,
                project=project, repo_slug=repo, bb_base=BITBUCKET_BASE_URL,
            )
            if detected_branch is None:
                print(f"[INFO] 브랜치 자동 감지 실패 → 원격 기본 브랜치로 clone")
            branch = detected_branch
        print(f"[INFO] Clone 시작: {safe_url} → {dest}")
        result = _git_clone_via_powershell(CUSTOMER_BB_TOKEN, clone_url, dest, branch)
    else:
        # Windows Python 환경: powershell.exe 경유로 git clone
        if branch is None:
            detected_branch = _detect_default_branch_via_powershell(
                CUSTOMER_BB_TOKEN, clone_url,
                project=project, repo_slug=repo, bb_base=BITBUCKET_BASE_URL,
            )
            if detected_branch is None:
                print(f"[INFO] 브랜치 자동 감지 실패 → 원격 기본 브랜치로 clone")
                branch_flag = ""
                branch_label = "(원격 기본 브랜치)"
            else:
                branch = detected_branch
                branch_flag = f"--branch '{branch}' "
                branch_label = branch
        else:
            branch_flag = f"--branch '{branch}' "
            branch_label = branch
        win_dest = str(dest)
        ps_cmd = (
            _GIT_PATH_PREAMBLE
            + f"git -c credential.helper= "
            f"-c http.extraHeader='Authorization: Bearer {CUSTOMER_BB_TOKEN}' "
            f"clone {branch_flag}--depth 1 '{clone_url}' '{win_dest}'"
        )
        print(f"[INFO] Clone 시작 (Windows git via PowerShell): {safe_url} → {dest}  [브랜치: {branch_label}]")
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True,
        )

    if result.returncode != 0:
        # stderr에 토큰이 노출될 수 있으므로 마스킹
        err = result.stderr.replace(CUSTOMER_BB_TOKEN, "****")
        print(f"[ERROR] Clone 실패:\n{err}", file=sys.stderr)
        sys.exit(1)

    print(f"[OK] Clone 완료: {dest}")

    # HEAD 커밋 해시 캡처
    commit_hash = None
    try:
        rev = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True, text=True,
        )
        if rev.returncode == 0:
            commit_hash = rev.stdout.strip()
            print(f"[INFO] HEAD commit: {commit_hash}")
    except Exception:
        pass

    # 마지막 커밋 작성자 캡처 (fallback용 담당자 정보)
    last_commit_author = None
    try:
        log = subprocess.run(
            ["git", "-C", str(dest), "log", "-1", "--format=%an <%ae>"],
            capture_output=True, text=True,
        )
        if log.returncode == 0 and log.stdout.strip():
            last_commit_author = log.stdout.strip()
    except Exception:
        pass

    # 실제 담당자 판별 (최근 N개월 커밋 빈도 기반, Bitbucket API)
    maintainer_info = _determine_maintainer(project, repo)
    maintainer = (maintainer_info or {}).get("maintainer") or last_commit_author
    if maintainer_info:
        print(
            f"[INFO] 담당자(최근 커밋 {maintainer_info['maintainer_window_anchor']} 기준 "
            f"{maintainer_info['maintainer_window_months']}개월 이내 커밋 "
            f"{maintainer_info['maintainer_commit_count']}건/{maintainer_info['sample_commit_total']}건 중): "
            f"{maintainer_info['maintainer']}"
        )
        if maintainer_info.get("reviewers_hint"):
            print(f"[INFO] 참고: 지정 리뷰어 — {', '.join(maintainer_info['reviewers_hint'])}")
    else:
        print(f"[INFO] 담당자(last commit, 폴백): {last_commit_author}")

    # .clone_info.json 저장 (palantir-testbed에서 git 추적용)
    import json as _json
    from datetime import datetime as _dt
    info = {
        "project":            project,
        "repo":               repo,
        "branch":             branch,
        "commit_hash":        commit_hash,
        "last_commit_author": last_commit_author,
        "maintainer":                 maintainer,
        "maintainer_commit_count":    (maintainer_info or {}).get("maintainer_commit_count"),
        "maintainer_window_months":   (maintainer_info or {}).get("maintainer_window_months"),
        "maintainer_window_anchor":   (maintainer_info or {}).get("maintainer_window_anchor"),
        "sample_commit_total":        (maintainer_info or {}).get("sample_commit_total"),
        "reviewers_hint":             (maintainer_info or {}).get("reviewers_hint"),
        "clone_url":          clone_url,
        "cloned_at":          _dt.now().isoformat(),
        "base_url":           BITBUCKET_BASE_URL,
    }
    (dest / ".clone_info.json").write_text(
        _json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # state/<repo>/repo_meta.json 에도 동일 저장 — testbed 삭제(클렌징) 이후에도
    # approve_report.py/generate_final_report.py가 레포 메타데이터를 읽을 수 있도록
    # testbed 밖의 영속 위치에 복제한다. (testbed/.clone_info.json은 클렌징 시 함께 삭제됨)
    _write_repo_meta(repo, info)

    # service_inventory.json 담당자 갱신
    _update_inventory_maintainer(repo, maintainer)

    return dest


def _write_repo_meta(repo: str, info: dict) -> None:
    """clone 시점의 레포 메타데이터를 state/<repo>/repo_meta.json 에 영속 저장한다."""
    import json as _json
    meta_dir = STATE_DIR / repo
    meta_dir.mkdir(parents=True, exist_ok=True)
    (meta_dir / "repo_meta.json").write_text(
        _json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _update_inventory_maintainer(repo: str, author: str | None) -> None:
    """service_inventory.json 의 해당 레포 maintainer 필드를 갱신한다."""
    if not author:
        return
    inv_path = Path(__file__).resolve().parent.parent / "docs" / "service_inventory.json"
    if not inv_path.exists():
        return
    import json as _json
    try:
        data = _json.loads(inv_path.read_text(encoding="utf-8"))
        for svc in data.get("services", []):
            if svc.get("repo") == repo:
                svc["maintainer"] = author
                break
        inv_path.write_text(_json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[WARN] service_inventory.json 갱신 실패: {e}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="code.skplanet.com Bitbucket Server repo clone 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("project",  help="Bitbucket 프로젝트 키 (예: PROJ)")
    parser.add_argument("repo",     help="레포 슬러그 (예: my-service)")
    parser.add_argument("--branch", default=None,
                        help="대상 브랜치 (기본: 자동 감지 — 최신 커밋 기준)")
    parser.add_argument("--force",  action="store_true",
                        help="이미 존재하면 삭제 후 재clone")
    args = parser.parse_args()

    dest = clone_repo(args.project, args.repo, args.branch, args.force)
    print(f"\n진단 대상 경로: {dest}")
    print(f"다음 명령으로 진단을 시작하세요:")
    print(f"  /sec-scan-injection  (또는 원하는 skill)")


if __name__ == "__main__":
    main()
