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
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

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

    # 마지막 커밋 작성자 캡처 (담당자 정보)
    last_commit_author = None
    try:
        log = subprocess.run(
            ["git", "-C", str(dest), "log", "-1", "--format=%an <%ae>"],
            capture_output=True, text=True,
        )
        if log.returncode == 0 and log.stdout.strip():
            last_commit_author = log.stdout.strip()
            print(f"[INFO] 담당자(last commit): {last_commit_author}")
    except Exception:
        pass

    # .clone_info.json 저장 (palantir-testbed에서 git 추적용)
    import json as _json
    from datetime import datetime as _dt
    info = {
        "project":            project,
        "repo":               repo,
        "branch":             branch,
        "commit_hash":        commit_hash,
        "last_commit_author": last_commit_author,
        "clone_url":          clone_url,
        "cloned_at":          _dt.now().isoformat(),
        "base_url":           BITBUCKET_BASE_URL,
    }
    (dest / ".clone_info.json").write_text(
        _json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # service_inventory.json 담당자 갱신
    _update_inventory_maintainer(repo, last_commit_author)

    return dest


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
