#!/usr/bin/env python3
"""
push_audit_result.py — 진단이력을 VULCHK/audit_result 레포에 업로드

  python3 tools/push_audit_result.py --repo <repo> [--run-id <RUN_ID>]

사전 조건 (.env):
  BITBUCKET_TOKEN=<PAT>   (이것만 있으면 됨)

동작:
  1. state/<repo>/에서 findings_*.json, scan_meta.json 수집
     logs/final_<repo>_*.md 수집
  2. C:\\Windows\\Temp\\audit_result_ws\\ 를 git workspace로 자동 관리
     (없으면 clone, 있으면 pull)
  3. <repo>/<폴더명>/ 에 파일 복사
  4. PowerShell 경유 git push (WSL → code.skplanet.com 직접 불가)

저장 구조 (VULCHK/audit_result):
  <repo>/<RUN_ID or YYYYMMDD_HHMM>/
    findings_INJ.json  findings_XSS.json  findings_FILE.json
    findings_DATA.json  findings_SCA.json
    scan_meta.json
    final_<repo>_<date>.md
"""

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_scan_gate

PALANTIR_DIR = Path(__file__).resolve().parent.parent
STATE_DIR    = PALANTIR_DIR / "state"
LOGS_DIR     = PALANTIR_DIR / "logs"

SKILL_ORDER   = ["injection", "xss", "file", "data", "sca"]
BB_REMOTE_URL = os.environ.get("AUDIT_RESULT_REPO_URL", "")

# PowerShell 실행 파일 (WSL에서 접근)
PSEXE      = "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe"


def _resolve_win_temp() -> tuple[Path, str]:
    """사용자 소유 %TEMP%를 동적 조회.
    C:\\Windows\\Temp는 도메인 PC 정책상 일반 계정에 삭제 권한이 없는 경우가 있어
    (BUILTIN\\Users: CreateFiles/AppendData만 허용) git workspace로 부적합하다."""
    try:
        result = subprocess.run(
            [PSEXE, "-NoProfile", "-NonInteractive", "-Command", "$env:TEMP"],
            capture_output=True, text=True, timeout=15,
        )
        win_temp = result.stdout.strip()
        if win_temp and ":\\" in win_temp:
            drive, rest = win_temp.split(":\\", 1)
            return Path(f"/mnt/{drive.lower()}/{rest.replace(chr(92), '/')}"), win_temp
    except Exception:
        pass
    return Path("/mnt/c/Windows/Temp"), "C:\\Windows\\Temp"


_TEMP_WSL, _TEMP_WIN = _resolve_win_temp()
# git workspace (clone of audit_result, git 전용)
WS_WSL     = _TEMP_WSL / "audit_result_ws"
WS_WIN     = f"{_TEMP_WIN}\\audit_result_ws"
# staging area (Python이 state/ 파일을 여기에 복사, PowerShell이 workspace로 이동)
STAGE_WSL  = _TEMP_WSL / "audit_result_stage"
STAGE_WIN  = f"{_TEMP_WIN}\\audit_result_stage"
PS_TMP_WSL = _TEMP_WSL / "push_audit_result.ps1"
PS_TMP_WIN = f"{_TEMP_WIN}\\push_audit_result.ps1"


def _load_env() -> dict:
    env = {}
    env_path = PALANTIR_DIR / ".env"
    if not env_path.exists():
        return env
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().split("#")[0].strip()
    return env


def _collect_findings(repo: str, run_id: str | None) -> list[Path]:
    paths = []
    repo_dir = STATE_DIR / repo
    if not repo_dir.is_dir():
        return paths
    for skill in SKILL_ORDER:
        skill_dir = repo_dir / skill
        if not skill_dir.is_dir():
            continue
        if run_id:
            candidate_dirs: list[Path] = [skill_dir / run_id]
        else:
            candidate_dirs = sorted(
                (d for d in skill_dir.iterdir() if d.is_dir()),
                key=lambda d: d.name,
                reverse=True,
            )
        for d in candidate_dirs:
            if not d.is_dir():
                continue
            files = sorted(d.glob("findings_*.json"))
            if files:
                paths.append(files[0])
                break
    return paths


def _collect_repo_meta(repo: str) -> Path | None:
    """repo 레벨(run_id 무관) 메타데이터 — clone_repo.py가 clone 시점에 기록."""
    meta = STATE_DIR / repo / "repo_meta.json"
    return meta if meta.exists() else None


def _collect_scan_meta(repo: str, run_id: str | None) -> Path | None:
    repo_dir = STATE_DIR / repo
    if not repo_dir.is_dir():
        return None
    for skill in SKILL_ORDER:
        skill_dir = repo_dir / skill
        if not skill_dir.is_dir():
            continue
        if run_id:
            candidate_dirs: list[Path] = [skill_dir / run_id]
        else:
            candidate_dirs = sorted(
                (d for d in skill_dir.iterdir() if d.is_dir()),
                key=lambda d: d.name,
                reverse=True,
            )
        for d in candidate_dirs:
            if not d.is_dir():
                continue
            meta = d / "scan_meta.json"
            if meta.exists():
                return meta
    return None


def _collect_final_report(repo: str, run_id: str | None) -> Path | None:
    if run_id:
        candidates = list(LOGS_DIR.glob(f"final_{repo}_{run_id}.md"))
    else:
        candidates = sorted(LOGS_DIR.glob(f"final_{repo}_*.md"))
    return candidates[-1] if candidates else None


def _run_powershell(ps_script: str) -> int:
    """PS1 파일로 저장 후 PowerShell 실행."""
    try:
        PS_TMP_WSL.write_text(ps_script, encoding="utf-8-sig")
    except Exception as e:
        print(f"  [WARN] PS1 임시 파일 생성 실패: {e} — 인라인 실행")
        result = subprocess.run([PSEXE, "-NoProfile", "-NonInteractive", "-Command", ps_script])
        return result.returncode

    result = subprocess.run([
        PSEXE, "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", PS_TMP_WIN,
    ])
    try:
        PS_TMP_WSL.unlink()
    except Exception:
        pass
    return result.returncode


def push(repo: str, run_id: str | None = None, folder: str | None = None) -> int:
    """
    진단이력 업로드 메인 로직.
    approve_report.py 에서 import 후 직접 호출 가능.

    반환: 0=성공, 1=설정 오류, 2=git push 실패(파일은 로컬에 보존)
    """
    env   = _load_env()
    token = env.get("BITBUCKET_TOKEN", "")

    if not token:
        print("  [ERROR] .env에 BITBUCKET_TOKEN 미설정")
        return 1

    remote_url = env.get("AUDIT_RESULT_REPO_URL", "") or BB_REMOTE_URL
    if not remote_url:
        print("  [ERROR] .env에 AUDIT_RESULT_REPO_URL 미설정")
        return 1

    # 파일 수집
    findings     = _collect_findings(repo, run_id)
    scan_meta    = _collect_scan_meta(repo, run_id)
    final_report = _collect_final_report(repo, run_id)
    repo_meta    = _collect_repo_meta(repo)

    if not findings:
        print(f"  [ERROR] findings 파일 없음 — state/{repo}/*/")
        return 1

    # 저장 폴더명: 지정 > RUN_ID > 오늘 날짜 (같은 날 재실행 시 git no-changes로 중복 방지)
    folder_name = folder or run_id or datetime.now().strftime("%Y%m%d")
    dest_wsl    = STAGE_WSL / repo / folder_name
    dest_wsl.mkdir(parents=True, exist_ok=True)

    print(f"\n  대상 폴더: {repo}/{folder_name}/")

    # 파일 복사 (state → Windows Temp workspace)
    copied: list[str] = []
    copied_paths: list[Path] = []
    for f in findings:
        dst = dest_wsl / f.name
        shutil.copy2(f, dst)
        print(f"  [+] {f.name}")
        copied.append(f.name)
        copied_paths.append(dst)

    if scan_meta:
        dst = dest_wsl / "scan_meta.json"
        shutil.copy2(scan_meta, dst)
        print(f"  [+] scan_meta.json")
        copied.append("scan_meta.json")
        copied_paths.append(dst)
    else:
        print("  [-] scan_meta.json — 없음, 생략")

    if final_report:
        dst = dest_wsl / final_report.name
        shutil.copy2(final_report, dst)
        print(f"  [+] {final_report.name}")
        copied.append(final_report.name)
        copied_paths.append(dst)
    else:
        print("  [-] final_*.md — 없음, 생략")

    if repo_meta:
        # repo_meta.json은 run_id와 무관한 repo 레벨 파일 — 날짜 폴더가 아닌 <repo>/ 루트에 저장
        dst = STAGE_WSL / repo / "repo_meta.json"
        shutil.copy2(repo_meta, dst)
        print(f"  [+] repo_meta.json (repo 레벨)")
        copied.append("repo_meta.json")
        copied_paths.append(dst)
    else:
        print("  [-] repo_meta.json — 없음, 생략")

    # 업로드 직전 최후 방어선: 마스킹 누락 시크릿 원문 검사 (2026-08-07 ocb-nft-batch 사고 재발방지)
    gate_violations = secret_scan_gate.scan_paths(copied_paths)
    if gate_violations:
        print("\n[BLOCKED] 시크릿 원문 패턴이 감지되어 업로드를 중단합니다:")
        for msg in gate_violations:
            print(msg)
        print("  → 상류 마스킹 로직(scan_data_protection.py / generate_final_report.py) 확인 후 재시도하세요.")
        return 1

    print(f"\n  파일 복사 완료 ({len(copied)}개), PowerShell git push 실행 중...")

    subfolder  = f"{repo}\\{folder_name}"
    commit_msg = f"feat: {repo} 진단이력 업로드 ({folder_name})"

    stage_repo_dir = f"{STAGE_WIN}\\{repo}"
    git_auth = f"-c credential.helper= -c \"http.extraHeader=Authorization: Bearer {token}\""

    # PowerShell 스크립트: workspace 자동 관리 + stage 복사 + commit + push
    ps_script = "\n".join([
        "chcp 65001 | Out-Null",
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
        "$OutputEncoding = [System.Text.Encoding]::UTF8",
        "$ErrorActionPreference = 'Continue'",
        "$env:PATH = 'C:\\Program Files\\Git\\bin;C:\\Program Files\\Git\\cmd;' + $env:PATH",
        f"$remote = '{remote_url}'",
        f"$ws     = '{WS_WIN}'",
        "",
        "# workspace 초기화 (3-case: 없음/git있음/파일만있음)",
        "if (-not (Test-Path $ws)) {",
        f"    git {git_auth} clone $remote $ws",
        "    if ($LASTEXITCODE -ne 0) { Write-Error 'clone 실패'; exit $LASTEXITCODE }",
        "} elseif (Test-Path \"$ws\\.git\") {",
        f"    git -C $ws {git_auth} fetch $remote main:refs/remotes/origin/main --force 2>&1 | Out-Null",
        "    if ($LASTEXITCODE -ne 0) {",
        "        Remove-Item -Recurse -Force $ws",
        f"        git {git_auth} clone $remote $ws",
        "        if ($LASTEXITCODE -ne 0) { Write-Error 'clone 실패'; exit $LASTEXITCODE }",
        "    }",
        "} else {",
        "    $tmp = \"${ws}_tmp\"",
        "    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }",
        f"    git {git_auth} clone $remote $tmp",
        "    if ($LASTEXITCODE -ne 0) { Write-Error 'clone 실패'; exit $LASTEXITCODE }",
        "    Move-Item \"$tmp\\.git\" \"$ws\\.git\"",
        "    Remove-Item -Recurse -Force $tmp",
        "    git -C $ws reset origin/main --mixed 2>&1 | Out-Null",
        "}",
        "# 원격 HEAD symref가 존재하지 않는 브랜치(예: master)를 가리키는 경우가 있어",
        "# 로컬 브랜치를 origin/main 기준으로 강제 정렬 (root-commit/non-fast-forward push 방지)",
        "# checkout -B만으로는 더러워진 워킹트리(이전 run의 미커밋 잔여물)가 유지될 수 있어",
        "# reset --hard + clean -fd로 origin/main과 완전히 동일한 상태로 강제 초기화",
        "git -C $ws checkout -B main origin/main 2>&1 | Out-Null",
        "git -C $ws reset --hard origin/main 2>&1 | Out-Null",
        "git -C $ws clean -fd 2>&1 | Out-Null",
        "git -C $ws config core.autocrlf false",
        "",
        "# stage → workspace 복사 (레포 루트 전체: 날짜 폴더 + repo_meta.json)",
        f"$stageRepoDir = '{stage_repo_dir}'",
        f"$destRepoDir  = \"$ws\\{repo}\"",
        "if (Test-Path $stageRepoDir) {",
        "    New-Item -ItemType Directory -Force $destRepoDir | Out-Null",
        "    Copy-Item -Recurse -Force \"$stageRepoDir\\*\" \"$destRepoDir\\\" -ErrorAction SilentlyContinue",
        "}",
        "",
        f"git -C $ws add '{repo}\\'",
        f"git -C $ws commit -m '{commit_msg}'",
        "$commitExit = $LASTEXITCODE",
        "if ($commitExit -eq 0) {",
        f"    git -C $ws {git_auth} push $remote HEAD:refs/heads/main",
        "    exit $LASTEXITCODE",
        "} elseif ($commitExit -eq 1) {",
        "    Write-Host '[INFO] 변경 없음 (already up to date)'",
        "    exit 0",
        "} else {",
        "    Write-Error \"git commit 실패: $commitExit\"",
        "    exit $commitExit",
        "}",
    ])

    rc = _run_powershell(ps_script)

    if rc == 0:
        audit_url = (
            f"https://code.skplanet.com/projects/VULCHK/repos/palantir_result"
            f"/browse/{repo}/{folder_name}"
        )
        print(f"  업로드 완료: {audit_url}")
    else:
        print(f"  [WARN] git push 실패 (returncode={rc}) — 파일은 {WS_WIN}\\{repo}\\{folder_name}\\ 에 보존됨")
        print("  수동 push (Windows PowerShell):")
        print(f"    git -C \"{WS_WIN}\" add \"{repo}\\\"")
        print(f"    git -C \"{WS_WIN}\" commit -m \"{commit_msg}\"")
        print(f"    git -C \"{WS_WIN}\" push")
        return 2

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="진단이력 audit_result 업로드")
    parser.add_argument("--repo",   required=True, help="레포 슬러그")
    parser.add_argument("--run-id", default=None,  help="RUN_ID (YYYYMMDD_HHMM)")
    parser.add_argument("--folder", default=None,  help="저장 폴더명 override")
    args = parser.parse_args()
    return push(args.repo, args.run_id, args.folder)


if __name__ == "__main__":
    sys.exit(main())
