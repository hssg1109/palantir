#!/usr/bin/env python3
"""
bulk_push_audit_result.py — 여러 레포 진단이력 일괄 업로드

  python3 tools/bulk_push_audit_result.py [--repos repo1,repo2,...] [--dry-run]

  --repos  없으면 logs/final_*.md 에서 최신 보고서가 있는 레포 전체 자동 수집
  --dry-run  파일 복사만, git push 생략

동작:
  1. 모든 레포의 findings/scan_meta/final 파일을 Windows Temp workspace에 복사
  2. PowerShell 1회로 전체 일괄 git push (레포별 18회 아님)
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PALANTIR_DIR = Path(__file__).resolve().parent.parent
STATE_DIR    = PALANTIR_DIR / "state"
LOGS_DIR     = PALANTIR_DIR / "logs"

SKILL_ORDER   = ["injection", "xss", "file", "data", "sca"]
BB_REMOTE_URL = os.environ.get("AUDIT_RESULT_REPO_URL", "")

PSEXE        = "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe"
# git workspace (clone of audit_result)
WS_WSL       = Path("/mnt/c/Windows/Temp/audit_result_ws")
WS_WIN       = "C:\\Windows\\Temp\\audit_result_ws"
# staging area (Python copies files here, then PowerShell copies into workspace)
STAGE_WSL    = Path("/mnt/c/Windows/Temp/audit_result_stage")
STAGE_WIN    = "C:\\Windows\\Temp\\audit_result_stage"
PS_TMP_WSL   = Path("/mnt/c/Windows/Temp/bulk_push.ps1")
PS_TMP_WIN   = "C:\\Windows\\Temp\\bulk_push.ps1"


def _load_token() -> str:
    env_path = PALANTIR_DIR / ".env"
    if not env_path.exists():
        return ""
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("BITBUCKET_TOKEN="):
            return line.split("=", 1)[1].strip().split("#")[0].strip()
    return ""


def _latest_final_report(repo: str) -> Path | None:
    candidates = sorted(LOGS_DIR.glob(f"final_{repo}_*.md"))
    return candidates[-1] if candidates else None


def _report_date(path: Path) -> str:
    m = re.search(r"_(\d{8})(?:_\d{4})?\.md$", path.name)
    return m.group(1) if m else datetime.now().strftime("%Y%m%d")


def _discover_repos() -> list[tuple[str, Path]]:
    """logs/final_*.md 에서 레포별 최신 보고서 수집."""
    seen: dict[str, Path] = {}
    for f in sorted(LOGS_DIR.glob("final_*.md")):
        # final_<repo>_<date>.md → repo 추출
        m = re.match(r"final_(.+?)_\d{8}(?:_\d{4})?\.md$", f.name)
        if not m:
            continue
        repo = m.group(1)
        if repo not in seen or f.name > seen[repo].name:
            seen[repo] = f
    return sorted(seen.items())


def _collect_findings(repo: str) -> list[Path]:
    paths = []
    repo_dir = STATE_DIR / repo
    if not repo_dir.is_dir():
        return paths
    for skill in SKILL_ORDER:
        skill_dir = repo_dir / skill
        if not skill_dir.is_dir():
            continue
        run_dirs = sorted(
            (d for d in skill_dir.iterdir() if d.is_dir() and re.match(r"\d{8}_\d{4}", d.name)),
            key=lambda d: d.name,
            reverse=True,
        )
        for d in run_dirs:
            files = sorted(d.glob("findings_*.json"))
            if files:
                paths.append(files[0])
                break
    return paths


def _collect_scan_meta(repo: str) -> Path | None:
    repo_dir = STATE_DIR / repo
    if not repo_dir.is_dir():
        return None
    for skill in SKILL_ORDER:
        skill_dir = repo_dir / skill
        if not skill_dir.is_dir():
            continue
        run_dirs = sorted(
            (d for d in skill_dir.iterdir() if d.is_dir() and re.match(r"\d{8}_\d{4}", d.name)),
            key=lambda d: d.name,
            reverse=True,
        )
        for d in run_dirs:
            meta = d / "scan_meta.json"
            if meta.exists():
                return meta
    return None


def _run_powershell(ps_script: str) -> int:
    try:
        PS_TMP_WSL.write_text(ps_script, encoding="utf-8-sig")
    except Exception as e:
        print(f"[WARN] PS1 임시 파일 생성 실패: {e} — 인라인 실행")
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


def main() -> int:
    parser = argparse.ArgumentParser(description="진단이력 일괄 업로드")
    parser.add_argument("--repos",   default=None, help="쉼표 구분 레포 목록 (생략 시 자동)")
    parser.add_argument("--dry-run", action="store_true", help="파일 복사만, git push 생략")
    args = parser.parse_args()

    token = _load_token()
    if not token and not args.dry_run:
        print("[ERROR] .env에 BITBUCKET_TOKEN 미설정")
        return 1

    # 대상 레포 목록 구성
    if args.repos:
        repo_entries: list[tuple[str, Path | None]] = []
        for r in args.repos.split(","):
            r = r.strip()
            repo_entries.append((r, _latest_final_report(r)))
    else:
        repo_entries = [(r, p) for r, p in _discover_repos()]

    if not repo_entries:
        print("[ERROR] 업로드 대상 레포 없음")
        return 1

    print(f"=== 일괄 업로드 대상: {len(repo_entries)}개 레포 ===\n")

    # ── 1. 파일 복사 ─────────────────────────────────────────
    copied_repos: list[str] = []
    skipped_repos: list[str] = []

    for repo, final_report in repo_entries:
        findings  = _collect_findings(repo)
        scan_meta = _collect_scan_meta(repo)

        if not findings:
            print(f"  [-] {repo:<40} findings 없음, 건너뜀")
            skipped_repos.append(repo)
            continue

        folder_name = _report_date(final_report) if final_report else datetime.now().strftime("%Y%m%d")
        dest_wsl    = STAGE_WSL / repo / folder_name
        dest_wsl.mkdir(parents=True, exist_ok=True)

        n = 0
        for f in findings:
            shutil.copy2(f, dest_wsl / f.name)
            n += 1
        if scan_meta:
            shutil.copy2(scan_meta, dest_wsl / "scan_meta.json")
            n += 1
        if final_report:
            shutil.copy2(final_report, dest_wsl / final_report.name)
            n += 1

        print(f"  [+] {repo:<40} → stage/{repo}/{folder_name}/  ({n}개)")
        copied_repos.append(repo)

    if not copied_repos:
        print("\n[ERROR] 복사된 파일 없음 — 업로드 중단")
        return 1

    print(f"\n  복사 완료: {len(copied_repos)}개 레포 / 건너뜀: {len(skipped_repos)}개")

    if args.dry_run:
        print("\n[dry-run] git push 생략")
        return 0

    # ── 2. PowerShell 일괄 git push ───────────────────────────
    commit_msg = f"feat: 진단이력 일괄 업로드 {datetime.now().strftime('%Y%m%d')} ({len(copied_repos)}개 레포)"

    print(f"\n[git] PowerShell push 실행 중 (1회)...")

    # git auth: Bearer header 방식 (x-token-auth URL 삽입보다 안정적)
    git_auth = f"-c credential.helper= -c \"http.extraHeader=Authorization: Bearer {token}\""

    ps_script = "\n".join([
        "chcp 65001 | Out-Null",
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
        "$OutputEncoding = [System.Text.Encoding]::UTF8",
        "$ErrorActionPreference = 'Continue'",
        "$env:PATH = 'C:\\Program Files\\Git\\bin;C:\\Program Files\\Git\\cmd;' + $env:PATH",
        f"$remote = '{BB_REMOTE_URL}'",
        f"$ws     = '{WS_WIN}'",
        f"$stage  = '{STAGE_WIN}'",
        f"$auth   = '{git_auth}'",
        "",
        "# workspace 초기화 (3-case: 없음/git있음/파일만있음)",
        "if (-not (Test-Path $ws)) {",
        f"    git {git_auth} clone $remote $ws",
        "    if ($LASTEXITCODE -ne 0) { Write-Error 'clone 실패'; exit $LASTEXITCODE }",
        "} elseif (Test-Path \"$ws\\.git\") {",
        f"    git -C $ws {git_auth} pull $remote 2>&1 | Out-Null",
        "} else {",
        "    # 파일 있으나 .git 없음 — 임시 clone 후 .git 이식",
        "    $tmp = \"${ws}_tmp\"",
        "    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }",
        f"    git {git_auth} clone $remote $tmp",
        "    if ($LASTEXITCODE -ne 0) { Write-Error 'clone 실패'; exit $LASTEXITCODE }",
        "    Move-Item \"$tmp\\.git\" \"$ws\\.git\"",
        "    Remove-Item -Recurse -Force $tmp",
        "    git -C $ws reset origin/main --mixed 2>&1 | Out-Null",
        "}",
        "",
        "# stage → workspace 복사",
        "if (Test-Path $stage) {",
        "    Copy-Item -Recurse -Force \"$stage\\*\" \"$ws\\\" -ErrorAction SilentlyContinue",
        "}",
        "",
        "git -C $ws add .",
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
        print(f"\n=== 업로드 완료 ===")
        print(f"레포 수  : {len(copied_repos)}개")
        for r in copied_repos:
            print(f"  - {r}")
        print(f"\nBitbucket: {os.environ.get("BITBUCKET_BASE_URL","")}/projects/VULCHK/repos/audit_result/browse")
    else:
        print(f"\n[WARN] git push 실패 (returncode={rc})")
        print(f"파일은 {WS_WIN}\\ 에 보존됨 — 수동 push (Windows PowerShell):")
        print(f"  git -C \"{WS_WIN}\" add .")
        print(f"  git -C \"{WS_WIN}\" commit -m \"{commit_msg}\"")
        print(f"  git -C \"{WS_WIN}\" push")
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
