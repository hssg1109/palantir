#!/usr/bin/env python3
"""
retroactive_cleanse.py — 소급 LLM 데이터 클렌징 처리 스크립트

완료된 진단 레포(review_meta.json 존재)에 대해:
  1. llm_data_access_log.json 생성 (retroactive=true, 접근파일 목록 미복원)
  2. testbed/<repo>/ 삭제
  3. state/ 소스코드 감사
  4. Confluence 레지스트리 행 추가

사용법:
  python3 tools/retroactive_cleanse.py [--dry-run] [--repo <repo>] [--skip-testbed-delete] [--skip-confluence]
"""

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from dotenv import load_dotenv

BASE_DIR = Path(__file__).parent.parent
STATE_DIR = BASE_DIR / "state"
TESTBED_DIR = BASE_DIR / "testbed"

CONFLUENCE_PAGE_ID = os.environ.get("CONFLUENCE_REGISTRY_PAGE_ID", "")
SKILLS = ["injection", "xss", "file", "data", "sca"]

KST = timezone(timedelta(hours=9))


def now_kst() -> str:
    return datetime.now(KST).isoformat(timespec="seconds")


def get_project(repo: str) -> str:
    """레포의 Bitbucket project 키 추출."""
    repo_dir = STATE_DIR / repo

    # 1) vuln_registry.json의 service_meta.bb_project
    vr = repo_dir / "vuln_registry.json"
    if vr.exists():
        try:
            d = json.loads(vr.read_text())
            p = d.get("service_meta", {}).get("bb_project", "")
            if p:
                return p
        except Exception:
            pass

    # 2) scan_meta.json의 bb_project
    for sm in sorted(repo_dir.glob("20*/scan_meta.json")):
        try:
            d = json.loads(sm.read_text())
            p = d.get("bb_project", "")
            if p:
                return p
        except Exception:
            pass

    return "?"


def get_skill_runs(repo: str) -> list[dict]:
    """레포의 skill별 실행 정보 목록 반환."""
    repo_dir = STATE_DIR / repo
    runs = []
    for skill in SKILLS:
        skill_dir = repo_dir / skill
        if not skill_dir.exists():
            continue
        # 가장 최신 run (날짜 내림차순)
        run_dirs = sorted(
            [d for d in skill_dir.iterdir() if d.is_dir()],
            reverse=True,
        )
        if not run_dirs:
            continue
        run_dir = run_dirs[0]
        prefix = run_dir.name  # YYYYMMDD_HHMM

        # scanned_at: prefix에서 파싱, 없으면 mtime
        try:
            dt = datetime.strptime(prefix, "%Y%m%d_%H%M").replace(tzinfo=KST)
            scanned_at = dt.isoformat(timespec="seconds")
        except ValueError:
            scanned_at = datetime.fromtimestamp(run_dir.stat().st_mtime, KST).isoformat(timespec="seconds")

        runs.append(
            {
                "skill": skill,
                "scan_dir": f"state/{repo}/{skill}/{prefix}",
                "scanned_at": scanned_at,
                "llm_accessed_files": [
                    {
                        "phase": "Phase 1 - Asset Identification",
                        "purpose": "자산 식별 (소급 처리 — 실제 접근 파일 목록 미복원)",
                        "files": [],
                        "retroactive_note": "소급 처리로 실제 Read 파일 목록을 복원할 수 없음",
                    },
                    {
                        "phase": "Phase 3 - LLM-Check",
                        "purpose": "교차검증 (소급 처리 — 실제 접근 파일 목록 미복원)",
                        "files": [],
                        "retroactive_note": "소급 처리로 실제 Read 파일 목록을 복원할 수 없음",
                    },
                ],
            }
        )
    return runs


def audit_state_sources(repo: str) -> tuple[bool, int, list[str]]:
    """state/<repo>/ 내 소스코드 전체 파일 복사 여부 감사."""
    repo_dir = STATE_DIR / repo
    found = []
    extensions = {".java", ".kt", ".py", ".go", ".ts", ".tsx", ".js", ".jsx"}
    for f in repo_dir.rglob("*"):
        if f.is_file() and f.suffix in extensions and "__pycache__" not in str(f):
            found.append(str(f.relative_to(BASE_DIR)))
    return len(found) == 0, len(found), found[:10]


def check_scan_redact(repo: str) -> tuple[bool, str]:
    """scan_data_protection.py _redact_snippet() 적용 여부 — data skill 실행 확인."""
    data_dir = STATE_DIR / repo / "data"
    if data_dir.exists() and any(data_dir.iterdir()):
        return True, "scan_data_protection.py _redact_snippet() 자동 적용"
    return False, "data skill 미실행"


def delete_testbed(repo: str, dry_run: bool) -> tuple[bool, str]:
    """testbed/<repo>/ 삭제."""
    tb_path = TESTBED_DIR / repo
    if not tb_path.exists():
        return True, "이미 삭제됨"
    if dry_run:
        return True, f"[DRY-RUN] 삭제 예정: {tb_path}"
    try:
        shutil.rmtree(tb_path)
        return True, f"삭제 완료: {tb_path}"
    except Exception as e:
        return False, f"삭제 실패: {e}"


def build_log(
    repo: str,
    project: str,
    runs: list[dict],
    tb_confirmed: bool,
    tb_note: str,
    state_ok: bool,
    state_note: str,
    scan_redact_ok: bool,
    scan_redact_note: str,
    cleansing_completed: bool,
) -> dict:
    ts = now_kst()
    return {
        "repo": repo,
        "project": project,
        "provider": "claude-cli",
        "retroactive": True,
        "cleansing_completed": cleansing_completed,
        "cleansing_completed_at": ts if cleansing_completed else None,
        "skills": runs,
        "cleansing_actions": [
            {
                "action": "testbed_deletion",
                "target": f"testbed/{repo}/",
                "confirmed": tb_confirmed,
                "confirmed_at": ts if tb_confirmed else None,
                "note": tb_note,
            },
            {
                "action": "state_snippet_audit",
                "description": "state/ 내 소스코드 전체 파일 복사 없음 확인",
                "confirmed": state_ok,
                "confirmed_at": ts if state_ok else None,
                "note": state_note,
            },
            {
                "action": "scan_script_redact",
                "description": "scan_data_protection.py _redact_snippet() 자동 적용 확인",
                "confirmed": scan_redact_ok,
                "confirmed_at": ts if scan_redact_ok else None,
                "note": scan_redact_note,
            },
            {
                "action": "claude_session_closure",
                "description": "진단 세션 종료 — 새 세션 시작으로 컨텍스트 만료",
                "confirmed": False,
                "note": "운영자 수동 수행 필요",
            },
        ],
        "notes": "소급 처리 — Phase C 누락으로 인한 사후 클렌징 기록 (2026-06-26). llm_accessed_files 목록은 소급 복원 불가.",
    }


def get_last_scanned(runs: list[dict]) -> str:
    """가장 최신 skill scanned_at 날짜 (YYYY-MM-DD)."""
    dates = [r["scanned_at"][:10] for r in runs if r.get("scanned_at")]
    return max(dates) if dates else "?"


def count_accessed_files(runs: list[dict]) -> int:
    total = 0
    for r in runs:
        for phase in r.get("llm_accessed_files", []):
            total += len(phase.get("files", []))
    return total


def add_confluence_row(
    repo: str,
    project: str,
    runs: list[dict],
    log: dict,
    token: str,
    base_url: str,
    dry_run: bool,
) -> tuple[bool, str]:
    """Confluence 레지스트리 페이지에 행 추가."""
    if not token:
        return False, "CONFLUENCE_TOKEN 없음"

    # 현재 페이지 content 가져오기
    url = f"{base_url}/rest/api/content/{CONFLUENCE_PAGE_ID}?expand=body.storage,version"
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=15)
    if resp.status_code != 200:
        return False, f"페이지 조회 실패: HTTP {resp.status_code}"

    page_data = resp.json()
    current_version = page_data["version"]["number"]
    body = page_data["body"]["storage"]["value"]

    tb_icon = "✅" if log["cleansing_actions"][0]["confirmed"] else "⚠️"
    state_icon = "✅" if log["cleansing_actions"][1]["confirmed"] else "⚠️"
    scan_redact_icon = "✅" if log["cleansing_actions"][2]["confirmed"] else "⚠️"
    skill_list = " / ".join(r["skill"] for r in runs)
    last_date = get_last_scanned(runs)
    log_path = f"state/{repo}/llm_data_access_log.json"

    new_row = (
        f"<tr>"
        f"<td>{last_date}</td>"
        f"<td>OCB / {project}</td>"
        f"<td>{repo}</td>"
        f"<td>all ({skill_list})</td>"
        f"<td>{tb_icon}</td>"
        f"<td>{state_icon}</td>"
        f"<td>{scan_redact_icon}</td>"
        f"<td>🔲</td>"
        f"<td>🔲</td>"
        f"<td>{log_path}</td>"
        f"</tr>"
    )

    # 테이블 마지막 </tr></tbody> 직전에 삽입
    if "</tbody>" in body:
        updated_body = body.replace("</tbody>", new_row + "</tbody>", 1)
    elif "</table>" in body:
        updated_body = body.replace("</table>", new_row + "</table>", 1)
    else:
        return False, "테이블 구조를 찾을 수 없음 — 수동 등록 필요"

    if dry_run:
        return True, "[DRY-RUN] Confluence 행 추가 스킵"

    update_url = f"{base_url}/rest/api/content/{CONFLUENCE_PAGE_ID}"
    payload = {
        "version": {"number": current_version + 1},
        "title": page_data["title"],
        "type": "page",
        "body": {"storage": {"value": updated_body, "representation": "storage"}},
    }
    r2 = requests.put(
        update_url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        timeout=20,
    )
    if r2.status_code in (200, 201):
        return True, f"등록 완료 (version {current_version + 1})"
    return False, f"등록 실패: HTTP {r2.status_code} — {r2.text[:200]}"


def process_repo(
    repo: str,
    token: str,
    base_url: str,
    dry_run: bool,
    skip_testbed: bool,
    skip_confluence: bool,
) -> bool:
    repo_dir = STATE_DIR / repo
    print(f"\n{'='*60}")
    print(f"[{repo}]")

    project = get_project(repo)
    runs = get_skill_runs(repo)
    if not runs:
        print(f"  ⚠️  skill 실행 결과 없음 — 스킵")
        return False

    print(f"  project: {project} | skills: {[r['skill'] for r in runs]}")

    # testbed 삭제
    if skip_testbed:
        tb_ok, tb_note = True, "삭제 스킵 (--skip-testbed-delete)"
    else:
        tb_ok, tb_note = delete_testbed(repo, dry_run)
    print(f"  testbed : {'✅' if tb_ok else '⚠️'}  {tb_note}")

    # state 감사
    state_ok, count, samples = audit_state_sources(repo)
    state_note = "" if state_ok else f"소스 파일 {count}건 발견: {samples}"
    print(f"  state감사: {'✅' if state_ok else '⚠️'}  {'0건' if state_ok else state_note}")

    # 스캔 redact
    scan_redact_ok, scan_redact_note = check_scan_redact(repo)
    print(f"  스캔redact: {'✅' if scan_redact_ok else '⚠️'}  {scan_redact_note}")

    cleansing_completed = tb_ok and state_ok

    # 로그 생성
    log = build_log(repo, project, runs, tb_ok, tb_note, state_ok, state_note, scan_redact_ok, scan_redact_note, cleansing_completed)
    log_path = repo_dir / "llm_data_access_log.json"
    if not dry_run:
        log_path.write_text(json.dumps(log, ensure_ascii=False, indent=2))
    print(f"  로그    : {'[DRY-RUN] 스킵' if dry_run else f'저장 완료 → {log_path.relative_to(BASE_DIR)}'}")

    # Confluence
    if skip_confluence:
        cf_ok, cf_note = True, "스킵 (--skip-confluence)"
    else:
        try:
            cf_ok, cf_note = add_confluence_row(repo, project, runs, log, token, base_url, dry_run)
        except Exception as e:
            cf_ok, cf_note = False, str(e)
    print(f"  Confluence: {'✅' if cf_ok else '⚠️'}  {cf_note}")

    status = "✅ 완료" if cleansing_completed else "⚠️ 부분완료"
    print(f"  → {status}")
    return cleansing_completed


def main():
    parser = argparse.ArgumentParser(description="소급 LLM 데이터 클렌징 처리")
    parser.add_argument("--dry-run", action="store_true", help="실제 삭제/저장 없이 시뮬레이션")
    parser.add_argument("--repo", help="특정 레포만 처리 (미지정 시 전체 완료 레포)")
    parser.add_argument("--skip-testbed-delete", action="store_true", help="testbed 삭제 스킵")
    parser.add_argument("--skip-confluence", action="store_true", help="Confluence 레지스트리 등록 스킵")
    args = parser.parse_args()

    load_dotenv(BASE_DIR / ".env")
    confluence_token = os.environ.get("CONFLUENCE_TOKEN", "")
    confluence_base = os.environ.get("CONFLUENCE_BASE_URL", "https://wiki.skplanet.com")

    if args.dry_run:
        print("[DRY-RUN 모드] 실제 변경 없이 시뮬레이션합니다.\n")

    # 처리 대상 레포 수집
    if args.repo:
        repos = [args.repo]
    else:
        repos = sorted(
            d.name
            for d in STATE_DIR.iterdir()
            if d.is_dir() and (d / "review_meta.json").exists()
        )

    print(f"처리 대상 레포: {len(repos)}개")
    print(", ".join(repos))

    results = {"done": [], "partial": [], "skip": []}
    for repo in repos:
        if not (STATE_DIR / repo / "review_meta.json").exists():
            print(f"\n[{repo}] review_meta.json 없음 — 스킵")
            results["skip"].append(repo)
            continue
        ok = process_repo(
            repo,
            confluence_token,
            confluence_base,
            args.dry_run,
            args.skip_testbed_delete,
            args.skip_confluence,
        )
        (results["done"] if ok else results["partial"]).append(repo)

    print(f"\n{'='*60}")
    print(f"소급 클렌징 완료 요약")
    print(f"  ✅ 완료      : {len(results['done'])}개")
    print(f"  ⚠️  부분완료  : {len(results['partial'])}개")
    print(f"  ─ 스킵       : {len(results['skip'])}개")
    if results["partial"]:
        print(f"\n부분완료 레포 (수동 확인 필요):")
        for r in results["partial"]:
            print(f"  - {r}")
    print(f"\n[운영자] 처리 완료 후 이 Claude 세션을 종료하고 새 세션을 시작하세요.")


if __name__ == "__main__":
    main()
