#!/usr/bin/env python3
"""
approve_report.py — /sec-review 완료 후 최종 보고서 생성 및 Confluence 게시

[필수] /sec-review 완료 후에만 실행 가능합니다.
       미판정(reviewed != true) findings가 존재하면 실행이 차단됩니다.
       --force 플래그로 강제 통과 가능 (의도적 사용 시에만).

사용법 (RUN_ID 모드):
    python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo>
    python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo> --publish
    python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo> --publish --title "제목"

사용법 (레포 단위 모드 — skill별 최신 파일 자동 선택):
    python3 tools/approve_report.py --repo <repo>
    python3 tools/approve_report.py --repo <repo> --publish

동작 흐름:
  0. [GATE] /sec-review 완료 여부 검증 — 미판정 finding 존재 시 즉시 종료
  1. findings_*.json 읽기 (RUN_ID 지정 시 해당 RUN, 미지정 시 skill별 최신)
  2. review_status: "오탐" findings → result: "양호" 로 변경
  3. 모든 파일에 approved: true, llm_checked: true 표시
  4. python3 tools/generate_report.py --type final --repos <repo> [--run-id <RUN_ID>]
     → logs/report_final_*.md + palantir-reports 자동 커밋
  5. --publish 시: python3 tools/generate_final_report.py --repo <repo> [--run-id <RUN_ID>] --publish
     → Confluence 게시
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

PALANTIR_DIR = Path(__file__).resolve().parent.parent
STATE_DIR    = PALANTIR_DIR / "state"

def _lookup_bb_project(repo: str) -> str:
    """clone 시점에 저장된 state/<repo>/repo_meta.json에서 Bitbucket 프로젝트 키 조회."""
    try:
        meta = STATE_DIR / repo / "repo_meta.json"
        if meta.exists():
            return json.loads(meta.read_text(encoding="utf-8")).get("project", "")
    except Exception:
        pass
    return ""


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(PALANTIR_DIR))


REVIEW_EXEMPT_RESULTS = {"양호", "양호(FP)", "해당없음", "safe"}


def _collect_findings_paths(repo: str, run_id: str | None, skip_sca: bool = False) -> list[Path]:
    """findings_*.json 경로 목록 수집 (apply_review_results와 동일 로직)."""
    if run_id is None:
        paths: list[Path] = []
        repo_dir = STATE_DIR / repo
        if not repo_dir.is_dir():
            return paths
        for skill_dir in sorted(repo_dir.iterdir()):
            if not skill_dir.is_dir():
                continue
            if skip_sca and skill_dir.name == "sca":
                continue
            run_dirs = sorted(
                (d for d in skill_dir.iterdir() if d.is_dir()),
                key=lambda d: d.name, reverse=True,
            )
            for run_dir in run_dirs:
                files = sorted(run_dir.glob("findings_*.json"))
                if files:
                    paths.append(files[0])
                    break
        return paths
    else:
        all_paths = sorted(STATE_DIR.glob(f"{repo}/*/{run_id}/findings_*.json"))
        if skip_sca:
            all_paths = [p for p in all_paths if p.parts[-3] != "sca"]
        return all_paths


def _check_review_complete(repo: str, run_id: str | None, skip_sca: bool = False) -> list[tuple[str, str]]:
    """
    /sec-review 완료 여부를 검증한다.
    reviewed != True 이고 result가 제외 목록에 없는 finding 목록을 반환한다.
    빈 리스트 반환 시 게이트 통과.
    """
    paths = _collect_findings_paths(repo, run_id, skip_sca=skip_sca)
    unreviewed: list[tuple[str, str]] = []

    for path in paths:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for f in doc.get("findings", []):
            if f.get("reviewed") is True:
                continue
            if f.get("result") in REVIEW_EXEMPT_RESULTS:
                continue
            # review_status가 "그룹병합"인 SCA 하위 finding도 제외
            if f.get("review_status") == "그룹병합":
                continue
            unreviewed.append((str(path), f.get("finding_id", "UNKNOWN")))

    return unreviewed


def apply_review_results(repo: str, run_id: str | None, skip_sca: bool = False) -> dict[str, int]:
    """
    findings_*.json 파일을 읽어 오탐 판정 finding의 result를 "양호"로 변경하고
    파일 수준에서 approved: true, llm_checked: true 를 설정한다.

    run_id=None 이면 레포 단위 모드 — skill별 최신 RUN_ID 파일 하나씩 선택.
    반환: {"updated": N, "skipped": N, "total_findings": N}
    """
    paths = _collect_findings_paths(repo, run_id, skip_sca=skip_sca)

    if not paths:
        pattern = f"{repo}/*/{run_id}/findings_*.json" if run_id else f"{repo}/*/latest/findings_*.json"
        print(f"[WARN] findings 없음: state/{pattern}")
        return {"updated": 0, "skipped": 0, "total_findings": 0}

    counts = {"updated": 0, "skipped": 0, "total_findings": 0}

    for path in paths:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[WARN] 파싱 실패 {path}: {e}")
            continue

        findings  = doc.get("findings", [])
        modified  = False

        for f in findings:
            counts["total_findings"] += 1
            review_status = f.get("review_status")

            if review_status in ("오탐", "그룹병합"):
                # 오탐 또는 SCA 라이브러리 그룹 하위 finding → 보고서 제외
                if f.get("result") != "양호":
                    f["result"] = "양호"
                    modified = True
                    counts["updated"] += 1
            else:
                # 정탐 or 미판정 — 비표준 result 정규화
                VALID_RESULT = {"취약", "정보", "양호", "양호(FP)", "해당없음", "safe"}
                current_result = f.get("result", "")
                review_result = f.get("review_result")
                if current_result not in VALID_RESULT:
                    # review_result가 확정값이면 우선 사용, 없으면 "정보"로 정규화
                    normalized = review_result if review_result in {"취약", "정보"} else "정보"
                    f["result"] = normalized
                    modified = True
                    counts["updated"] += 1
                elif review_status == "정탐" and review_result in {"취약", "정보"}:
                    # 정탐 판정 후 review_result로 result 명시적 동기화
                    if f.get("result") != review_result:
                        f["result"] = review_result
                        modified = True
                        counts["updated"] += 1
                counts["skipped"] += 1

            # 최종 result 기준으로 보고서에 포함될 건수 집계
            if f.get("result") in ("취약", "정보"):
                counts["reportable"] = counts.get("reportable", 0) + 1

        # 파일 수준 플래그 갱신
        doc["approved"]    = True
        doc["llm_checked"] = True
        modified = True

        path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        rel = path.relative_to(PALANTIR_DIR)
        print(f"[OK] {rel}  (오탐→양호: {counts['updated']}건 누계)")

    return counts


def _count_sca_reportable(repo: str, run_id: str | None) -> int:
    """SCA findings 중 취약·정보 건수 (skip_sca=False로 SCA 포함 수집)."""
    all_paths = _collect_findings_paths(repo, run_id, skip_sca=False)
    sca_paths = [p for p in all_paths if p.parent.parent.name == "sca"]
    count = 0
    for path in sca_paths:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            for f in doc.get("findings", []):
                if f.get("result") in ("취약", "정보"):
                    count += 1
        except Exception:
            pass
    return count


def _extract_review_notes(repo: str, run_id: str | None, skip_sca: bool = False) -> list[dict]:
    """
    findings_*.json에서 리뷰 완료된 finding의 review_note를 추출한다.
    매니저 검토 UI에서 티켓 발행 여부 판단 근거로 활용된다.
    """
    paths = _collect_findings_paths(repo, run_id, skip_sca=skip_sca)
    notes: list[dict] = []

    for path in paths:
        try:
            skill = path.parent.parent.name  # state/<repo>/<skill>/<run_id>/
            doc   = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        for f in doc.get("findings", []):
            if not f.get("reviewed"):
                continue
            review_status = f.get("review_status", "")
            if review_status == "그룹병합":
                continue

            note_text = (f.get("review_note") or "").strip()
            if not note_text and review_status == "오탐":
                note_text = "오탐 판정 — 보고서에서 제외됨"

            notes.append({
                "finding_id":    f.get("finding_id", ""),
                "skill":         skill,
                "title":         f.get("title", ""),
                "severity":      f.get("severity", ""),
                "decision":      review_status,
                "review_result": f.get("review_result") or f.get("result", ""),
                "review_note":   note_text,
            })

    return notes


def _send_to_jira_gateway(
    repo: str,
    page_id: str,
    report_key: str,
    review_notes: list | None = None,
) -> bool:
    """게이트웨이에 MD 페이로드를 POST — 검토 대기(pending) 티켓으로 등록.

    반환값은 실제로 티켓이 생성됐는지 여부다 (완료 요약이 이 값을 확인 없이
    항상 '전송 완료'로 출력하던 버그 수정 — 2026-08-25).
    """
    import os
    from dotenv import load_dotenv
    load_dotenv(PALANTIR_DIR / ".env")

    gateway_url = os.getenv("JIRA_GATEWAY_URL", "").strip()
    if not gateway_url:
        print("      [WARN] .env에 JIRA_GATEWAY_URL 미설정 — Jira 게이트웨이 전송 생략")
        return False

    # 최종 보고서 MD 읽기
    md_path = PALANTIR_DIR / report_key
    if not md_path.exists():
        print(f"      [WARN] 최종 보고서 파일 없음: {md_path} — 전송 생략")
        return False

    md_text = md_path.read_text(encoding="utf-8")
    jira_project = os.getenv("JIRA_PROJECT_KEY", "")

    # system_code_to_repo 에서 Bitbucket 프로젝트 키 조회 (vision API용)
    bb_project = _lookup_bb_project(repo)

    try:
        import urllib.request, urllib.error
        payload = json.dumps({
            "repo":               repo,
            "page_id":            page_id or "",
            "md_text":            md_text,
            "jira_project":       jira_project,
            "review_notes":       review_notes or [],
            "bitbucket_project":  bb_project,
        }, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            f"{gateway_url.rstrip('/')}/api/pending",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
        ticket_id = body.get("ticket_id", "?")
        base = os.getenv("JIRA_GATEWAY_URL", "http://localhost:8000").rstrip("/")
        print(f"      게이트웨이 전송 완료 — 검토 대기: {base}/review/{ticket_id}")
        return True
    except Exception as exc:
        print(f"      [ERROR] 게이트웨이 전송 실패: {exc}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="오탐 반영 → final 보고서 생성 → (선택) Confluence 게시",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--run-id",  required=False, default=None,
                        help="파이프라인 RUN_ID (YYYYMMDD_HHMM). 생략 시 레포 단위 모드 (skill별 최신 파일 선택)")
    parser.add_argument("--repo",    required=True, help="레포 슬러그")
    parser.add_argument("--publish", action="store_true",
                        help="Confluence 자동 게시")
    parser.add_argument("--parent", type=int, default=0, metavar="PAGE_ID",
                        help="Confluence 부모 페이지 ID (생략 시 기본 OCB 진단 페이지 하위)")
    parser.add_argument("--title",   default=None,
                        help="Confluence 페이지 제목 (생략 시 {repo}-진단결과)")
    parser.add_argument("--force",    action="store_true",
                        help="/sec-review 완료 여부 게이트 강제 통과 (긴급 시에만 사용)")
    parser.add_argument("--skip-sca", action="store_true", default=True,
                        help="SCA(오픈소스 CVE) findings를 보고서·Jira 티켓에서 제외 (기본: 제외)")
    parser.add_argument("--include-sca", action="store_true",
                        help="SCA findings를 보고서에 포함 (--skip-sca 기본값 override)")
    args = parser.parse_args()

    run_id   = args.run_id
    run_label = run_id if run_id else "(레포 단위)"
    skip_sca  = args.skip_sca and not args.include_sca
    _confluence_url = ""   # 게시 완료 후 채워짐 (audit 기록용)
    _jira_sent = False     # Jira 게이트웨이 실제 전송 성공 여부 (완료 요약 판단용)
    print(f"\n[approve] RUN_ID={run_label}  repo={args.repo}")
    if skip_sca:
        print("[approve] --skip-sca: SCA findings 제외 모드")
    print("=" * 60)

    # 0. [GATE] /sec-review 완료 여부 강제 검증
    if not args.force:
        unreviewed = _check_review_complete(args.repo, run_id, skip_sca=skip_sca)
        if unreviewed:
            print("\n[GATE ERROR] /sec-review 미완료 — 아래 findings가 판정되지 않았습니다:")
            for path, fid in unreviewed:
                rel = Path(path).relative_to(PALANTIR_DIR) if Path(path).is_absolute() else path
                print(f"  {fid}  ({rel})")
            print()
            print("  → /sec-review 실행 후 approve_report.py를 재실행하세요.")
            if run_id:
                print(f"  → /sec-review {run_id} {args.repo}")
            else:
                print(f"  → /sec-review {args.repo}")
            print()
            print("  (긴급 시 --force 플래그로 게이트 우회 가능)")
            return 1
    else:
        print("\n[GATE] --force 지정 — /sec-review 완료 여부 게이트 건너뜀")

    # 1. 오탐 반영
    print("\n[1/4] 오탐 판정 적용 중...")
    stats = apply_review_results(args.repo, run_id, skip_sca=skip_sca)
    print(f"      전체 {stats['total_findings']}건  /  오탐→양호: {stats['updated']}건  /  유지: {stats['skipped']}건")

    # 2. final 1차 보고서 생성 + palantir-reports 커밋
    print("\n[2/4] final 1차 보고서 생성...")
    gen_cmd = [
        sys.executable, "tools/generate_report.py",
        "--type",  "final",
        "--repos", args.repo,
    ]
    if run_id:
        gen_cmd += ["--run-id", run_id]
    r = _run(gen_cmd)
    if r.returncode != 0:
        print(f"[ERROR] generate_report.py 실패 (returncode={r.returncode})")
        return r.returncode

    from datetime import date
    today = date.today().strftime("%Y%m%d")
    if run_id:
        report_path = f"logs/report_final_{run_id}.md"
        commit_path = f"~/palantir-reports/{args.repo}/{run_id}/"
    else:
        report_path = f"logs/report_final_{args.repo}_{today}.md"
        commit_path = f"~/palantir-reports/{args.repo}/{today}/"

    print(f"\n      저장: {report_path}")
    print(f"      커밋: {commit_path}")

    # 3. Confluence 게시 (--publish 옵션 시)
    if args.publish:
        reportable = stats.get("reportable", 0)
        if reportable == 0:
            # skip_sca 모드 + SCA findings 존재 → SCA 전용 케이스 누적 기록
            if skip_sca:
                sca_count = _count_sca_reportable(args.repo, run_id)
                if sca_count > 0:
                    print(f"\n[3/4] SAST 양호 (SCA 전용 {sca_count}건) — Jira 미발행, ocb_scan_plan 누적 기록 중...")
                    _run([sys.executable, "tools/update_ocb_plan.py",
                          "--sca-only", args.repo, str(sca_count)])
                else:
                    print("\n[3/4] Confluence 게시 생략 — 전체 양호 (SAST + SCA 모두 이상 없음)")
            else:
                print("\n[3/4] Confluence 게시 생략 — 보고서에 포함할 취약/정보 finding 없음 (전체 양호)")
        else:
            meta_path = PALANTIR_DIR / "state" / args.repo / "repo_meta.json"
            if not meta_path.exists():
                print(f"\n[GATE] repo_meta.json 누락 — 빈칸 게시 방지를 위해 메타데이터 전용 재clone 시도")
                bf = _run([sys.executable, "tools/backfill_repo_meta.py", "--repo", args.repo])
                if bf.returncode != 0 or not meta_path.exists():
                    print(f"\n[GATE ERROR] 메타데이터 자동 복구 실패 — 게시 차단.")
                    print(f"  → PROJECT 키를 확인해 수동 실행: python3 tools/backfill_repo_meta.py --repo {args.repo} --project <PROJECT>")
                    return 1
                print(f"[GATE] repo_meta.json 복구 완료 — 게시 계속 진행\n")

            print(f"\n[3/4] 최종 보고서 생성 + Confluence 게시... (보고 대상 {reportable}건)")
            cmd = [
                sys.executable, "tools/generate_final_report.py",
                "--repo",   args.repo,
                "--publish",
            ]
            if run_id:
                cmd += ["--run-id", run_id]
            if args.title:
                cmd += ["--title", args.title]
            if args.parent:
                cmd += ["--parent", str(args.parent)]
            if skip_sca:
                cmd += ["--skip-sca"]
            r = _run(cmd)
            if r.returncode != 0:
                print(f"[ERROR] generate_final_report.py 실패 (returncode={r.returncode})")
                return r.returncode
            # 보고서 컬럼 자동 갱신 (Confluence page_id → URL)
            registry_path = PALANTIR_DIR / "docs" / ".confluence_pages.json"
            if registry_path.exists():
                reg = json.loads(registry_path.read_text(encoding="utf-8"))
                today_str = date.today().strftime("%Y%m%d")
                if run_id:
                    report_key = f"logs/final_{args.repo}_{run_id}.md"
                else:
                    report_key = f"logs/final_{args.repo}_{today_str}.md"
                page_id = reg.get(report_key)
                if page_id:
                    import os
                    from dotenv import load_dotenv
                    load_dotenv(PALANTIR_DIR / ".env")
                    base_url = os.getenv("CONFLUENCE_BASE_URL", "https://wiki.skplanet.com")
                    report_url = f"{base_url}/pages/viewpage.action?pageId={page_id}"
                    _confluence_url = report_url
                    print(f"\n      체크리스트 보고서 컬럼 갱신 중 ... ({report_url})")
                    _run([sys.executable, "tools/update_ocb_plan.py",
                          "--report", args.repo, report_url])
                else:
                    print(f"\n      [WARN] .confluence_pages.json에서 {report_key} 를 찾지 못해 체크리스트 갱신 생략")
            # Jira 티켓 게이트웨이 전송
            print(f"\n[4/4] Jira 티켓 게이트웨이 전송...")
            _review_notes = _extract_review_notes(args.repo, run_id, skip_sca=skip_sca)
            print(f"      review_notes 추출: {len(_review_notes)}건")
            _jira_sent = _send_to_jira_gateway(args.repo, page_id or "", report_key, _review_notes)
    else:
        print("\n[3/4] Confluence 게시 생략 (--publish 미지정)")
        if run_id:
            publish_hint = (f"python3 tools/approve_report.py "
                            f"--run-id {run_id} --repo {args.repo} --publish")
        else:
            publish_hint = (f"python3 tools/approve_report.py "
                            f"--repo {args.repo} --publish")
        print(f"      게시하려면: {publish_hint}")

    # 진단이력 업로드 (VULCHK/palantir_result)
    print("\n[audit] 진단이력 업로드 중 (VULCHK/palantir_result)...")
    try:
        import importlib.util, os as _os
        spec = importlib.util.spec_from_file_location(
            "push_audit_result",
            PALANTIR_DIR / "tools" / "push_audit_result.py",
        )
        _par = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_par)
        _par.push(args.repo, run_id)
    except Exception as _exc:
        _hint = f"python3 tools/push_audit_result.py --repo {args.repo}"
        if run_id:
            _hint += f" --run-id {run_id}"
        print(f"  [WARN] 업로드 실패: {_exc}")
        print(f"  수동 실행: {_hint}")

    # vuln_registry 갱신 + service_meta/runs 통합 + audit log 기록
    print("\n[audit] vuln_registry 갱신 및 audit_log 기록 중...")
    try:
        sys.path.insert(0, str(PALANTIR_DIR))
        from tools.audit_utils import (
            update_registry_from_findings,
            update_service_meta,
            add_run_entry,
            log_report_published,
        )
        # findings[] 갱신
        reg_stats = update_registry_from_findings(
            repo=args.repo,
            run_id=run_id,
            report_url=_confluence_url,
        )
        print(f"  registry.findings: 신규 +{reg_stats['added']} / 업데이트 {reg_stats['updated']}")

        # service_meta 동기화 (scan_meta + review_meta → registry)
        update_service_meta(args.repo)
        print("  registry.service_meta: 동기화 완료")

        # runs[] 실행 이력 추가
        add_run_entry(
            args.repo,
            run_id,
            finding_counts={
                "total":      stats.get("total_findings", 0),
                "reportable": stats.get("reportable", 0),
                "fp_applied": stats.get("updated", 0),
            },
            report_path=report_path,
            confluence_url=_confluence_url,
        )
        print("  registry.runs: 실행 이력 추가 완료")

        # audit_log.json 글로벌 이벤트 기록 (유지)
        log_report_published(
            repo=args.repo,
            run_id=run_id,
            report_path=report_path,
            confluence_url=_confluence_url,
            findings_count={
                "total":      stats.get("total_findings", 0),
                "reportable": stats.get("reportable", 0),
                "fp_applied": stats.get("updated", 0),
            },
        )
        print("  audit_log: report_published 이벤트 기록 완료")
    except Exception as _exc:
        print(f"  [WARN] audit 기록 실패: {_exc}")

    # 완료 요약
    print("\n" + "=" * 60)
    print(f"[완료] RUN_ID={run_label}  repo={args.repo}")
    print(f"  1차 보고서: {report_path}")
    print(f"  커밋 이력:  {commit_path}")
    if args.publish and stats.get("reportable", 0) > 0:
        if run_id:
            final_path = f"logs/final_{args.repo}_{run_id}.md"
        else:
            final_path = f"logs/final_{args.repo}_{today}.md"
        print(f"  최종 보고서: {final_path}")
        print(f"  Confluence 게시 완료")
        if _jira_sent:
            print(f"  Jira 게이트웨이 전송 완료 (검토 대기)")
        else:
            print(f"  [WARN] Jira 게이트웨이 전송 실패 — 위 [ERROR]/[WARN] 로그 확인 후 재전송 필요")
    elif args.publish:
        print(f"  Confluence 게시: 생략 (전체 양호, 보고 대상 0건)")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
