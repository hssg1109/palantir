#!/usr/bin/env python3
"""
approve_report.py — /sec-review 완료 후 최종 보고서 생성 및 Confluence 게시

사용법 (RUN_ID 모드):
    python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo>
    python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo> --publish
    python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo> --publish --title "제목"

사용법 (레포 단위 모드 — skill별 최신 파일 자동 선택):
    python3 tools/approve_report.py --repo <repo>
    python3 tools/approve_report.py --repo <repo> --publish

동작 흐름:
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


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(PALANTIR_DIR))


def apply_review_results(repo: str, run_id: str | None) -> dict[str, int]:
    """
    findings_*.json 파일을 읽어 오탐 판정 finding의 result를 "양호"로 변경하고
    파일 수준에서 approved: true, llm_checked: true 를 설정한다.

    run_id=None 이면 레포 단위 모드 — skill별 최신 RUN_ID 파일 하나씩 선택.
    반환: {"updated": N, "skipped": N, "total_findings": N}
    """
    if run_id is None:
        # 레포 단위 모드: skill별 최신 파일 선택
        paths = []
        repo_dir = STATE_DIR / repo
        if not repo_dir.is_dir():
            print(f"[WARN] 레포 경로 없음: {repo_dir}")
            return {"updated": 0, "skipped": 0, "total_findings": 0}
        for skill_dir in sorted(repo_dir.iterdir()):
            if not skill_dir.is_dir():
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
    else:
        pattern = f"{repo}/*/{run_id}/findings_*.json"
        paths   = sorted(STATE_DIR.glob(pattern))

    if not paths:
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

            if review_status == "오탐":
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

        # 파일 수준 플래그 갱신
        doc["approved"]    = True
        doc["llm_checked"] = True
        modified = True

        path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        rel = path.relative_to(PALANTIR_DIR)
        print(f"[OK] {rel}  (오탐→양호: {counts['updated']}건 누계)")

    return counts


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
    parser.add_argument("--title",   default=None,
                        help="Confluence 페이지 제목 (생략 시 {repo}-진단결과)")
    args = parser.parse_args()

    run_id   = args.run_id
    run_label = run_id if run_id else "(레포 단위)"
    print(f"\n[approve] RUN_ID={run_label}  repo={args.repo}")
    print("=" * 60)

    # 1. 오탐 반영
    print("\n[1/3] 오탐 판정 적용 중...")
    stats = apply_review_results(args.repo, run_id)
    print(f"      전체 {stats['total_findings']}건  /  오탐→양호: {stats['updated']}건  /  유지: {stats['skipped']}건")

    # 2. final 1차 보고서 생성 + palantir-reports 커밋
    print("\n[2/3] final 1차 보고서 생성...")
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
        print("\n[3/3] 최종 보고서 생성 + Confluence 게시...")
        cmd = [
            sys.executable, "tools/generate_final_report.py",
            "--repo",   args.repo,
            "--publish",
        ]
        if run_id:
            cmd += ["--run-id", run_id]
        if args.title:
            cmd += ["--title", args.title]
        r = _run(cmd)
        if r.returncode != 0:
            print(f"[ERROR] generate_final_report.py 실패 (returncode={r.returncode})")
            return r.returncode
    else:
        print("\n[3/3] Confluence 게시 생략 (--publish 미지정)")
        if run_id:
            publish_hint = (f"python3 tools/approve_report.py "
                            f"--run-id {run_id} --repo {args.repo} --publish")
        else:
            publish_hint = (f"python3 tools/approve_report.py "
                            f"--repo {args.repo} --publish")
        print(f"      게시하려면: {publish_hint}")

    # 완료 요약
    print("\n" + "=" * 60)
    print(f"[완료] RUN_ID={run_label}  repo={args.repo}")
    print(f"  1차 보고서: {report_path}")
    print(f"  커밋 이력:  {commit_path}")
    if args.publish:
        if run_id:
            final_path = f"logs/final_{args.repo}_{run_id}.md"
        else:
            final_path = f"logs/final_{args.repo}_{today}.md"
        print(f"  최종 보고서: {final_path}")
        print(f"  Confluence 게시 완료")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
