#!/usr/bin/env python3
"""
pipeline_runner.py — 전체 파이프라인 오케스트레이터

동작 흐름 (repo별):
  1. Auto-Clone   : testbed/<repo> 없으면 Bitbucket에서 자동 clone
  2. Auto-Scan    : Python 스캐너 직접 실행 (skill × repo)
  3. LLM-Check    : LLM 교차검증 + findings 출력
  4. Cleanup      : (비활성화됨 — testbed는 수동 관리)
  5. Report       : --report draft 시 1차 보고서 자동 생성

결과 경로 규칙:
  state/<repo>/<skill>/<RUN_ID>/
  (RUN_ID = 파이프라인 시작 시각 YYYYMMDD_HHMM — 전 repo 공통)

사용법:
  python3 tools/pipeline_runner.py                           # 전체 active 대상
  python3 tools/pipeline_runner.py --repos ocb-webview-api  # 특정 repo만
  python3 tools/pipeline_runner.py --skills injection sca   # 특정 skill만
  python3 tools/pipeline_runner.py --report draft           # 완료 후 1차 보고서
  python3 tools/pipeline_runner.py --dry-run                # 실행 계획 확인
  python3 tools/pipeline_runner.py --no-clone               # clone 건너뜀
  python3 tools/pipeline_runner.py --force-clone            # 기존 testbed 재clone

옵션:
  --targets FILE        scan_targets.yaml 경로 (기본: trigger/scan_targets.yaml)
  --repos REPO ...      실행할 repo 목록 필터 (생략 시 active 전체)
  --skills SKILL ...    실행할 skill 목록 필터 (생략 시 repo_type별 기본값)
  --provider PROVIDER   LLM provider 전체 오버라이드
  --no-clone            Auto-Clone 건너뜀 (testbed 없으면 skip)
  --force-clone         기존 testbed 삭제 후 재clone
  --skip-scan           Auto-Scan 건너뜀 (이미 실행된 경우)
  --skip-llm            LLM-Check 건너뜀
  --max-budget-usd N    skill당 최대 토큰 비용 (기본: targets 설정 또는 3.0)
  --max-turns N         LLM 최대 턴 수 (기본: targets 설정 또는 80)
  --report draft|final  완료 후 보고서 생성 (draft=LLM판정 기준, final=audit확정)
  --dry-run             실행 계획만 출력

종료 코드:
  0 — 전체 성공 (또는 dry-run)
  1 — 1건 이상 실패
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    print("[ERROR] pyyaml 없음. pip install pyyaml 후 재실행하세요.", file=sys.stderr)
    sys.exit(1)

# ─── 경로 설정 ────────────────────────────────────────────────────────────────

PALANTIR_DIR = Path(__file__).resolve().parent.parent

# ─── .env 로드 ────────────────────────────────────────────────────────────────

def _load_env() -> None:
    env_path = PALANTIR_DIR / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = val.strip()

_load_env()

# ─── 상수 ─────────────────────────────────────────────────────────────────────

BACKEND_SKILLS  = ["injection", "xss", "file", "data", "sca"]
FRONTEND_SKILLS = ["xss", "sca"]
PHP_SKILLS      = ["sca"]
ALL_SKILLS      = ["injection", "xss", "file", "data", "sca"]

# ─── YAML 로드 ────────────────────────────────────────────────────────────────

def load_targets(targets_file: Path) -> tuple[dict, list[dict]]:
    if not targets_file.exists():
        print(f"[ERROR] targets 파일 없음: {targets_file}", file=sys.stderr)
        sys.exit(1)
    data     = yaml.safe_load(targets_file.read_text(encoding="utf-8"))
    defaults = data.get("defaults", {})
    targets  = [t for t in data.get("targets", []) if t.get("active", True)]
    return defaults, targets


def resolve_skills(target: dict, defaults: dict, cli_skills: list[str] | None) -> list[str]:
    """실행 skill 목록 확정. CLI --skills 가 있으면 교집합 필터링."""
    if "skills" in target:
        skills = target["skills"]
    else:
        repo_type = target.get("repo_type", "")
        if repo_type == "frontend":
            skills = FRONTEND_SKILLS
        elif repo_type in ("php", "unknown"):
            skills = PHP_SKILLS
        else:
            # backend 또는 미지정 → 전체 (run_skill이 clone 후 재감지)
            skills = BACKEND_SKILLS
    if cli_skills:
        skills = [s for s in skills if s in cli_skills]
    return skills

# ─── Auto-Clone ───────────────────────────────────────────────────────────────

def auto_clone(target: dict, defaults: dict, force: bool = False) -> tuple[bool, str]:
    """
    clone_repo.py를 subprocess로 호출해 testbed/<repo>를 준비한다.
    반환: (성공 여부, 메시지)
    """
    repo    = target["repo"]
    project = target.get("project", "")
    branch  = target.get("branch") or defaults.get("branch", "")
    dest    = PALANTIR_DIR / "testbed" / repo

    # 이미 존재하고 force 아님 → pull만
    if dest.exists() and (dest / ".git").exists() and not force:
        print(f"  [clone] 이미 존재 — git pull: testbed/{repo}")
        cmd = ["python3", str(PALANTIR_DIR / "tools" / "clone_repo.py"),
               project, repo]
        if branch:
            cmd += ["--branch", branch]
        r = subprocess.run(cmd, cwd=str(PALANTIR_DIR))
        return r.returncode == 0, "pull"

    if not project:
        return False, f"project key 미설정 — testbed/{repo} 없음. 수동 clone 필요"

    print(f"  [clone] {project}/{repo} → testbed/{repo}/")
    cmd = ["python3", str(PALANTIR_DIR / "tools" / "clone_repo.py"),
           project, repo]
    if branch:
        cmd += ["--branch", branch]
    if force:
        cmd.append("--force")

    r = subprocess.run(cmd, cwd=str(PALANTIR_DIR))
    if r.returncode != 0:
        return False, f"clone 실패 (exit {r.returncode})"
    return True, "cloned"

# ─── run_skill 실행 ───────────────────────────────────────────────────────────

def run_skill(
    *,
    skill: str,
    repo: str,
    run_id: str,
    provider: str,
    max_budget_usd: float,
    max_turns: int,
    skip_scan: bool,
    skip_llm: bool,
) -> bool:
    """run_skill.py 1회 실행. 성공 시 True."""
    src    = str(PALANTIR_DIR / "testbed" / repo)
    prefix = str(PALANTIR_DIR / "state" / repo / skill / run_id)

    cmd = [
        sys.executable,
        str(PALANTIR_DIR / "tools" / "run_skill.py"),
        skill, src, prefix,
        "--provider", provider,
        "--batch",
        "--max-budget-usd", str(max_budget_usd),
        "--max-turns",      str(max_turns),
    ]
    if skip_scan: cmd.append("--skip-scan")
    if skip_llm:  cmd.append("--skip-llm")

    print(f"\n  skill  : {skill}")
    print(f"  prefix : state/{repo}/{skill}/{run_id}/")

    Path(prefix).mkdir(parents=True, exist_ok=True)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(PALANTIR_DIR),
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
        proc.wait()
        if proc.returncode != 0:
            print(f"\n  [FAIL] run_skill 종료 코드 {proc.returncode}")
            return False
        return True
    except Exception as exc:
        print(f"\n  [ERROR] run_skill 실행 오류: {exc}")
        return False

# ─── 로그 tee ────────────────────────────────────────────────────────────────

class Tee:
    def __init__(self, log_path: Path):
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._file   = log_path.open("a", encoding="utf-8")
        self._stdout = sys.stdout

    def write(self, text: str) -> None:
        self._stdout.write(text)
        self._file.write(text)

    def flush(self) -> None:
        self._stdout.flush()
        self._file.flush()

    def close(self) -> None:
        self._file.close()

    def fileno(self):
        return self._stdout.fileno()

# ─── 요약 출력 ────────────────────────────────────────────────────────────────

def print_plan(jobs: list[tuple[str, str]], defaults: dict, args: argparse.Namespace,
               run_id: str, need_clone: list[str]) -> None:
    provider = args.provider or defaults.get("provider", "claude-cli")
    budget   = args.max_budget_usd if args.max_budget_usd is not None else defaults.get("max_budget_usd", 3.0)
    turns    = args.max_turns if args.max_turns is not None else defaults.get("max_turns", 80)

    print(f"\n{'═'*60}")
    print(f"  palantir pipeline_runner  RUN_ID={run_id}")
    print(f"  provider={provider}  budget=${budget:.1f}/skill  max_turns={turns}")
    if args.no_clone:
        print("  [--no-clone] clone 단계 건너뜀")
    elif args.force_clone:
        print("  [--force-clone] 기존 testbed 삭제 후 재clone")
    if args.dry_run:
        print("  [DRY-RUN 모드]")
    print(f"  총 {len(jobs)}건 (repo × skill)")

    if need_clone:
        print(f"\n  [clone 예정] {len(need_clone)}개 repo")
        for r in need_clone:
            print(f"    + {r}")

    print(f"{'═'*60}")

    cur_repo = None
    for repo, skill in jobs:
        if repo != cur_repo:
            cur_repo = repo
            print(f"\n  {repo}")
        print(f"    → {skill}")


def print_summary(results: list[dict], run_id: str, elapsed: float) -> None:
    total   = len(results)
    success = sum(1 for r in results if r["ok"])
    failed  = total - success

    print(f"\n{'═'*60}")
    print(f"  파이프라인 완료  RUN_ID={run_id}")
    print(f"  소요: {elapsed/60:.1f}분  |  성공: {success}/{total}  실패: {failed}")
    print(f"{'═'*60}")

    if failed:
        print("\n  [실패 목록]")
        for r in results:
            if not r["ok"]:
                mark = "clone실패" if r.get("clone_failed") else "scan실패"
                print(f"    ✗ {r['repo']} / {r.get('skill', '(all)')}  [{mark}]")

    print("\n  [전체 결과]")
    cur_repo = None
    for r in results:
        if r["repo"] != cur_repo:
            cur_repo = r["repo"]
            print(f"\n  {cur_repo}")
        if r.get("clone_failed"):
            print(f"    ✗ (clone 실패 — skill 전체 skip)")
            break
        mark       = "✓" if r["ok"] else "✗"
        state_path = f"state/{r['repo']}/{r.get('skill','?')}/{run_id}/"
        print(f"    {mark} {r.get('skill','?'):12s}  →  {state_path}")

# ─── 보고서 호출 ──────────────────────────────────────────────────────────────

def call_generate_report(run_id: str, report_type: str, elapsed: float | None = None) -> None:
    report_script = PALANTIR_DIR / "tools" / "generate_report.py"
    if not report_script.exists():
        print(f"\n[WARN] generate_report.py 없음 — --report {report_type} 건너뜀")
        return
    print(f"\n[보고서 생성] --report {report_type}  RUN_ID={run_id}")
    cmd = [sys.executable, str(report_script), "--run-id", run_id, "--type", report_type]
    if elapsed is not None:
        cmd += ["--elapsed", str(round(elapsed, 1))]
    r = subprocess.run(cmd, cwd=str(PALANTIR_DIR))
    if r.returncode != 0:
        print(f"[WARN] generate_report.py 종료 코드 {r.returncode}")

# ─── 메인 ────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="palantir 파이프라인 오케스트레이터 — clone → scan → report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--targets",   default="trigger/scan_targets.yaml")
    parser.add_argument("--repos",     nargs="+", metavar="REPO")
    parser.add_argument("--skills",    nargs="+", metavar="SKILL")
    parser.add_argument("--provider",  default=None)
    parser.add_argument("--no-clone",    dest="no_clone",    action="store_true",
                        help="auto-clone 건너뜀 (testbed 없으면 해당 repo skip)")
    parser.add_argument("--force-clone", dest="force_clone", action="store_true",
                        help="기존 testbed 삭제 후 재clone")
    parser.add_argument("--skip-scan",    action="store_true")
    parser.add_argument("--skip-llm",     action="store_true")
    parser.add_argument("--max-budget-usd", type=float, default=None)
    parser.add_argument("--max-turns",      type=int,   default=None)
    parser.add_argument("--report",  choices=["draft", "final"], default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.skills:
        invalid = [s for s in args.skills if s not in ALL_SKILLS]
        if invalid:
            parser.error(f"알 수 없는 skill: {invalid}. 선택 가능: {ALL_SKILLS}")

    targets_file = PALANTIR_DIR / args.targets
    defaults, targets = load_targets(targets_file)

    run_id   = datetime.now().strftime("%Y%m%d_%H%M")
    log_path = PALANTIR_DIR / "logs" / f"pipeline_{run_id}.log"

    # ── 대상 필터링 + repo 단위 구조화 ───────────────────────────────────────
    # repo_jobs: {repo: {"target": ..., "skills": [...]}}
    repo_jobs: dict[str, dict] = {}

    for tgt in targets:
        repo = tgt.get("repo", "")
        if not repo:
            continue
        if args.repos and repo not in args.repos:
            continue

        skills = resolve_skills(tgt, defaults, args.skills)
        if not skills:
            continue

        repo_jobs[repo] = {"target": tgt, "skills": skills}

    if not repo_jobs:
        print("[INFO] 실행할 대상이 없습니다. --repos 필터 또는 active 설정을 확인하세요.")
        return 0

    # clone 필요 여부 판단 (dry-run 포함 안내용)
    need_clone = []
    if not args.no_clone:
        for repo, info in repo_jobs.items():
            dest = PALANTIR_DIR / "testbed" / repo
            if not dest.exists() or args.force_clone:
                need_clone.append(repo)

    # ── 계획 출력 ─────────────────────────────────────────────────────────────
    flat_jobs = [(r, s) for r, info in repo_jobs.items() for s in info["skills"]]
    print_plan(flat_jobs, defaults, args, run_id, need_clone)

    if args.dry_run:
        return 0

    # ── 로그 tee 설정 ─────────────────────────────────────────────────────────
    tee = Tee(log_path)
    sys.stdout = tee  # type: ignore[assignment]
    print(f"  로그: {log_path}\n")

    # ── 실행 ─────────────────────────────────────────────────────────────────
    start_ts = datetime.now()
    results: list[dict] = []

    for repo, info in repo_jobs.items():
        tgt    = info["target"]
        skills = info["skills"]

        print(f"\n{'─'*60}")
        print(f"  repo: {repo}")

        # ── 1. Auto-Clone ────────────────────────────────────────────────────
        if not args.no_clone:
            clone_ok, clone_msg = auto_clone(tgt, defaults, force=args.force_clone)
            if not clone_ok:
                print(f"  [FAIL] clone: {clone_msg}")
                results.append({"repo": repo, "ok": False, "clone_failed": True})
                continue
        else:
            dest = PALANTIR_DIR / "testbed" / repo
            if not dest.exists():
                print(f"  [SKIP] testbed/{repo} 없음 (--no-clone 모드)")
                results.append({"repo": repo, "ok": False, "clone_failed": True,
                                 "note": "no-clone + testbed 없음"})
                continue

        # ── 2. Skill 순차 실행 ───────────────────────────────────────────────
        provider   = args.provider or tgt.get("provider") or defaults.get("provider", "claude-cli")
        budget     = args.max_budget_usd if args.max_budget_usd is not None \
                     else float(tgt.get("max_budget_usd") or defaults.get("max_budget_usd", 3.0))
        max_turns  = args.max_turns if args.max_turns is not None \
                     else int(tgt.get("max_turns") or defaults.get("max_turns", 80))

        for skill in skills:
            ok = run_skill(
                skill=skill,
                repo=repo,
                run_id=run_id,
                provider=provider,
                max_budget_usd=budget,
                max_turns=max_turns,
                skip_scan=args.skip_scan,
                skip_llm=args.skip_llm,
            )
            results.append({"repo": repo, "skill": skill, "ok": ok})

    elapsed = (datetime.now() - start_ts).total_seconds()

    # ── 요약 ──────────────────────────────────────────────────────────────────
    print_summary(results, run_id, elapsed)

    # ── 진단현황 자동 갱신 ────────────────────────────────────────────────────
    update_plan = PALANTIR_DIR / "tools" / "update_ocb_plan.py"
    if update_plan.exists():
        print("\n[진단현황 갱신] update_ocb_plan.py --auto ...")
        subprocess.run([sys.executable, str(update_plan), "--auto"], cwd=str(PALANTIR_DIR))

    # ── 보고서 생성 ───────────────────────────────────────────────────────────
    if args.report:
        call_generate_report(run_id, args.report, elapsed)

    # ── 결과 JSON 저장 ────────────────────────────────────────────────────────
    summary_path = PALANTIR_DIR / "logs" / f"pipeline_{run_id}_summary.json"
    summary_path.write_text(
        json.dumps({
            "run_id":  run_id,
            "elapsed": round(elapsed, 1),
            "total":   len(results),
            "success": sum(1 for r in results if r["ok"]),
            "failed":  sum(1 for r in results if not r["ok"]),
            "results": results,
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\n  요약: {summary_path}")

    sys.stdout = tee._stdout  # type: ignore[attr-defined]
    tee.close()

    return 1 if any(not r["ok"] for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
