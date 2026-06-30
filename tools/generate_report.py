#!/usr/bin/env python3
"""
generate_report.py — 파이프라인 1차 보고서 생성기

사용법:
    # RUN_ID 지정 모드 (새 파이프라인 — 5개 skill 공통 RUN_ID)
    python3 tools/generate_report.py --run-id 20260506_2200 --type draft
    python3 tools/generate_report.py --run-id 20260506_2200 --type final --repos ocb-webview-api

    # 레포 단위 모드 (레거시 데이터 — skill별 RUN_ID 산재)
    python3 tools/generate_report.py --repos ocb-webview-api --type draft
    python3 tools/generate_report.py --all-repos --type draft   # state/ 전체 레포

draft  : llm_checked True/False 무관하게 모든 findings 포함
final  : llm_checked True 파일만 포함 (LLM 교차검증 완료 항목만)
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

PALANTIR_DIR = Path(__file__).resolve().parent.parent
STATE_DIR    = PALANTIR_DIR / "state"
LOGS_DIR     = PALANTIR_DIR / "logs"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_KR    = {
    "Critical":      "매우위험",
    "High":          "고위험",
    "Medium":        "중간위험",
    "Low":           "저위험",
    "Informational": "매우낮음",
}

SKILL_LABEL = {
    "injection": "SQL/OS Command Injection",
    "xss":       "XSS",
    "file":      "파일 처리",
    "data":      "데이터 보호",
    "sca":       "SCA (오픈소스 CVE)",
}


# ── 데이터 수집 ───────────────────────────────────────────────────────────────

_SKIP_DIRS = {"old", "README.md"}


def _load_doc(path: Path, report_type: str) -> list[dict]:
    """findings_*.json 한 파일을 읽어 result in (취약,정보) findings 반환."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] 파싱 실패 {path}: {e}")
        return []
    if report_type == "final" and doc.get("llm_checked") is not True:
        return []
    return [f for f in doc.get("findings", [])
            if f.get("result", "취약") in ("취약", "정보")]


def collect_findings(run_id: str, report_type: str, filter_repos: list[str] | None
                     ) -> dict[str, dict[str, list[dict]]]:
    """
    state/<repo>/<skill>/<run_id>/findings_*.json 을 모두 읽고
    { repo → { skill → [finding, ...] } } 딕셔너리를 반환한다.
    """
    data: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    pattern = f"*/*/{run_id}/findings_*.json"

    matched = sorted(STATE_DIR.glob(pattern))
    if not matched:
        print(f"[WARN] run_id={run_id} 에 해당하는 findings 파일을 찾지 못했습니다.")
        print(f"       검색 경로: {STATE_DIR}/{pattern}")
        return data

    for path in matched:
        # state/<repo>/<skill>/<run_id>/findings_SKILL.json
        repo  = path.parts[-4]
        skill = path.parts[-3]

        if filter_repos and repo not in filter_repos:
            continue

        for f in _load_doc(path, report_type):
            data[repo][skill].append(f)

    return data


def collect_findings_for_repo(repo: str, report_type: str
                               ) -> dict[str, dict[str, list[dict]]]:
    """
    레포 단위 모드 — RUN_ID 없이 skill별 최신 findings 파일 하나씩 선택.
    state/<repo>/<skill>/*/findings_*.json 에서 skill별로 RUN_ID 최신 파일을 쓴다.
    """
    data: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    repo_dir = STATE_DIR / repo
    if not repo_dir.is_dir():
        print(f"[WARN] 레포 경로 없음: {repo_dir}")
        return data

    for skill_dir in sorted(repo_dir.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill = skill_dir.name
        # skill 하위에서 RUN_ID 디렉터리를 내림차순 정렬 → 가장 최신 선택
        run_dirs = sorted(
            (d for d in skill_dir.iterdir() if d.is_dir()),
            key=lambda d: d.name, reverse=True,
        )
        for run_dir in run_dirs:
            files = sorted(run_dir.glob("findings_*.json"))
            if not files:
                continue
            findings = _load_doc(files[0], report_type)
            if findings or report_type == "draft":
                for f in findings:
                    data[repo][skill].append(f)
            break  # 최신 RUN_ID 하나만 사용

    return data


def collect_all_repos(report_type: str) -> dict[str, dict[str, list[dict]]]:
    """state/ 내 모든 레포를 레포 단위 모드로 수집."""
    merged: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for entry in sorted(STATE_DIR.iterdir()):
        if not entry.is_dir() or entry.name in _SKIP_DIRS:
            continue
        repo_data = collect_findings_for_repo(entry.name, report_type)
        for repo, skill_map in repo_data.items():
            for skill, findings in skill_map.items():
                merged[repo][skill].extend(findings)
    return merged


# ── 집계 ─────────────────────────────────────────────────────────────────────

_SEV_ALIAS = {"Info": "Informational", "info": "Informational"}


def _normalize_sev(sev: str) -> str:
    return _SEV_ALIAS.get(sev, sev)


def severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = _normalize_sev(f.get("severity", "Informational"))
        if sev in counts:
            counts[sev] += 1
    return counts


def repo_totals(skill_map: dict[str, list[dict]]) -> dict[str, int]:
    totals: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for findings in skill_map.values():
        for sev, cnt in severity_counts(findings).items():
            totals[sev] += cnt
    return totals


def all_findings_flat(data: dict) -> list[tuple[str, str, dict]]:
    rows: list[tuple[str, str, dict]] = []
    for repo, skill_map in sorted(data.items()):
        for skill, findings in sorted(skill_map.items()):
            for f in findings:
                rows.append((repo, skill, f))
    return rows


# ── 마크다운 렌더링 ───────────────────────────────────────────────────────────

def _location(finding: dict) -> str:
    raw   = finding.get("scope") or {}
    # scope가 리스트인 오래된 포맷 방어
    scope = raw[0] if isinstance(raw, list) else raw
    ep    = scope.get("endpoint") or ""
    evidence = finding.get("evidence") or {}
    if isinstance(evidence, list):
        evidence = evidence[0] if evidence else {}
    elif isinstance(evidence, str):
        evidence = {}
    af    = scope.get("affected_file") or evidence.get("file", "")
    line  = scope.get("affected_line") or evidence.get("lines", "")
    pkg   = scope.get("package") or ""

    if ep and af:
        return f"`{ep}` → `{af}`"
    if ep:
        return f"`{ep}`"
    if pkg:
        ver = scope.get("version", "")
        cve = scope.get("cve_id", "")
        return f"`{pkg} {ver}` ({cve})" if cve else f"`{pkg} {ver}`"
    if af:
        return f"`{af}`" + (f":{line}" if line else "")
    return "—"


def render_markdown(
    run_id:      str | None,
    report_type: str,
    data:        dict[str, dict[str, list[dict]]],
    elapsed_sec: float | None = None,
) -> str:
    lines: list[str] = []
    now   = datetime.now().strftime("%Y-%m-%d %H:%M")
    total_findings = sum(
        len(f) for sm in data.values() for f in sm.values()
    )
    repos = sorted(data.keys())

    run_id_label = f"`{run_id}`" if run_id else f"레포 단위 ({now[:10]})"

    # ── 헤더 ──────────────────────────────────────────────────────────────────
    lines += [
        f"# 보안 진단 1차 보고서 ({report_type.upper()})",
        f"",
        f"| 항목 | 내용 |",
        f"|------|------|",
        f"| 생성 일시 | {now} |",
        f"| RUN_ID | {run_id_label} |",
        f"| 보고서 유형 | {report_type} |",
        f"| 진단 대상 | {len(repos)}개 레포 |",
        f"| 전체 발견 건수 | {total_findings}건 |",
    ]
    if elapsed_sec is not None:
        lines.append(f"| 소요 시간 | {elapsed_sec/60:.1f}분 |")
    lines.append("")

    if report_type == "final":
        lines += [
            "> **[FINAL]** LLM 교차검증(`llm_checked: true`) 완료 파일만 집계합니다.",
            "",
        ]
    else:
        lines += [
            "> **[DRAFT]** LLM 검증 완료 여부 무관하게 모든 findings를 포함합니다.",
            "",
        ]

    if not data:
        lines += ["findings 없음 — 전체 양호 또는 스캔 결과 없음.", ""]
        return "\n".join(lines)

    # ── 전체 severity 요약 ─────────────────────────────────────────────────────
    global_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for sm in data.values():
        for findings in sm.values():
            for sev, cnt in severity_counts(findings).items():
                global_counts[sev] += cnt


    lines += [
        "## 전체 위험도 요약",
        "",
        "| 위험도 | 건수 |",
        "|--------|-----:|",
    ]
    for sev in SEVERITY_ORDER:
        cnt = global_counts[sev]
        if cnt:
            lines.append(f"| **{sev}** ({SEVERITY_KR[sev]}) | {cnt} |")
    lines.append("")

    # ── 레포별 요약 테이블 ────────────────────────────────────────────────────
    all_skills = sorted({sk for sm in data.values() for sk in sm})

    lines += [
        "## 레포별 결과 요약",
        "",
    ]
    # 헤더: 레포 | Critical | High | Medium | Low | Info | 합계
    sev_cols = [s for s in SEVERITY_ORDER if any(
        severity_counts(sm.get(sk, []))[s] > 0
        for sm in data.values() for sk in sm
    )]
    if not sev_cols:
        sev_cols = ["Critical", "High", "Medium"]

    hdr_cols = " | ".join(f"{s}" for s in sev_cols)
    sep_cols = " | ".join("---:" for _ in sev_cols)
    lines += [
        f"| 레포 | 스킬 | {hdr_cols} | 합계 |",
        f"|------|------|{sep_cols}|-----:|",
    ]

    for repo in repos:
        skill_map = data[repo]
        totals    = repo_totals(skill_map)
        total_cnt = sum(totals.values())
        skills_str = ", ".join(SKILL_LABEL.get(sk, sk) for sk in sorted(skill_map))
        sev_vals = " | ".join(str(totals[s]) for s in sev_cols)
        lines.append(f"| **{repo}** | {skills_str} | {sev_vals} | {total_cnt} |")
    lines.append("")

    # ── Critical / High 상세 목록 ─────────────────────────────────────────────
    priority_findings = [
        (repo, skill, f)
        for repo, skill, f in all_findings_flat(data)
        if _normalize_sev(f.get("severity", "")) in ("Critical", "High")
    ]

    if priority_findings:
        lines += [
            "## Critical / High 상세",
            "",
            "| # | 레포 | 스킬 | 위험도 | 제목 | 위치 |",
            "|---|------|------|--------|------|------|",
        ]
        for idx, (repo, skill, f) in enumerate(priority_findings, 1):
            sev  = f.get("severity", "")
            title = f.get("title", "—").replace("|", "｜")
            loc   = _location(f).replace("|", "｜")
            lines.append(
                f"| {idx} | {repo} | {SKILL_LABEL.get(skill, skill)} "
                f"| **{sev}** | {title} | {loc} |"
            )
        lines.append("")

    # ── 레포별 상세 ───────────────────────────────────────────────────────────
    lines += ["## 레포별 상세", ""]

    for repo in repos:
        skill_map = data[repo]
        totals    = repo_totals(skill_map)
        total_cnt = sum(totals.values())

        lines += [
            f"### {repo}",
            "",
            f"총 {total_cnt}건 — "
            + "  ".join(
                f"**{sev}** {cnt}"
                for sev, cnt in totals.items() if cnt
            ),
            "",
        ]

        for skill in sorted(skill_map):
            findings = skill_map[skill]
            if not findings:
                continue
            sc = severity_counts(findings)
            lines += [
                f"#### {SKILL_LABEL.get(skill, skill)} ({len(findings)}건)",
                "",
                "| ID | 위험도 | 제목 | 결과 | 위치 |",
                "|----|--------|------|------|------|",
            ]
            def _sev_key(x: dict) -> int:
                sev = _normalize_sev(x.get("severity", "Informational"))
                if sev not in SEVERITY_ORDER:
                    sev = "Informational"
                return SEVERITY_ORDER.index(sev)

            for f in sorted(findings, key=_sev_key):
                fid   = f.get("finding_id", "—")
                sev   = f.get("severity", "—")
                title = f.get("title", "—").replace("|", "｜")
                res   = f.get("result", "—")
                loc   = _location(f).replace("|", "｜")
                lines.append(f"| {fid} | {sev} | {title} | {res} | {loc} |")
            lines.append("")

    # ── 푸터 ─────────────────────────────────────────────────────────────────
    lines += [
        "---",
        "",
        f"*생성: palantir generate_report.py — {now}*",
        "",
    ]

    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="palantir 1차 보고서 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--run-id",   default=None,
                        help="파이프라인 RUN_ID (YYYYMMDD_HHMM) — 생략 시 레포 단위 모드")
    parser.add_argument("--type",     default="draft", choices=["draft", "final"],
                        help="보고서 유형 (draft | final)")
    parser.add_argument("--repos",    nargs="+", metavar="REPO",
                        help="특정 repo만 포함 (생략 시 전체)")
    parser.add_argument("--all-repos", action="store_true",
                        help="state/ 내 모든 레포 대상 (레포 단위 모드)")
    parser.add_argument("--elapsed",  type=float, default=None,
                        help="파이프라인 소요 시간 (초) — pipeline_runner가 전달")
    args = parser.parse_args()

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    today = datetime.now().strftime("%Y%m%d")

    # ── 레포 단위 모드 (--run-id 없음) ────────────────────────────────────────
    if args.run_id is None:
        if args.all_repos:
            repos_to_scan = None  # collect_all_repos 가 처리
        elif args.repos:
            repos_to_scan = args.repos
        else:
            print("[ERROR] --run-id 없을 때는 --repos 또는 --all-repos 를 지정해야 합니다.")
            return 1

        if repos_to_scan is None:
            print(f"[보고서] 레포 단위 모드 — state/ 전체  type={args.type}")
            data = collect_all_repos(args.type)
        else:
            print(f"[보고서] 레포 단위 모드 — {repos_to_scan}  type={args.type}")
            data = defaultdict(lambda: defaultdict(list))
            for repo in repos_to_scan:
                repo_data = collect_findings_for_repo(repo, args.type)
                for r, sm in repo_data.items():
                    for skill, findings in sm.items():
                        data[r][skill].extend(findings)

        if len(data) == 1:
            # 레포 1개 → 레포명 포함 파일명
            repo_name = next(iter(data))
            out_path = LOGS_DIR / f"report_{args.type}_{repo_name}_{today}.md"
        else:
            out_path = LOGS_DIR / f"report_{args.type}_batch_{today}.md"

        total = sum(len(f) for sm in data.values() for f in sm.values())
        print(f"[보고서] {len(data)}개 레포  {total}건 findings")

        md = render_markdown(None, args.type, data, args.elapsed)
        out_path.write_text(md, encoding="utf-8")
        print(f"[보고서] 저장 완료: {out_path}")
        return 0

    # ── RUN_ID 지정 모드 (기존 동작) ──────────────────────────────────────────
    out_path = LOGS_DIR / f"report_{args.type}_{args.run_id}.md"

    print(f"[보고서] RUN_ID={args.run_id}  type={args.type}")
    print(f"[보고서] findings 수집 중: {STATE_DIR}/*/{args.run_id}/")

    data = collect_findings(args.run_id, args.type, args.repos)

    total = sum(len(f) for sm in data.values() for f in sm.values())
    print(f"[보고서] {len(data)}개 레포  {total}건 findings")

    md = render_markdown(args.run_id, args.type, data, args.elapsed)
    out_path.write_text(md, encoding="utf-8")

    print(f"[보고서] 저장 완료: {out_path}")

    # final 보고서 완료 후 palantir-reports 레포에 자동 커밋
    if args.type == "final":
        commit_script = PALANTIR_DIR / "tools" / "commit_report.py"
        if commit_script.exists():
            print(f"\n[보고서] palantir-reports 커밋 중...")
            cmd = [sys.executable, str(commit_script), "--run-id", args.run_id]
            if args.repos:
                cmd += ["--repos"] + args.repos
            subprocess.run(cmd, cwd=str(PALANTIR_DIR))

    return 0


if __name__ == "__main__":
    sys.exit(main())
