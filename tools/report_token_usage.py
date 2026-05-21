#!/usr/bin/env python3
"""
report_token_usage.py — 스캔 로그에서 토큰 비용/시간 통계를 추출하여 마크다운 보고서 생성.

사용법:
  python3 tools/report_token_usage.py [로그파일]
  python3 tools/report_token_usage.py               # logs/ 에서 최신 run_all_*.log 자동 선택
"""

import re
import sys
from pathlib import Path
from datetime import datetime

PALANTIR = Path(__file__).resolve().parent.parent

# ── 로그 파싱 ─────────────────────────────────────────────────────────────────

def parse_log(log_path: Path) -> list[dict]:
    """각 skill×repo 실행 결과를 파싱하여 레코드 리스트로 반환."""
    text = log_path.read_text(encoding="utf-8", errors="replace")
    records = []

    # 실행 시작 라인: "→ [skill] repo  prefix=..."
    start_pat = re.compile(
        r"\[(\d{2}:\d{2}:\d{2})\].*?→ \[(\w+)\] ([\w-]+)\s+prefix=(\S+)"
    )
    cost_pat    = re.compile(r"비용: \$([\d.]+) USD")
    time_pat    = re.compile(r"소요시간: (\d+)초")
    size_pat    = re.compile(r"findings_\w+\.json \(([,\d]+) bytes\)")
    ok_pat      = re.compile(r"✓ \[(\w+)\] ([\w-]+) 완료")
    err_pat     = re.compile(r"ERR:.*\[(\w+)\] ([\w-]+) (실패|findings 없음)")

    lines = text.splitlines()
    current: dict | None = None

    for line in lines:
        m = start_pat.search(line)
        if m:
            if current:
                records.append(current)
            current = {
                "start_time": m.group(1),
                "skill":      m.group(2),
                "repo":       m.group(3),
                "prefix":     m.group(4),
                "cost_usd":   None,
                "elapsed_s":  None,
                "size_bytes": None,
                "status":     "running",
            }
            continue

        if current is None:
            continue

        if m2 := cost_pat.search(line):
            current["cost_usd"] = float(m2.group(1))
        if m2 := time_pat.search(line):
            current["elapsed_s"] = int(m2.group(1))
        if m2 := size_pat.search(line):
            current["size_bytes"] = int(m2.group(1).replace(",", ""))
        if m2 := ok_pat.search(line):
            current["status"] = "ok"
        if m2 := err_pat.search(line):
            current["status"] = "error"

    if current:
        records.append(current)
    return records


# ── 보고서 생성 ────────────────────────────────────────────────────────────────

SKILL_ORDER = ["injection", "xss", "file", "data", "sca"]
ALL_REPOS = [
    "ocb-bridge-scheduler",
    "ocb-community-api",
    "ocb-epm",
    "ocb-fnc-webview-api",
    "ocb-iam",
    "ocb-joy-api",
    "ocb-sugar",
    "ocb-webview-api",
    "ocb-wp-api",
    "ocbws-web-api",
]

def fmt_cost(v):   return f"${v:.3f}" if v is not None else "—"
def fmt_time(v):
    if v is None: return "—"
    return f"{v//60}m{v%60:02d}s" if v >= 60 else f"{v}s"
def fmt_size(v):   return f"{v//1024}K" if v is not None else "—"


def build_report(records: list[dict], log_name: str) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # 인덱스: (skill, repo) → record
    idx = {(r["skill"], r["repo"]): r for r in records}
    done  = [r for r in records if r["status"] == "ok"]
    errs  = [r for r in records if r["status"] == "error"]
    runs  = [r for r in records if r["status"] == "running"]

    total_cost = sum(r["cost_usd"] for r in done if r["cost_usd"])
    total_time = sum(r["elapsed_s"] for r in done if r["elapsed_s"])

    lines = [
        f"# OCB 진단 토큰 사용량 보고서",
        f"",
        f"생성 시각: {now}  |  로그: `{log_name}`",
        f"",
        f"## 진행 현황",
        f"",
        f"| 구분 | 건수 |",
        f"|---|---|",
        f"| 완료 (✓) | **{len(done)}** / {len(records)} |",
        f"| 오류 (✗) | **{len(errs)}** |",
        f"| 진행 중 (→) | **{len(runs)}** |",
        f"| 총 비용 (완료분) | **${total_cost:.3f} USD** |",
        f"| 총 소요시간 (완료분) | **{total_time//3600}h {(total_time%3600)//60}m {total_time%60}s** |",
        f"",
    ]

    # ── skill별 집계 ────────────────────────────────────────────────────────
    lines += ["## Skill별 집계", ""]
    lines += ["| Skill | 완료 | 평균비용 | 최대비용 | 평균시간 | 누적비용 |"]
    lines += ["|---|---|---|---|---|---|"]
    for skill in SKILL_ORDER:
        recs = [r for r in done if r["skill"] == skill]
        if not recs:
            lines.append(f"| {skill} | 0 | — | — | — | — |")
            continue
        costs = [r["cost_usd"] for r in recs if r["cost_usd"] is not None]
        times = [r["elapsed_s"] for r in recs if r["elapsed_s"] is not None]
        avg_c = sum(costs)/len(costs) if costs else 0
        max_c = max(costs) if costs else 0
        avg_t = sum(times)/len(times) if times else 0
        tot_c = sum(costs)
        lines.append(
            f"| {skill} | {len(recs)}/10 | ${avg_c:.3f} | ${max_c:.3f} | {fmt_time(int(avg_t))} | ${tot_c:.3f} |"
        )
    lines.append("")

    # ── repo별 집계 ─────────────────────────────────────────────────────────
    lines += ["## Repo별 집계", ""]
    lines += ["| Repo | 완료 | 총비용 | 총시간 |"]
    lines += ["|---|---|---|---|"]
    for repo in ALL_REPOS:
        recs = [r for r in done if r["repo"] == repo]
        costs = [r["cost_usd"] for r in recs if r["cost_usd"] is not None]
        times = [r["elapsed_s"] for r in recs if r["elapsed_s"] is not None]
        tot_c = sum(costs)
        tot_t = sum(times)
        cnt   = len(recs)
        lines.append(f"| {repo} | {cnt}/5 | {fmt_cost(tot_c) if costs else '—'} | {fmt_time(tot_t) if times else '—'} |")
    lines.append("")

    # ── 전체 매트릭스 ────────────────────────────────────────────────────────
    lines += ["## 전체 매트릭스 (비용 / 소요시간)", ""]
    header = "| Repo | " + " | ".join(s.upper()[:4] for s in SKILL_ORDER) + " |"
    sep    = "|---|" + "|".join(["---|"] * len(SKILL_ORDER))
    lines += [header, sep]

    for repo in ALL_REPOS:
        cells = []
        for skill in SKILL_ORDER:
            r = idx.get((skill, repo))
            if r is None:
                cells.append("?")
            elif r["status"] == "ok":
                c = fmt_cost(r["cost_usd"])
                t = fmt_time(r["elapsed_s"])
                cells.append(f"{c} / {t}")
            elif r["status"] == "error":
                cells.append("✗ ERR")
            else:
                cells.append("→ 진행중")
        lines.append(f"| {repo} | " + " | ".join(cells) + " |")
    lines.append("")

    # ── 비용 예측 ───────────────────────────────────────────────────────────
    if done:
        avg_per_job = total_cost / len(done)
        remaining   = 50 - len(done)  # 총 50 jobs (10 repo × 5 skill)
        projected   = total_cost + avg_per_job * remaining
        lines += [
            "## 비용 예측",
            "",
            f"| 항목 | 값 |",
            f"|---|---|",
            f"| 완료 {len(done)}건 평균 비용 | ${avg_per_job:.3f} |",
            f"| 잔여 {remaining}건 예상 비용 | ${avg_per_job * remaining:.2f} |",
            f"| 전체 50건 예상 총합 | **${projected:.2f} USD** |",
            f"| Claude Pro $20/월 대비 | {projected/20*100:.1f}% |",
            "",
            "> ⚠️ ocb-community-api(injection $1.59)처럼 대규모 repo는 평균 왜곡 가능.",
            "",
        ]

    # ── 오류 목록 ───────────────────────────────────────────────────────────
    if errs:
        lines += ["## 오류 목록", ""]
        for r in errs:
            lines.append(f"- `[{r['skill']}] {r['repo']}` — {r.get('prefix', '')}")
        lines.append("")

    lines += [
        "---",
        f"*auto-generated by `tools/report_token_usage.py`  |  {now}*",
    ]

    return "\n".join(lines)


# ── 메인 ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1:
        log_path = Path(sys.argv[1])
        if not log_path.is_absolute():
            log_path = PALANTIR / log_path
    else:
        logs = sorted((PALANTIR / "logs").glob("run_all_*.log"), key=lambda p: p.stat().st_mtime)
        if not logs:
            print("[ERROR] logs/run_all_*.log 없음")
            sys.exit(1)
        log_path = logs[-1]

    print(f"[파싱] {log_path}")
    records = parse_log(log_path)
    print(f"  총 {len(records)}건 파싱됨  (완료: {sum(1 for r in records if r['status']=='ok')})")

    report = build_report(records, log_path.name)

    out_path = PALANTIR / "docs" / "token_usage_report.md"
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"[저장] {out_path}")
    print()
    print(report)


if __name__ == "__main__":
    main()
