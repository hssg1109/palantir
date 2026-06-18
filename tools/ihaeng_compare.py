#!/usr/bin/env python3
"""
ihaeng_compare.py — 이행진단: 두 진단 회차 간 취약점 변화 비교

사용법:
  python3 tools/ihaeng_compare.py --repo <repo> --base-run-id <base> --new-run-id <new>
  python3 tools/ihaeng_compare.py --repo <repo> --base-run-id <base> --new-run-id <new> --update-registry

비교 결과:
  - fixed     : 이전에 open이었으나 이번 회차에서 FP 또는 미검출 (조치 완료)
  - persistent: 이전·이번 모두 open (미조치)
  - new       : 이번 회차 신규 발견
  - 재발      : 이전에 fixed였으나 이번 회차에서 다시 open
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PALANTIR_DIR = Path(__file__).resolve().parent.parent
STATE_DIR    = PALANTIR_DIR / "state"

sys.path.insert(0, str(PALANTIR_DIR))
from tools.audit_utils import (
    uid_for_finding,
    load_vuln_registry,
    save_vuln_registry,
    log_ihaeng,
)


def _collect_findings(repo: str, run_id: str) -> dict[str, dict]:
    """
    state/<repo>/*/<run_id>/findings_*.json 에서 모든 finding을 읽어
    uid → finding dict 형태로 반환한다.
    """
    findings: dict[str, dict] = {}
    for path in sorted(STATE_DIR.glob(f"{repo}/*/{run_id}/findings_*.json")):
        try:
            skill = path.parts[path.parts.index(repo) + 1]
        except (ValueError, IndexError):
            skill = "unknown"
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for f in doc.get("findings", []):
            review_status = f.get("review_status", "")
            if review_status == "그룹병합":
                continue
            uid = uid_for_finding(repo, skill, f)
            f["_skill"] = skill
            f["_run_id"] = run_id
            findings[uid] = f
    return findings


def _is_open(finding: dict) -> bool:
    result        = finding.get("result", "")
    review_status = finding.get("review_status", "")
    if review_status == "오탐":
        return False
    if result in ("양호", "양호(FP)", "해당없음", "safe"):
        return False
    if review_status in ("정탐",) and result in ("취약", "정보"):
        return True
    if result in ("취약", "정보"):
        return True
    return False


def _compare(
    base_findings: dict[str, dict],
    new_findings:  dict[str, dict],
) -> dict:
    base_uids = set(uid for uid, f in base_findings.items() if _is_open(f))
    new_uids  = set(uid for uid, f in new_findings.items()  if _is_open(f))
    base_fixed_uids = set(uid for uid, f in base_findings.items() if not _is_open(f))

    fixed      = base_uids - new_uids
    persistent = base_uids & new_uids
    new_vulns  = new_uids - base_uids
    재발        = base_fixed_uids & new_uids

    return {
        "fixed":      sorted(fixed),
        "persistent": sorted(persistent),
        "new":        sorted(new_vulns),
        "재발":        sorted(재발),
    }


def _format_report(
    repo:          str,
    base_run_id:   str,
    new_run_id:    str,
    comparison:    dict,
    base_findings: dict[str, dict],
    new_findings:  dict[str, dict],
) -> str:
    now  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# 이행진단 비교 결과 — {repo}",
        f"",
        f"기준 회차: `{base_run_id}` → 비교 회차: `{new_run_id}`",
        f"생성일시: {now}",
        f"",
        f"## 요약",
        f"",
        f"| 구분 | 건수 |",
        f"|------|------|",
        f"| ✅ 조치 완료 (fixed) | {len(comparison['fixed'])} |",
        f"| ⚠️ 미조치 (persistent) | {len(comparison['persistent'])} |",
        f"| 🆕 신규 발견 (new) | {len(comparison['new'])} |",
        f"| 🔄 재발 (재발) | {len(comparison['재발'])} |",
        f"",
    ]

    def _uid_row(uid: str, label: str, findings: dict[str, dict]) -> str:
        f    = findings.get(uid, {})
        fid  = f.get("finding_id", "")
        sev  = f.get("severity", "")
        ttl  = (f.get("title") or uid)[:60]
        skill = f.get("_skill", "")
        return f"| {uid.split(':')[1] if ':' in uid else uid} | {fid} | {sev} | {ttl} | {label} |"

    def _section(title: str, uids: list[str], src: dict[str, dict]) -> list[str]:
        if not uids:
            return [f"## {title}", f"", f"해당 없음", f""]
        rows = [
            f"## {title}",
            f"",
            f"| UID(skill) | Finding ID | 심각도 | 제목 | 비고 |",
            f"|------------|------------|--------|------|------|",
        ]
        for uid in uids:
            rows.append(_uid_row(uid, "", src))
        rows.append("")
        return rows

    lines += _section(f"✅ 조치 완료 ({len(comparison['fixed'])}건)", comparison["fixed"], base_findings)
    lines += _section(f"⚠️ 미조치 ({len(comparison['persistent'])}건)", comparison["persistent"], new_findings)
    lines += _section(f"🆕 신규 발견 ({len(comparison['new'])}건)", comparison["new"], new_findings)
    lines += _section(f"🔄 재발 ({len(comparison['재발'])}건)", comparison["재발"], new_findings)

    return "\n".join(lines)


def _update_registry_statuses(
    repo:       str,
    comparison: dict,
    new_findings: dict[str, dict],
    base_run_id:  str,
    new_run_id:   str,
) -> None:
    registry = load_vuln_registry(repo)
    existing = {f["uid"]: f for f in registry["findings"]}
    today    = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for uid in comparison["fixed"]:
        if uid in existing:
            existing[uid]["status"]      = "fixed"
            existing[uid]["last_run_id"] = new_run_id
            existing[uid]["last_seen"]   = today

    for uid in comparison["persistent"]:
        if uid in existing:
            existing[uid]["status"]      = "open"
            existing[uid]["last_run_id"] = new_run_id
            existing[uid]["last_seen"]   = today

    for uid in comparison["재발"]:
        if uid in existing:
            existing[uid]["status"]      = "재발"
            existing[uid]["last_run_id"] = new_run_id
            existing[uid]["last_seen"]   = today

    for uid in comparison["new"]:
        if uid in existing:
            existing[uid]["status"]      = "open"
            existing[uid]["last_run_id"] = new_run_id
            existing[uid]["last_seen"]   = today
        else:
            f = new_findings.get(uid, {})
            existing[uid] = {
                "uid":            uid,
                "finding_id":     f.get("finding_id", ""),
                "skill":          f.get("_skill", ""),
                "category":       f.get("category", ""),
                "title":          f.get("title", ""),
                "severity":       f.get("severity", ""),
                "affected_target": (
                    f.get("scope", {}).get("package")
                    or f.get("scope", {}).get("affected_file")
                    or f.get("scope", {}).get("endpoint")
                    or ""
                ),
                "first_detected": today,
                "first_run_id":   new_run_id,
                "last_seen":      today,
                "last_run_id":    new_run_id,
                "status":         "open",
                "history":        [],
            }

    registry["findings"] = list(existing.values())
    save_vuln_registry(repo, registry)


def main() -> None:
    parser = argparse.ArgumentParser(prog="ihaeng_compare.py")
    parser.add_argument("--repo",         required=True)
    parser.add_argument("--base-run-id",  required=True, help="기준 회차 RUN_ID (이전)")
    parser.add_argument("--new-run-id",   required=True, help="비교 회차 RUN_ID (이번)")
    parser.add_argument("--update-registry", action="store_true",
                        help="비교 결과를 vuln_registry.json에 반영")
    parser.add_argument("--operator",     default="auditor")
    parser.add_argument("--output",       help="결과 파일 경로 (미지정 시 stdout)")
    args = parser.parse_args()

    repo        = args.repo
    base_run_id = args.base_run_id
    new_run_id  = args.new_run_id

    print(f"[이행진단] {repo}: {base_run_id} → {new_run_id} 비교 시작...")

    base_findings = _collect_findings(repo, base_run_id)
    new_findings  = _collect_findings(repo, new_run_id)

    if not base_findings:
        print(f"[경고] 기준 회차({base_run_id}) findings가 없습니다. 경로를 확인하세요.")
    if not new_findings:
        print(f"[경고] 비교 회차({new_run_id}) findings가 없습니다. 경로를 확인하세요.")

    comparison = _compare(base_findings, new_findings)

    print(
        f"[이행진단 결과] "
        f"조치완료={len(comparison['fixed'])} | "
        f"미조치={len(comparison['persistent'])} | "
        f"신규={len(comparison['new'])} | "
        f"재발={len(comparison['재발'])}"
    )

    report = _format_report(repo, base_run_id, new_run_id, comparison, base_findings, new_findings)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"[이행진단] 결과 저장 → {args.output}")
    else:
        print("\n" + report)

    # Audit log
    log_ihaeng(
        repo=repo,
        base_run_id=base_run_id,
        new_run_id=new_run_id,
        fixed=len(comparison["fixed"]),
        persistent=len(comparison["persistent"]),
        new=len(comparison["new"]),
        재발=len(comparison["재발"]),
        operator=args.operator,
    )
    print(f"[audit] 이행진단 이벤트 기록 완료")

    if args.update_registry:
        _update_registry_statuses(repo, comparison, new_findings, base_run_id, new_run_id)
        print(f"[이행진단] vuln_registry.json 상태 갱신 완료")


if __name__ == "__main__":
    main()
