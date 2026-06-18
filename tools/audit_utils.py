#!/usr/bin/env python3
"""
audit_utils.py — 진단 이력 누적 · Audit Log 관리 유틸리티

사용법 (CLI):
  python3 tools/audit_utils.py init-session --repo <repo> --run-id <run_id> [--operator <name>]
  python3 tools/audit_utils.py log-review   --session-id <sid> --repo <repo> --run-id <run_id>
                                             --skill <skill> --finding-id <fid> --finding-title <title>
                                             --scan-severity <sev> --scan-result <result>
                                             --decision <정탐|오탐|스킵>
                                             [--review-result <취약|정보>]
                                             [--severity-before <sev>] [--severity-after <sev>]
                                             [--review-note <note>]
                                             [--auditor-questions <json_list>]
                                             [--code-analysis <summary>]
  python3 tools/audit_utils.py end-session  --session-id <sid> --정탐 N --오탐 N --스킵 N
  python3 tools/audit_utils.py log-report   --repo <repo> --run-id <run_id>
                                             --report-path <path> [--confluence-url <url>]
                                             [--operator <name>]
  python3 tools/audit_utils.py log-ihaeng   --repo <repo> --base-run-id <base> --new-run-id <new>
                                             --fixed <n> --persistent <n> --new <n> --재발 <n>
                                             [--operator <name>]

라이브러리 import 사용:
  from tools.audit_utils import (
      append_audit_log, load_audit_log,
      uid_for_finding,
      load_vuln_registry, save_vuln_registry
  )
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PALANTIR_DIR = Path(__file__).resolve().parent.parent
STATE_DIR    = PALANTIR_DIR / "state"
AUDIT_LOG    = STATE_DIR / "audit_log.json"


# ──────────────────────────────────────────────
# Audit Log I/O
# ──────────────────────────────────────────────

def load_audit_log() -> list[dict]:
    if AUDIT_LOG.exists():
        try:
            return json.loads(AUDIT_LOG.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def append_audit_log(entry: dict) -> None:
    """entry를 state/audit_log.json에 원자적으로 추가한다."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    log = load_audit_log()
    log.append(entry)
    AUDIT_LOG.write_text(json.dumps(log, ensure_ascii=False, indent=2), encoding="utf-8")


def _entry_id(prefix: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{now}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ──────────────────────────────────────────────
# Session helpers
# ──────────────────────────────────────────────

def _session_id(repo: str) -> str:
    return f"SESSION-{repo}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"


def init_session(repo: str, run_id: str | None, operator: str = "auditor") -> str:
    sid = _session_id(repo)
    entry = {
        "entry_id":    _entry_id("LOG"),
        "timestamp":   _now_iso(),
        "event_type":  "review_session_start",
        "session_id":  sid,
        "repo":        repo,
        "run_id":      run_id,
        "operator":    operator,
    }
    append_audit_log(entry)
    return sid


def end_session(
    session_id: str,
    정탐: int = 0,
    오탐: int = 0,
    스킵: int = 0,
) -> None:
    entry = {
        "entry_id":    _entry_id("LOG"),
        "timestamp":   _now_iso(),
        "event_type":  "review_session_end",
        "session_id":  session_id,
        "summary": {
            "정탐": 정탐,
            "오탐": 오탐,
            "스킵": 스킵,
            "total": 정탐 + 오탐 + 스킵,
        },
    }
    append_audit_log(entry)


# ──────────────────────────────────────────────
# Finding review logging
# ──────────────────────────────────────────────

def log_finding_review(
    *,
    session_id:          str,
    repo:                str,
    run_id:              str | None,
    skill:               str,
    finding_id:          str,
    finding_title:       str,
    scan_severity:       str,
    scan_result:         str,
    decision:            str,            # "정탐" | "오탐" | "스킵"
    review_result:       str | None = None,
    severity_before:     str | None = None,
    severity_after:      str | None = None,
    review_note:         str = "",
    auditor_questions:   list[str] | None = None,
    code_analysis:       str = "",
) -> None:
    severity_changed = (
        severity_before is not None
        and severity_after is not None
        and severity_before != severity_after
    )
    entry: dict[str, Any] = {
        "entry_id":      _entry_id("LOG"),
        "timestamp":     _now_iso(),
        "event_type":    "finding_reviewed",
        "session_id":    session_id,
        "repo":          repo,
        "run_id":        run_id,
        "skill":         skill,
        "finding_id":    finding_id,
        "finding_title": finding_title,
        "scan_result": {
            "severity": scan_severity,
            "result":   scan_result,
        },
        "review_action": {
            "decision":          decision,
            "review_result":     review_result,
            "severity_before":   severity_before,
            "severity_after":    severity_after,
            "severity_changed":  severity_changed,
        },
        "auditor": {
            "questions_asked":         auditor_questions or [],
            "code_analysis_performed": bool(code_analysis),
            "code_analysis_summary":   code_analysis,
            "review_note":             review_note,
        },
    }
    append_audit_log(entry)


# ──────────────────────────────────────────────
# Report event logging
# ──────────────────────────────────────────────

def log_report_published(
    *,
    repo:           str,
    run_id:         str | None,
    report_path:    str,
    confluence_url: str = "",
    operator:       str = "auditor",
    findings_count: dict | None = None,
) -> None:
    entry = {
        "entry_id":       _entry_id("LOG"),
        "timestamp":      _now_iso(),
        "event_type":     "report_published",
        "repo":           repo,
        "run_id":         run_id,
        "operator":       operator,
        "report_path":    report_path,
        "confluence_url": confluence_url,
        "findings_count": findings_count or {},
    }
    append_audit_log(entry)


def log_ihaeng(
    *,
    repo:        str,
    base_run_id: str,
    new_run_id:  str,
    fixed:       int,
    persistent:  int,
    new:         int,
    재발:         int,
    operator:    str = "auditor",
) -> None:
    entry = {
        "entry_id":    _entry_id("LOG"),
        "timestamp":   _now_iso(),
        "event_type":  "ihaeng_scan",
        "repo":        repo,
        "base_run_id": base_run_id,
        "new_run_id":  new_run_id,
        "operator":    operator,
        "comparison": {
            "fixed":      fixed,
            "persistent": persistent,
            "new":        new,
            "재발":        재발,
        },
    }
    append_audit_log(entry)


# ──────────────────────────────────────────────
# Vuln Registry helpers
# ──────────────────────────────────────────────

def _registry_path(repo: str) -> Path:
    return STATE_DIR / repo / "vuln_registry.json"


def load_vuln_registry(repo: str) -> dict:
    p = _registry_path(repo)
    if p.exists():
        try:
            reg = json.loads(p.read_text(encoding="utf-8"))
            # v1.0 → v2.0 온라인 마이그레이션
            if reg.get("schema_version", "1.0") == "1.0":
                reg["schema_version"] = "2.0"
                reg.setdefault("service_meta", {})
                reg.setdefault("runs", [])
            return reg
        except Exception:
            pass
    return {
        "schema_version": "2.0",
        "repo": repo,
        "last_updated": _now_iso(),
        "service_meta": {},
        "runs": [],
        "findings": [],
    }


def save_vuln_registry(repo: str, registry: dict) -> None:
    p = _registry_path(repo)
    p.parent.mkdir(parents=True, exist_ok=True)
    registry["last_updated"] = _now_iso()
    p.write_text(json.dumps(registry, ensure_ascii=False, indent=2), encoding="utf-8")


def update_service_meta(repo: str) -> None:
    """scan_meta.json + review_meta.json → vuln_registry.service_meta 동기화."""
    import glob as _glob

    registry = load_vuln_registry(repo)
    meta: dict[str, Any] = registry.setdefault("service_meta", {})

    # scan_meta.json — 가장 최신 파일 우선
    scan_meta_paths = sorted(
        _glob.glob(str(STATE_DIR / repo / "*" / "scan_meta.json")),
        reverse=True,
    )
    for p in scan_meta_paths:
        try:
            sm = json.loads(Path(p).read_text(encoding="utf-8"))
            if sm.get("bb_commit") or sm.get("bb_branch"):
                meta["bb_project"]  = sm.get("bb_project", meta.get("bb_project", ""))
                meta["clone_url"]   = sm.get("repo_url",   meta.get("clone_url", ""))
                meta["branch"]      = sm.get("bb_branch",  meta.get("branch", ""))
                break
        except Exception:
            continue

    # review_meta.json
    review_meta_path = STATE_DIR / repo / "review_meta.json"
    if review_meta_path.exists():
        try:
            rm = json.loads(review_meta_path.read_text(encoding="utf-8"))
            meta["service_characteristics"]  = rm.get("service_characteristics", meta.get("service_characteristics", ""))
            meta["additional_diagnosis_needed"] = rm.get("additional_diagnosis_needed", meta.get("additional_diagnosis_needed", False))
            meta["meta_updated_at"]          = rm.get("updated_at", _now_iso())
        except Exception:
            pass

    registry["service_meta"] = meta
    save_vuln_registry(repo, registry)


def add_run_entry(
    repo: str,
    run_id: str | None,
    *,
    finding_counts: dict | None = None,
    report_path: str = "",
    confluence_url: str = "",
    jira_key: str = "",
) -> None:
    """approve_report.py 완료 시 vuln_registry.runs[] 에 진단 실행 이력 추가."""
    registry = load_vuln_registry(repo)
    runs: list[dict] = registry.setdefault("runs", [])

    entry: dict[str, Any] = {
        "run_id":         run_id or "repo-mode",
        "completed_at":   _now_iso(),
        "finding_counts": finding_counts or {},
        "report_path":    report_path,
        "confluence_url": confluence_url,
        "jira_key":       jira_key,
    }

    # 동일 run_id 기존 항목 업데이트, 없으면 append
    for i, r in enumerate(runs):
        if r.get("run_id") == entry["run_id"]:
            runs[i] = entry
            break
    else:
        runs.append(entry)

    registry["runs"] = runs
    save_vuln_registry(repo, registry)


def uid_for_finding(repo: str, skill: str, finding: dict) -> str:
    """
    재진단(이행진단)에서 동일 취약점을 매칭하기 위한 안정적 UID 생성.

    SCA  : {repo}:SCA:{package_name}
    INJ  : {repo}:INJ:{affected_file}:{category}
    XSS  : {repo}:XSS:{endpoint}:{xss_type}
    FILE : {repo}:FILE:{category}:{endpoint}
    DATA : {repo}:DATA:{category}:{affected_file_stem}
    """
    skill_upper = skill.upper()

    if skill_upper == "SCA":
        pkg = (
            finding.get("scope", {}).get("package")
            or finding.get("affected_package", "")
            or finding.get("artifact", "")
        )
        # Strip version from artifact string (e.g. "tomcat-embed-core:10.1.36" → "tomcat-embed-core")
        pkg_name = pkg.split(":")[0].strip() if pkg else "unknown"
        return f"{repo}:SCA:{pkg_name}"

    scope      = finding.get("scope", {})
    category   = finding.get("category", skill_upper)
    af         = scope.get("affected_file") or scope.get("file") or finding.get("file") or ""
    af_stem    = Path(af).stem if af else "unknown"
    endpoint   = scope.get("endpoint") or scope.get("affected_endpoint") or ""
    ep_slug    = endpoint.replace("/", "_").strip("_")[:40] if endpoint else "unknown"

    if skill_upper == "INJECTION":
        return f"{repo}:INJ:{af_stem}:{category}"
    if skill_upper == "XSS":
        xss_type = category.split("/")[-1] if "/" in category else category
        return f"{repo}:XSS:{ep_slug}:{xss_type}"
    if skill_upper == "FILE":
        return f"{repo}:FILE:{category}:{ep_slug}"
    # DATA / fallback
    return f"{repo}:DATA:{category}:{af_stem}"


def update_registry_from_findings(
    repo: str,
    run_id: str | None,
    scan_date: str | None = None,
    report_url: str = "",
) -> dict:
    """
    state/<repo>의 findings_*.json을 읽어 vuln_registry.json을 갱신한다.
    반환: {"added": N, "updated": N, "unchanged": N}
    """
    if run_id:
        paths = sorted(STATE_DIR.glob(f"{repo}/*/{run_id}/findings_*.json"))
    else:
        paths = []
        repo_dir = STATE_DIR / repo
        if repo_dir.is_dir():
            for skill_dir in sorted(repo_dir.iterdir()):
                if not skill_dir.is_dir():
                    continue
                run_dirs = sorted(
                    (d for d in skill_dir.iterdir() if d.is_dir()),
                    key=lambda d: d.name, reverse=True,
                )
                for rd in run_dirs:
                    files = sorted(rd.glob("findings_*.json"))
                    if files:
                        paths.append(files[0])
                        break

    registry  = load_vuln_registry(repo)
    existing  = {f["uid"]: f for f in registry["findings"]}
    stats     = {"added": 0, "updated": 0, "unchanged": 0}
    today     = scan_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for path in paths:
        # Determine skill from path (state/<repo>/<skill>/...)
        try:
            skill = path.parts[path.parts.index(repo) + 1]
        except (ValueError, IndexError):
            skill = "unknown"

        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        current_run_id = run_id or path.parent.name

        for finding in doc.get("findings", []):
            result = finding.get("result", "")
            review_status = finding.get("review_status", "")

            # Skip pure-FP (not interesting to track)
            if result in ("양호", "양호(FP)", "해당없음", "safe") and review_status == "오탐":
                continue
            if review_status == "그룹병합":
                continue

            uid = uid_for_finding(repo, skill, finding)

            history_entry = {
                "run_id":        current_run_id,
                "scan_date":     today,
                "result":        result,
                "severity":      finding.get("severity", ""),
                "review_status": review_status,
                "report_url":    report_url,
            }

            if uid in existing:
                rec = existing[uid]
                # Update status
                if result in ("취약", "정보") and review_status == "정탐":
                    prev_status = rec.get("status", "open")
                    if prev_status in ("fixed", "verified_fixed"):
                        rec["status"] = "재발"
                    else:
                        rec["status"] = "open"
                elif review_status == "오탐":
                    rec["status"] = "false_positive"
                rec["severity"]     = finding.get("severity", rec.get("severity", ""))
                rec["last_seen"]    = today
                rec["last_run_id"]  = current_run_id
                rec.setdefault("history", []).append(history_entry)
                stats["updated"] += 1
            else:
                new_rec: dict[str, Any] = {
                    "uid":            uid,
                    "finding_id":     finding.get("finding_id", ""),
                    "skill":          skill,
                    "category":       finding.get("category", ""),
                    "title":          finding.get("title", ""),
                    "severity":       finding.get("severity", ""),
                    "affected_target": (
                        finding.get("scope", {}).get("package")
                        or finding.get("scope", {}).get("affected_file")
                        or finding.get("scope", {}).get("endpoint")
                        or finding.get("affected_package", "")
                        or ""
                    ),
                    "first_detected": today,
                    "first_run_id":   current_run_id,
                    "last_seen":      today,
                    "last_run_id":    current_run_id,
                    "status":         "open" if result in ("취약", "정보") else "false_positive",
                    "history":        [history_entry],
                }
                existing[uid] = new_rec
                stats["added"] += 1

    registry["findings"] = list(existing.values())
    save_vuln_registry(repo, registry)
    return stats


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def _cli_init_session(args: argparse.Namespace) -> None:
    sid = init_session(args.repo, args.run_id, args.operator)
    print(sid)


def _cli_log_review(args: argparse.Namespace) -> None:
    questions = json.loads(args.auditor_questions) if args.auditor_questions else []
    log_finding_review(
        session_id=args.session_id,
        repo=args.repo,
        run_id=args.run_id,
        skill=args.skill,
        finding_id=args.finding_id,
        finding_title=args.finding_title,
        scan_severity=args.scan_severity,
        scan_result=args.scan_result,
        decision=args.decision,
        review_result=args.review_result,
        severity_before=args.severity_before,
        severity_after=args.severity_after,
        review_note=args.review_note or "",
        auditor_questions=questions,
        code_analysis=args.code_analysis or "",
    )
    print(f"[audit] logged: {args.finding_id} → {args.decision}")


def _cli_end_session(args: argparse.Namespace) -> None:
    end_session(args.session_id, args.정탐, args.오탐, args.스킵)
    print(f"[audit] session {args.session_id} 종료 기록 완료")


def _cli_log_report(args: argparse.Namespace) -> None:
    log_report_published(
        repo=args.repo,
        run_id=args.run_id,
        report_path=args.report_path,
        confluence_url=args.confluence_url or "",
        operator=args.operator,
    )
    print(f"[audit] report_published logged: {args.repo}")


def _cli_log_ihaeng(args: argparse.Namespace) -> None:
    log_ihaeng(
        repo=args.repo,
        base_run_id=args.base_run_id,
        new_run_id=args.new_run_id,
        fixed=args.fixed,
        persistent=args.persistent,
        new=args.new,
        재발=args.재발,
        operator=args.operator,
    )
    print(f"[audit] ihaeng logged: {args.repo}  fixed={args.fixed} persistent={args.persistent} new={args.new}")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit_utils.py")
    sub = p.add_subparsers(dest="command", required=True)

    # init-session
    s = sub.add_parser("init-session")
    s.add_argument("--repo",     required=True)
    s.add_argument("--run-id",   default=None)
    s.add_argument("--operator", default="auditor")
    s.set_defaults(func=_cli_init_session)

    # log-review
    s = sub.add_parser("log-review")
    s.add_argument("--session-id",        required=True)
    s.add_argument("--repo",              required=True)
    s.add_argument("--run-id",            default=None)
    s.add_argument("--skill",             required=True)
    s.add_argument("--finding-id",        required=True)
    s.add_argument("--finding-title",     default="")
    s.add_argument("--scan-severity",     default="")
    s.add_argument("--scan-result",       default="")
    s.add_argument("--decision",          required=True, choices=["정탐", "오탐", "스킵"])
    s.add_argument("--review-result",     default=None)
    s.add_argument("--severity-before",   default=None)
    s.add_argument("--severity-after",    default=None)
    s.add_argument("--review-note",       default="")
    s.add_argument("--auditor-questions", default=None, help="JSON array string")
    s.add_argument("--code-analysis",     default="")
    s.set_defaults(func=_cli_log_review)

    # end-session
    s = sub.add_parser("end-session")
    s.add_argument("--session-id", required=True)
    s.add_argument("--정탐", type=int, default=0)
    s.add_argument("--오탐", type=int, default=0)
    s.add_argument("--스킵", type=int, default=0)
    s.set_defaults(func=_cli_end_session)

    # log-report
    s = sub.add_parser("log-report")
    s.add_argument("--repo",           required=True)
    s.add_argument("--run-id",         default=None)
    s.add_argument("--report-path",    required=True)
    s.add_argument("--confluence-url", default="")
    s.add_argument("--operator",       default="auditor")
    s.set_defaults(func=_cli_log_report)

    # log-ihaeng
    s = sub.add_parser("log-ihaeng")
    s.add_argument("--repo",        required=True)
    s.add_argument("--base-run-id", required=True)
    s.add_argument("--new-run-id",  required=True)
    s.add_argument("--fixed",       type=int, default=0)
    s.add_argument("--persistent",  type=int, default=0)
    s.add_argument("--new",         type=int, default=0)
    s.add_argument("--재발",        type=int, default=0)
    s.add_argument("--operator",    default="auditor")
    s.set_defaults(func=_cli_log_ihaeng)

    return p


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
