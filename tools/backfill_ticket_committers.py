#!/usr/bin/env python3
"""pending 티켓 assignee(vision_assignee_id) + watchers_suggested BB 커밋 기반 소급 갱신.

로직:
  (1) Vision 담당자 있음 + 1년 미만  → 변경 없음 (watchers_suggested=[])
  (2) Vision 담당자 있음 + 1년 이상  → BB top-2 커밋자를 watchers_suggested로
  (3) Vision 담당자 없음              → BB top-1 → vision_assignee_id,
                                         BB top-2~3 → watchers_suggested

실행:
  python3 tools/backfill_ticket_committers.py [--dry-run]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

PALANTIR_DIR = Path(__file__).resolve().parent.parent
GATEWAY_DIR  = PALANTIR_DIR.parent / "palantir-jira-gateway"
TICKETS_DIR  = GATEWAY_DIR / "data" / "tickets"
STATE_DIR    = PALANTIR_DIR / "state"

# Jira 자격증명은 gateway .env에 있음 (palantir에는 없음)
try:
    from dotenv import load_dotenv
    load_dotenv(GATEWAY_DIR / ".env")
except ImportError:
    pass

# approve_report.py를 모듈로 로드 (argparse 충돌 방지)
def _load_approve_report():
    spec = importlib.util.spec_from_file_location(
        "approve_report", PALANTIR_DIR / "tools" / "approve_report.py"
    )
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pass
    return mod

_ar = _load_approve_report()
_top_committers = _ar._top_committers

# gateway lambda 모듈 (Vision API, Jira resolve)
sys.path.insert(0, str(GATEWAY_DIR / "lambda"))
from vision_api import lookup as vision_lookup
from jira_client import resolve_jira_user


def _resolve_committers(email_prefixes: list[str], project: str, exclude_account: str) -> list[str]:
    """email prefix 목록을 Jira 사번으로 resolve하고 중복·미해석·assignee 동일인 제거.

    - 빈 resolve → 제외 (퇴사자 또는 외부 계정)
    - 해석 결과가 exclude_account(assignee 사번)와 동일 → 제외
    - 중복 사번 → 한 번만 포함
    Returns: 유효한 Jira account 목록 (최대 top_n - 이미 slicing은 호출자가)
    """
    seen: set = set()
    result: list = []
    for prefix in email_prefixes:
        account = resolve_jira_user(prefix, project=project)
        if not account:
            continue  # 미해석
        if account == exclude_account:
            continue  # assignee와 동일인
        if account in seen:
            continue  # 중복
        seen.add(account)
        result.append(account)
    return result


def _is_stale(date_str: str, months: int = 12) -> bool:
    if not date_str:
        return False
    try:
        if "T" in date_str:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        else:
            dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc) - timedelta(days=months * 30)
    except Exception:
        return False


def _bb_project(repo: str) -> str:
    meta = STATE_DIR / repo / "repo_meta.json"
    try:
        return json.loads(meta.read_text(encoding="utf-8")).get("project", "") if meta.exists() else ""
    except Exception:
        return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--repo", help="특정 레포만 처리")
    args = parser.parse_args()

    files   = sorted(TICKETS_DIR.glob("*.json"))
    pending = [f for f in files
               if json.loads(f.read_text(encoding="utf-8"))["status"] == "pending"]

    if args.repo:
        pending = [f for f in pending
                   if json.loads(f.read_text(encoding="utf-8")).get("repo") == args.repo]

    print(f"대상 {len(pending)}건\n")

    results = {"updated": 0, "no_change": 0, "no_bb": 0}

    for fp in pending:
        d    = json.loads(fp.read_text(encoding="utf-8"))
        repo = d.get("repo", "")
        prj  = _bb_project(repo)

        if not prj:
            print(f"  [SKIP] {repo} — repo_meta.json 없음")
            results["no_bb"] += 1
            continue

        old_aid = (d.get("vision_assignee_id") or "").strip()
        old_ws  = d.get("watchers_suggested", [])

        # BB top-5 조회 (resolve 후 중복 제거되면 2명 이하로 줄 수 있어 여유 확보)
        top5 = _top_committers(prj, repo, months=6, top_n=5)
        if not top5:
            print(f"  [SKIP] {repo} — BB 커밋자 조회 실패 또는 없음")
            results["no_bb"] += 1
            continue

        # Vision 재조회 (staleness용 reason_dt/created 필요)
        v_record = vision_lookup(prj, repo) if old_aid else None
        stale = False
        new_aid = old_aid
        new_ws: list[str] = []

        if old_aid and v_record is not None:
            # (1) or (2) — Vision에 등록된 레포
            date_str = (v_record.get("reason_dt") or v_record.get("created") or "")
            stale = _is_stale(date_str)
            if stale:
                # (2) Vision 담당자 유지, BB 커밋자 2명 watcher (resolve + 동일인 제거)
                new_ws = _resolve_committers(top5, prj, exclude_account=old_aid)[:2]
                tag = "(2) stale"
            else:
                # (1) 변경 없음
                tag = "(1) fresh"
        else:
            # (3) Vision 미등록 — BB top 커밋자로 assignee/watcher 결정
            # top-1 resolve → assignee
            new_aid_raw = top5[0]
            new_aid = resolve_jira_user(new_aid_raw, project=prj) or old_aid or new_aid_raw
            # top-2~5 중 assignee와 다른 사람 2명 watcher (resolve 실패·동일인 제외)
            new_ws = _resolve_committers(top5[1:], prj, exclude_account=new_aid)[:2]
            tag = "(3) no-vision"

        changed = (new_aid != old_aid) or (new_ws != old_ws)

        print(
            f"  [{tag}] {repo} ({prj})"
            f" | assignee: {old_aid!r} → {new_aid!r}"
            f" | watchers: {old_ws} → {new_ws}"
            + (" [NO CHANGE]" if not changed else "")
        )

        if not changed:
            results["no_change"] += 1
            continue

        if not args.dry_run:
            d["vision_assignee_id"] = new_aid
            d["watchers_suggested"] = new_ws
            fp.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
        results["updated"] += 1
        time.sleep(0.3)

    print(f"\n완료: 갱신 {results['updated']}건 / 변경없음 {results['no_change']}건 / BB미확인 {results['no_bb']}건")
    if args.dry_run:
        print("(dry-run — 실제 파일 저장 없음)")


if __name__ == "__main__":
    main()
