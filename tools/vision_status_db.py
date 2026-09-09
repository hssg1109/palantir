#!/usr/bin/env python3
"""
vision_status_db.py — Vision(vision.skplanet.com) 레포 사용여부 조회 결과의 로컬 JSON 캐시.

배경:
  Vision API(palantir-jira-gateway/lambda/vision_api.py::lookup)는 내부망 라이브 조회라
  호출마다 네트워크 왕복이 발생한다. 보고서 담당자 조회(generate_final_report.py)와
  judgment_lookup.py의 "종료/폐기 레포 제외" 필터가 같은 데이터(레포별 use_yn/담당자)를
  반복 조회하므로, 결과를 state/vision_repo_status.json에 캐시해 두 기능이 공유한다.

캐시 정책:
  - 키: "{project}/{repo}"
  - refresh_if_missing=False(기본): 캐시만 읽는다. 네트워크 호출 없음 — judgment_lookup.py의
    판정 hot path에서 이 모드로만 호출해 지연/실패 리스크를 만들지 않는다.
  - refresh_if_missing=True: 캐시 miss일 때만 라이브 API를 호출해 upsert — 보고서 생성,
    수동 배치 갱신(--refresh-all)에서만 사용.
  - Vision 사용여부/담당자 자체의 최신화는 여전히 사람이 필요 시 --refresh-all을 수동
    실행해야 한다 (자동 스케줄 없음 — 기존 Vision 담당자 갱신 정책과 동일 원칙).

CLI:
  python3 tools/vision_status_db.py --seed-csv            # docs/vision_repo_status.csv → DB 이관
  python3 tools/vision_status_db.py --refresh-all         # state/*/repo_meta.json 전체 라이브 갱신
  python3 tools/vision_status_db.py --query PROJECT/repo  # 단건 조회 (캐시 우선, miss 시 라이브)
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PALANTIR_DIR = Path(__file__).resolve().parent.parent
STATE_DIR    = PALANTIR_DIR / "state"
DOCS_DIR     = PALANTIR_DIR / "docs"
GATEWAY_DIR  = PALANTIR_DIR.parent / "palantir-jira-gateway"

DB_PATH  = STATE_DIR / "vision_repo_status.json"
CSV_PATH = DOCS_DIR / "vision_repo_status.csv"


def _key(project: str, repo: str) -> str:
    return f"{project}/{repo}"


def load_db() -> dict:
    if DB_PATH.exists():
        try:
            return json.loads(DB_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_db(db: dict) -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    DB_PATH.write_text(
        json.dumps(db, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )


def _live_lookup(project: str, repo: str) -> dict | None:
    """gateway의 vision_api.lookup()을 그대로 재사용 (실패 시 None)."""
    try:
        sys.path.insert(0, str(GATEWAY_DIR / "lambda"))
        from vision_api import lookup
        return lookup(project, repo)
    except Exception:
        return None


def _extract_assignee_id(assignee: str) -> str:
    """gateway vision_api.py::_extract_id()와 동일한 규칙(중복 정의 — CSV seed 시점엔
    라이브 API를 타지 않아 gateway의 추출 로직을 그대로 거치지 않으므로, 캐시가
    라이브 조회와 다른 결과를 내지 않도록 동일 정규식을 여기서도 적용한다)."""
    import re
    m = re.match(r"^(\d+)\s+", assignee.strip())
    if m:
        return m.group(1)
    m = re.search(r"/(\d+)\s*$", assignee.strip())
    if m:
        return m.group(1)
    return ""


def get(
    project: str,
    repo: str,
    refresh_if_missing: bool = False,
    db: dict | None = None,
) -> dict | None:
    """Vision 레포 상태 조회 (cache-aside).

    db를 전달하면 그 dict를 그대로 갱신한다 (배치로 여러 건 조회 후 한 번에 save_db 하고
    싶을 때 — --refresh-all 용). 생략하면 매 호출마다 파일을 읽고, miss 시에만 다시 쓴다.
    """
    owns_db = db is None
    if owns_db:
        db = load_db()
    if not project or not repo:
        return None

    k = _key(project, repo)
    cached = db.get(k)
    if cached is not None:
        return cached
    if not refresh_if_missing:
        return None

    item = _live_lookup(project, repo)
    if item is None:
        return None
    item = dict(item)
    item["checked_at"] = datetime.now(timezone.utc).isoformat()
    db[k] = item
    if owns_db:
        save_db(db)
    return item


def is_decommissioned(project: str, repo: str, db: dict | None = None) -> bool:
    """use_yn == 0 이면 종료/미사용으로 간주.

    캐시에 레코드가 없으면 False — "Vision 미등록 = 대부분 정상 사용중"이라는 기존
    _vision_lookup() fallback 철학과 동일하게, 근거 없이 과잉 제외하지 않는다.
    """
    item = get(project, repo, refresh_if_missing=False, db=db)
    if not item:
        return False
    try:
        return int(item.get("use_yn")) == 0
    except (TypeError, ValueError):
        return False


def seed_from_csv(csv_path: Path = CSV_PATH) -> int:
    """docs/vision_repo_status.csv 스냅샷을 DB로 1회성 이관."""
    db = load_db()
    n = 0
    with csv_path.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            project = (row.get("project") or "").strip()
            repo = (row.get("repository") or "").strip()
            if not project or not repo:
                continue
            assignee = row.get("assignee", "") or ""
            assignee_id = (row.get("assignee_id") or "").strip() or _extract_assignee_id(assignee)
            db[_key(project, repo)] = {
                "use_yn":      row.get("use_yn", ""),
                "assignee_id": assignee_id,
                "assignee":    assignee,
                "reason_text": row.get("reason_text", ""),
                "reason_dt":   row.get("reason_dt", ""),
                "checked_at":  datetime.now(timezone.utc).isoformat(),
                "source":      "csv_seed",
            }
            n += 1
    save_db(db)
    return n


def refresh_all(sleep_sec: float = 0.3) -> tuple[int, int]:
    """state/*/repo_meta.json 전체를 순회하며 라이브 API로 갱신. (성공 건수, 전체 건수) 반환."""
    db = load_db()
    ok = 0
    total = 0
    for meta_path in STATE_DIR.glob("*/repo_meta.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        project = meta.get("project")
        repo = meta.get("repo")
        if not project or not repo:
            continue
        total += 1
        item = get(project, repo, refresh_if_missing=True, db=db)
        if item is not None:
            ok += 1
        time.sleep(sleep_sec)
    save_db(db)
    return ok, total


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-csv", action="store_true", help=f"{CSV_PATH} → DB 1회성 이관")
    ap.add_argument("--refresh-all", action="store_true", help="state/*/repo_meta.json 전체를 라이브 API로 갱신")
    ap.add_argument("--query", metavar="PROJECT/repo", help="단건 조회 (캐시 우선, miss 시 라이브 조회)")
    args = ap.parse_args()

    if args.seed_csv:
        n = seed_from_csv()
        print(f"[SEED] {CSV_PATH} → {DB_PATH} : {n} rows")
        return

    if args.refresh_all:
        ok, total = refresh_all()
        print(f"[REFRESH] {ok}/{total} repos 갱신 완료 → {DB_PATH}")
        return

    if args.query:
        project, _, repo = args.query.partition("/")
        item = get(project, repo, refresh_if_missing=True)
        print(json.dumps(item, ensure_ascii=False, indent=2))
        return

    ap.print_help()


if __name__ == "__main__":
    main()
