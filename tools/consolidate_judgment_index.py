#!/usr/bin/env python3
"""
consolidate_judgment_index.py — judgment_lookup.py 매칭 인덱스 분기별 압축 배치.

배경 (Confluence pageId=775427230 정보보호담당 이형관 매니저 제안, 2026-09-07):
  reviewed finding이 무한정 누적되면 유사 판정 사례가 Jaccard 매칭 노이즈로 쌓여
  조건이 반전된 케이스(예: DATA-001류 — 같은 카테고리인데 운영 로그 여부에 따라
  판정이 갈리는 사례)를 잘못 채택할 위험이 커진다. 이 스크립트는 (category, direction)
  단위로 클러스터링해 "대표건 + 발생건수"로 압축한 state/precedent_index.json을
  생성한다. state/audit_log.json과 state/*/*/*/findings_*.json 원본은 절대 수정하지
  않는다 — 감사원본(불변)과 검색인덱스(압축본)의 역할을 분리하는 것이 이번 배치의 목적.

실행 주체: 사람이 분기 1회 수동 실행 (스킬 자동 체인에 포함하지 않음 — 다른
  tools/backfill_*.py류와 동일한 독립 유지보수 도구).

direction 산출 (review_note 의미분석 없이 기존 필드만으로 결정론적 계산):
  - review_result != "취약" (오탐/양호 등) → "오탐"
  - state/audit_log.json의 finding_reviewed 이벤트에서 severity_before/after를
    찾을 수 있고 서로 다르면 등급 순위 비교로 "상향"/"하향"
  - 그 외(등급 동일, 또는 audit_log에서 못 찾음) → "유지"

대표건 선정 (2026-09-08 실측 후 수정 — MAX_REPS_PER_CLUSTER 참고):
  최초 설계는 클러스터당 최신 run_id 1건만 남기는 방식이었으나, 60건 leave-one-out
  벤치마크에서 high-confidence 매칭률이 35%→2%로 붕괴함을 확인(레포마다 다른
  코드스니펫/변수명/로그 프레임워크 표현이 사라져 Jaccard 신호 소멸). 이를 반영해
  "레포당 1건(그 레포 내 최신 run_id) 우선 선정 → distinct repo 수가
  MAX_REPS_PER_CLUSTER를 넘으면 run_id 최신순 캡"으로 변경 — 같은 레포 내 근접중복만
  압축하고 레포간 텍스트 다양성은 보존한다.

CLI:
  python3 tools/consolidate_judgment_index.py --dry-run   # 클러스터 요약만 출력, 파일 미생성
  python3 tools/consolidate_judgment_index.py             # state/precedent_index.json 생성
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import judgment_lookup  # noqa: E402

PALANTIR_DIR = Path(__file__).resolve().parent.parent
STATE_DIR = PALANTIR_DIR / "state"
AUDIT_LOG = STATE_DIR / "audit_log.json"
PRECEDENT_INDEX = STATE_DIR / "precedent_index.json"

_SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# 클러스터당 최대 대표건 수 (레포당 1건 선정 후 이 수를 넘으면 run_id 최신순 캡).
# 60건 leave-one-out 벤치마크로 절충점 선정: cap=5 → high 21→6, informed(=high+low)
# 41→20/60. cap=20 → high 21→10, informed 41→35/60(58%, raw 대비 -10pt)이면서
# raw index 대비 여전히 54.4% 압축(804→367). low-confidence 매칭도 /sec-review
# §4 전제조건 검증을 거치므로 high→low 이동 자체는 치명적이지 않음
# (feedback_auto_judgment_confidence_precondition.md).
MAX_REPS_PER_CLUSTER = 20


def _severity_rank(sev: str) -> int | None:
    if not sev:
        return None
    return _SEVERITY_RANK.get(sev.strip().lower())


def _load_audit_severity_map() -> dict[tuple[str, str, str], tuple[str | None, str | None]]:
    """(repo, run_id, finding_id) -> (severity_before, severity_after) 맵.

    audit_log.json은 원본 그대로 읽기만 한다 — 수정하지 않음.
    """
    m: dict[tuple[str, str, str], tuple[str | None, str | None]] = {}
    if not AUDIT_LOG.exists():
        return m
    try:
        entries = json.loads(AUDIT_LOG.read_text(encoding="utf-8"))
    except Exception:
        return m
    for e in entries:
        if not isinstance(e, dict) or e.get("event_type") != "finding_reviewed":
            continue
        key = (e.get("repo", ""), e.get("run_id", ""), e.get("finding_id", ""))
        ra = e.get("review_action") or {}
        m[key] = (ra.get("severity_before"), ra.get("severity_after"))
    return m


def _direction(entry: dict, severity_map: dict) -> str:
    if entry.get("review_result", "") != "취약":
        return "오탐"

    key = (entry.get("repo", ""), entry.get("run_id", ""), entry.get("finding_id", ""))
    before, after = severity_map.get(key, (None, None))
    rb, ra = _severity_rank(before), _severity_rank(after)
    if rb is not None and ra is not None and rb != ra:
        return "상향" if ra > rb else "하향"
    return "유지"


def build_clusters() -> tuple[list[dict], int]:
    """(clusters, raw_count) 반환. clusters는 대표건+발생건수+precedent_ids 목록."""
    severity_map = _load_audit_severity_map()
    # judgment_lookup.build_index()가 아닌 _scan_raw_index()를 직접 호출한다 —
    # build_index()는 기존 state/precedent_index.json이 있으면 그걸 베이스로 쓰므로,
    # 재실행(분기 배치) 시 이전 압축 결과 위에 또 압축하는 식으로 원본 다양성이
    # 누적 손실되는 것을 방지한다. 이 배치는 항상 진짜 raw 전수(SCA/decommissioned
    # 필터만 적용된)에서 새로 클러스터링해야 한다.
    raw_index = judgment_lookup._scan_raw_index(None, None, skip_ids=set(), after_run_id=None)

    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for entry in raw_index:
        direction = _direction(entry, severity_map)
        groups[(entry["category"], direction)].append(entry)

    clusters = []
    for (category, direction), entries in groups.items():
        reps = _select_representatives(entries)
        clusters.append({
            "cluster_key": f"{category}::{direction}",
            "category": category,
            "direction": direction,
            "representatives": reps,
            "occurrence_count": len(entries),
            "precedent_ids": [e["precedent_id"] for e in entries],
        })

    clusters.sort(key=lambda c: c["occurrence_count"], reverse=True)
    return clusters, len(raw_index)


def _select_representatives(entries: list[dict], max_reps: int = MAX_REPS_PER_CLUSTER) -> list[dict]:
    """클러스터 내에서 대표건을 최대 max_reps건 선정한다.

    단일 대표건(최신 run_id 1건)으로만 압축하면 같은 (category, direction)이라도
    레포/파일마다 다른 코드스니펫·변수명·로그 프레임워크 표현이 사라져 Jaccard
    매칭 신호가 거의 소멸함을 실측으로 확인(leave-one-out high 매칭 35%→2%,
    2026-09-08). 이를 막기 위해 "레포당 1건(그 레포 내 최신 run_id)"으로 먼저
    골라 같은 레포 내 근접중복만 압축하고, 서로 다른 레포 간 텍스트 다양성은
    보존한다. 그래도 distinct repo 수가 max_reps를 넘으면 run_id가 최신인 순으로
    상위 max_reps개만 남긴다(회귀 방지를 위한 캡 — 무한정 누적은 여전히 막는다).
    """
    by_repo: dict[str, dict] = {}
    for e in entries:
        repo = e.get("repo", "")
        cur = by_repo.get(repo)
        if cur is None or e.get("run_id", "") > cur.get("run_id", ""):
            by_repo[repo] = e

    per_repo_reps = sorted(by_repo.values(), key=lambda e: e.get("run_id", ""), reverse=True)
    selected = per_repo_reps[:max_reps]

    reps_out = []
    for e in selected:
        rep_out = dict(e)
        rep_out["tokens"] = sorted(rep_out.get("tokens", set()))
        rep_out.pop("precedent_count", None)
        reps_out.append(rep_out)
    return reps_out


def _cutoff_run_id(clusters: list[dict]) -> str:
    """압축에 반영된 finding들 중 가장 최신 run_id.

    judgment_lookup.py가 이 이후 run_id만 raw로 재스캔해 압축본에 합치므로,
    반영된 것과 정확히 겹치지 않게(누락도, 중복도 없이) 하는 경계값이다.
    """
    latest = ""
    for c in clusters:
        for rep in c["representatives"]:
            rep_run_id = rep.get("run_id", "")
            if rep_run_id > latest:
                latest = rep_run_id
    return latest


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="파일 생성 없이 클러스터 요약만 출력")
    args = ap.parse_args()

    clusters, raw_count = build_clusters()
    rep_count = sum(len(c["representatives"]) for c in clusters)
    reduction = raw_count - rep_count

    print(f"[SUMMARY] raw_index={raw_count}건 → clusters={len(clusters)}개 "
          f"(대표건 합계={rep_count}건, 압축 {reduction}건, {reduction / raw_count * 100:.1f}%)"
          if raw_count else "[SUMMARY] raw_index=0건")
    by_direction = defaultdict(int)
    for c in clusters:
        by_direction[c["direction"]] += c["occurrence_count"]
    for direction, cnt in sorted(by_direction.items(), key=lambda x: -x[1]):
        print(f"  - {direction}: {cnt}건")

    if args.dry_run:
        print("[DRY-RUN] state/precedent_index.json 미생성 (--dry-run)")
        return

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cutoff_run_id": _cutoff_run_id(clusters),
        "raw_count": raw_count,
        "clusters": clusters,
    }
    PRECEDENT_INDEX.parent.mkdir(parents=True, exist_ok=True)
    PRECEDENT_INDEX.write_text(
        json.dumps(output, ensure_ascii=False, indent=2, sort_keys=False), encoding="utf-8"
    )
    print(f"[WRITE] {PRECEDENT_INDEX} ({len(clusters)} clusters, {rep_count} representatives, "
          f"cutoff_run_id={output['cutoff_run_id']})")


if __name__ == "__main__":
    main()
