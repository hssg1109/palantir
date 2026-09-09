#!/usr/bin/env python3
"""
judgment_lookup.py — 과거 판정 이력 기반 유사 finding 검색 (/sec-review 자동 판정 보조)

목적:
  /sec-review 는 이제 finding마다 사람에게 정탐/오탐·위험도를 묻지 않고, 과거에 축적된
  판정 이력(state/*/*/*/findings_*.json 의 reviewed:true 항목 + state/audit_log.json 의
  finding_reviewed 이벤트)에서 가장 유사한 사례를 찾아 그 판정을 참고 자동판정한다.
  이 스크립트는 그 "가장 유사한 과거 판정 찾기" 단계만 담당한다 — 최종 판정 로직(임계값에
  따라 채택/보수적 기본값 적용)은 /sec-review 스킬(.claude/commands/sec-review.md §4) 쪽에 있다.

인덱스 소스 (매 실행마다 재구축 — 레포 규모상 수 초 내):
  1순위: state/<repo>/<skill>/<run_id>/findings_*.json 의 reviewed:true finding
         (category/description/evidence.code_snippet 등 원본 필드가 풍부)
  2순위: state/audit_log.json 의 finding_reviewed 이벤트 (title/severity/decision만 보유,
         1순위에서 원본 finding을 못 찾은 경우의 보조 자료)

매칭 알고리즘 (외부 의존성 없음, stdlib만 사용):
  1. category 완전 일치(없으면 skill+cwe_id 일치)를 1차 필터로 사용
  2. title+description+evidence.code_snippet 토큰화 후 Jaccard 유사도
  3. scope.file 베이스네임/로그레벨 키워드 겹치면 가산점
  4. score >= 0.45 → high, 0.2 <= score < 0.45 → low, 그 외 → none

인덱스 노이즈 관리 (2026-09-08, Confluence pageId=775427230 댓글 반영):
  - SCA 계열 카테고리(SCA/*, *(SCA)*)는 애초에 /sec-review가 건별 판정에서 제외하는
    대상(feedback_sca_review_policy.md)이라 judgment_lookup을 절대 호출하지 않는다 —
    인덱스에 넣어봐야 100% 데드웨이트이므로 build_index()에서 원천 제외한다.
  - 종료/폐기된 서비스 레포는 tools/vision_status_db.py(Vision 사용여부 로컬 캐시)를
    캐시 전용(refresh_if_missing=False)으로 조회해 use_yn==0이면 제외한다. 캐시 미스는
    "제외 안 함"으로 처리(과잉 제외 방지) — 실제 갱신은 vision_status_db.py --refresh-all
    수동 배치가 담당.
  - tools/consolidate_judgment_index.py(분기별 수동 배치)가 만든 state/precedent_index.json이
    있으면 그 압축(대표건+발생건수) 결과를 베이스로 쓰고, 그 이후 새로 reviewed:true가 된
    (즉 아직 분기 배치에 반영 안 된) 최신 raw finding만 추가로 합친다 — "매 실행마다
    재구축, 최신성 우선" 원칙은 유지하면서 오래된 중복 precedent의 매칭 노이즈만 줄인다.

CLI:
  python3 tools/judgment_lookup.py --finding-json <path> [--top-k 3]
  python3 tools/judgment_lookup.py --finding-json <path> --exclude-repo <repo> --exclude-finding-id <fid>
      (leave-one-out 검증용 — 자기 자신을 인덱스에서 제외)

  stdout: {"matches": [...], "confidence": "high|low|none"}
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

PALANTIR_DIR      = Path(__file__).resolve().parent.parent
STATE_DIR         = PALANTIR_DIR / "state"
AUDIT_LOG         = STATE_DIR / "audit_log.json"
PRECEDENT_INDEX   = STATE_DIR / "precedent_index.json"

HIGH_THRESHOLD = 0.45
LOW_THRESHOLD  = 0.20

# SCA 계열은 /sec-review가 건별 판정에서 애초에 제외하는 카테고리라 인덱스에 넣지 않는다
# (feedback_sca_review_policy.md). 문자열 하드코딩 목록 대신 접두/부분 문자열로 판정해
# SCA 세부 카테고리가 늘어도 갱신이 필요 없게 한다.
def _is_sca_category(category: str) -> bool:
    return category.startswith("SCA/") or "(SCA)" in category


_repo_project_cache: dict[str, str | None] = {}
_vision_db_cache: dict | None = None


def _repo_project(repo: str) -> str | None:
    """state/<repo>/repo_meta.json의 project 필드 조회 (없으면 None)."""
    if repo in _repo_project_cache:
        return _repo_project_cache[repo]
    project = None
    meta_path = STATE_DIR / repo / "repo_meta.json"
    if meta_path.exists():
        try:
            project = json.loads(meta_path.read_text(encoding="utf-8")).get("project")
        except Exception:
            project = None
    _repo_project_cache[repo] = project
    return project


def _is_decommissioned_repo(repo: str) -> bool:
    """Vision 로컬 캐시(state/vision_repo_status.json)를 캐시 전용으로 조회한다.

    캐시 전용(refresh_if_missing=False)으로 고정 — 판정 실행 중 라이브 API 호출로
    지연/실패 리스크를 만들지 않는다. vision_status_db 모듈 자체가 없거나 로드에
    실패해도 조용히 False(제외 안 함)로 폴백한다.
    """
    global _vision_db_cache
    project = _repo_project(repo)
    if not project:
        return False
    try:
        import vision_status_db
    except Exception:
        return False
    if _vision_db_cache is None:
        _vision_db_cache = vision_status_db.load_db()
    return vision_status_db.is_decommissioned(project, repo, db=_vision_db_cache)

_TOKEN_RE = re.compile(r"[a-zA-Z0-9가-힣_]+")

_STOPWORDS = {
    "이", "가", "을", "를", "은", "는", "의", "에", "에서", "으로", "로", "및",
    "the", "a", "an", "is", "are", "of", "in", "on", "to", "and", "or",
}


def _tokenize(text: str) -> set[str]:
    if not text:
        return set()
    tokens = {t.lower() for t in _TOKEN_RE.findall(text)}
    return {t for t in tokens if len(t) >= 2 and t not in _STOPWORDS}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def _finding_text_tokens(finding: dict) -> set[str]:
    evidence = finding.get("evidence")
    code_snippet = evidence.get("code_snippet", "") if isinstance(evidence, dict) else ""
    parts = [
        finding.get("title", "") or "",
        finding.get("description", "") or "",
        code_snippet or "",
        finding.get("category", "") or "",
    ]
    return _tokenize(" ".join(p for p in parts if isinstance(p, str) and p))


def _scope_file_basename(finding: dict) -> str:
    scope = finding.get("scope")
    if not isinstance(scope, dict):
        return ""
    f = scope.get("file") or scope.get("affected_file") or ""
    return Path(f).stem.lower() if isinstance(f, str) and f else ""


def _category_key(finding: dict) -> str:
    cat = finding.get("category", "")
    if cat:
        return cat
    return f"{finding.get('skill', '')}:{finding.get('cwe_id', '')}"


def _load_precedent_index() -> dict | None:
    if not PRECEDENT_INDEX.exists():
        return None
    try:
        return json.loads(PRECEDENT_INDEX.read_text(encoding="utf-8"))
    except Exception:
        return None


def _scan_raw_index(
    exclude_repo: str | None,
    exclude_finding_id: str | None,
    skip_ids: set[str],
    after_run_id: str | None,
) -> list[dict]:
    """state/ 전체를 스캔해 과거 판정 완료 finding 원본 인덱스를 만든다.

    skip_ids: 이미 압축 인덱스(precedent_index.json)에 반영된 precedent_id — 대표건으로
      추가됐거나, 압축 시 중복으로 흡수돼 의도적으로 드롭된 항목이므로 원본 재스캔에서
      다시 넣지 않는다.
    after_run_id: 지정되면 이 run_id보다 최신인 finding만 포함 — 분기 배치 이후 새로
      리뷰된 항목만 raw로 합쳐서 최신성을 유지한다 (None이면 전체 스캔, 압축 인덱스가
      없을 때의 기존 동작과 동일).
    """
    index: list[dict] = []
    seen_precedent_ids: set[str] = set()

    for findings_path in STATE_DIR.glob("*/*/*/findings_*.json"):
        try:
            repo = findings_path.parts[len(STATE_DIR.parts)]
        except IndexError:
            continue
        try:
            doc = json.loads(findings_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        skill = ""
        run_id = ""
        try:
            # state/<repo>/<skill>/<run_id>/findings_*.json
            idx = findings_path.parts.index(repo)
            skill = findings_path.parts[idx + 1]
            run_id = findings_path.parts[idx + 2]
        except (ValueError, IndexError):
            pass

        if after_run_id is not None and run_id <= after_run_id:
            continue

        for f in doc.get("findings", []) or []:
            if not isinstance(f, dict) or not f.get("reviewed"):
                continue
            fid = f.get("finding_id", "")
            if exclude_repo and repo == exclude_repo and fid == exclude_finding_id:
                continue
            precedent_id = f"{repo}/{fid}"
            if precedent_id in seen_precedent_ids or precedent_id in skip_ids:
                continue

            category = _category_key(f)
            if _is_sca_category(category):
                continue
            if _is_decommissioned_repo(repo):
                continue

            seen_precedent_ids.add(precedent_id)
            index.append({
                "precedent_id":     precedent_id,
                "repo":             repo,
                "skill":            skill,
                "run_id":           run_id,
                "finding_id":       fid,
                "category":         category,
                "tokens":           _finding_text_tokens(f),
                "scope_basename":   _scope_file_basename(f),
                "review_status":    f.get("review_status", ""),
                "review_result":    f.get("review_result", ""),
                "severity_scan":    f.get("severity", ""),
                "severity_after":   f.get("severity", ""),
                "review_note":      (f.get("review_note") or "")[:500],
                "precedent_count":  1,
            })

    return index


def build_index(exclude_repo: str | None = None, exclude_finding_id: str | None = None) -> list[dict]:
    """과거 판정 완료 finding 인덱스를 만든다.

    state/precedent_index.json(분기별 수동 배치 tools/consolidate_judgment_index.py의
    산출물)이 있으면 그 압축(대표건+발생건수) 결과를 베이스로 쓰고, 그 이후 새로
    reviewed:true가 된 raw finding만 추가로 합친다. 없으면 기존처럼 전체 raw 스캔.
    """
    consolidated = _load_precedent_index()
    if not consolidated:
        return _scan_raw_index(exclude_repo, exclude_finding_id, skip_ids=set(), after_run_id=None)

    index: list[dict] = []
    skip_ids: set[str] = set()
    for cluster in consolidated.get("clusters", []) or []:
        reps = cluster.get("representatives")
        if not isinstance(reps, list):
            continue
        occurrence_count = cluster.get("occurrence_count", 1)
        for rep in reps:
            if not isinstance(rep, dict):
                continue
            precedent_id = rep.get("precedent_id", "")
            if exclude_repo and precedent_id == f"{exclude_repo}/{exclude_finding_id}":
                continue
            entry = dict(rep)
            entry["tokens"] = set(entry.get("tokens", []))
            entry["precedent_count"] = occurrence_count
            index.append(entry)
        skip_ids.update(cluster.get("precedent_ids", []) or [])

    cutoff_run_id = consolidated.get("cutoff_run_id")
    fresh = _scan_raw_index(exclude_repo, exclude_finding_id, skip_ids=skip_ids, after_run_id=cutoff_run_id)
    index.extend(fresh)
    return index


def lookup(finding: dict, index: list[dict], top_k: int = 3) -> list[dict]:
    cat_key = _category_key(finding)
    query_tokens = _finding_text_tokens(finding)
    query_basename = _scope_file_basename(finding)

    candidates = [c for c in index if c["category"] == cat_key]
    if not candidates:
        # category 완전 일치 후보가 없으면 skill만이라도 일치하는 후보로 완화
        skill = finding.get("skill", "")
        candidates = [c for c in index if skill and c["skill"] == skill]

    scored = []
    for c in candidates:
        score = _jaccard(query_tokens, c["tokens"])
        if query_basename and query_basename == c["scope_basename"]:
            score += 0.15
        scored.append((score, c))

    scored.sort(key=lambda x: x[0], reverse=True)
    results = []
    for score, c in scored[:top_k]:
        results.append({
            "precedent_id":  c["precedent_id"],
            "score":         round(score, 4),
            "decision":      c["review_status"],
            "review_result": c["review_result"],
            "severity_after": c["severity_after"],
            "review_note":   c["review_note"],
            "precedent_count": c.get("precedent_count", 1),
        })
    return results


def confidence_for(matches: list[dict]) -> str:
    if not matches:
        return "none"
    top = matches[0]["score"]
    if top >= HIGH_THRESHOLD:
        return "high"
    if top >= LOW_THRESHOLD:
        return "low"
    return "none"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--finding-json", required=True, help="조회할 finding 단일 객체가 담긴 JSON 파일 경로")
    ap.add_argument("--top-k", type=int, default=3)
    ap.add_argument("--exclude-repo", default=None, help="leave-one-out 검증용: 인덱스에서 제외할 repo")
    ap.add_argument("--exclude-finding-id", default=None, help="leave-one-out 검증용: 인덱스에서 제외할 finding_id")
    args = ap.parse_args()

    finding = json.loads(Path(args.finding_json).read_text(encoding="utf-8"))
    index = build_index(exclude_repo=args.exclude_repo, exclude_finding_id=args.exclude_finding_id)
    matches = lookup(finding, index, top_k=args.top_k)
    result = {
        "matches": matches,
        "confidence": confidence_for(matches),
        "index_size": len(index),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
