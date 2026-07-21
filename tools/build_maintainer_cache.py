#!/usr/bin/env python3
"""
docs/service_inventory.json + palantir-jira-gateway/data/repo_config.json 의
기존 담당자 표기에서 이메일 -> {name_kr, name_en, team} 매핑을 추출해
shared/references/maintainer_directory_cache.json 캐시를 (재)구축한다.

동일 이메일에 여러 표기가 섞여 있으면 가장 완전한(팀+영문명 모두 있는) 표기를 채택한다.
재실행 가능 — 기존 캐시를 항상 덮어쓴다 (수기로 보완한 항목은 소스 파일에 반영해야 유지됨).
"""
import json
import re
from pathlib import Path

PALANTIR_DIR = Path(__file__).resolve().parent.parent
SERVICE_INVENTORY = PALANTIR_DIR / "docs" / "service_inventory.json"
REPO_CONFIG = PALANTIR_DIR.parent / "palantir-jira-gateway" / "data" / "repo_config.json"
CACHE_OUT = PALANTIR_DIR / "shared" / "references" / "maintainer_directory_cache.json"
MANUAL_OVERRIDES = PALANTIR_DIR / "shared" / "references" / "maintainer_manual_overrides.json"

EMAIL_RE = r"[\w.+-]+@[\w.-]+"

# 완전도(높은 순): (패턴, 그룹명 -> (kr, en, team))
INVENTORY_PATTERNS = [
    # 이름(영문명)/팀명/SKP <메일>
    (re.compile(rf"^(?P<kr>[^(/<]+?)\((?P<en>[^)]+)\)/(?P<team>[^/]+)/SKP\s*<(?P<email>{EMAIL_RE})>$"), 3),
    # 이름/팀명/SKP <메일>  (영문명 없음)
    (re.compile(rf"^(?P<kr>[^(/<]+?)/(?P<team>[^/]+)/SKP\s*<(?P<email>{EMAIL_RE})>$"), 2),
    # 이름(영문명) <메일>  (팀 없음)
    (re.compile(rf"^(?P<kr>[^(/<]+?)\((?P<en>[^)]+)\)\s*<(?P<email>{EMAIL_RE})>$"), 1),
    # [SKP] 이름 <메일>  (팀 없음, 영문명 없음)
    (re.compile(rf"^\[SKP\]\s*(?P<kr>[^<]+?)\s*<(?P<email>{EMAIL_RE})>$"), 0),
    # 이름/영문명 <메일> 등 그 외 "무언가 <메일>" (팀 없음, kr/en 구분 안 함 -> name 필드로만 저장)
    (re.compile(rf"^(?P<kr>[^<]+?)\s*<(?P<email>{EMAIL_RE})>$"), 0),
]

# repo_config.json note 필드: "이름(영문명)/팀명 — ... (메일)" 또는 "... <메일>"
NOTE_HEADER_RE = re.compile(r"^(?P<kr>[^(/]+)\((?P<en>[^)]+)\)/(?P<team>[^\s—]+)")
NOTE_EMAIL_RE = re.compile(rf"[<(]({EMAIL_RE})[>)]")


def _score(entry: dict) -> int:
    return (1 if entry.get("name_en") else 0) + (2 if entry.get("team") else 0)


def _merge(cache: dict, email: str, name_kr: str, name_en: str, team: str, source: str):
    email = email.strip().lower()
    candidate = {
        "name_kr": (name_kr or "").strip() or None,
        "name_en": (name_en or "").strip() or None,
        "team": (team or "").strip() or None,
        "source": source,
    }
    existing = cache.get(email)
    if existing is None or _score(candidate) > _score(existing):
        cache[email] = candidate


def parse_service_inventory(cache: dict) -> int:
    if not SERVICE_INVENTORY.exists():
        print(f"[SKIP] {SERVICE_INVENTORY} 없음")
        return 0
    data = json.loads(SERVICE_INVENTORY.read_text(encoding="utf-8"))
    matched = 0
    for svc in data.get("services", []):
        maintainer = (svc.get("maintainer") or "").strip()
        if not maintainer:
            continue
        repo = svc.get("repo", "?")
        for pattern, _rank in INVENTORY_PATTERNS:
            m = pattern.match(maintainer)
            if not m:
                continue
            g = m.groupdict()
            _merge(
                cache,
                g["email"],
                g.get("kr", ""),
                g.get("en", ""),
                g.get("team", ""),
                f"service_inventory:{repo}",
            )
            matched += 1
            break
    return matched


def parse_repo_config(cache: dict) -> int:
    if not REPO_CONFIG.exists():
        print(f"[SKIP] {REPO_CONFIG} 없음")
        return 0
    data = json.loads(REPO_CONFIG.read_text(encoding="utf-8"))
    matched = 0
    for repo, entry in data.items():
        if repo.startswith("_"):
            continue
        note = (entry.get("note") or "").strip()
        if not note:
            continue
        email_m = NOTE_EMAIL_RE.search(note)
        if not email_m:
            continue
        header_m = NOTE_HEADER_RE.match(note)
        if header_m:
            g = header_m.groupdict()
            _merge(cache, email_m.group(1), g["kr"], g["en"], g["team"], f"repo_config:{repo}")
            matched += 1
    return matched


def apply_manual_overrides(cache: dict) -> int:
    """
    shared/references/maintainer_manual_overrides.json (수기 관리, git 추적)을 캐시 위에 병합한다.
    자동 파싱 결과보다 항상 우선하며, 재실행(캐시 재생성) 시에도 유실되지 않는다.
    부분 필드만 지정 가능 (예: status만 있고 team은 기존 값 유지).
    """
    if not MANUAL_OVERRIDES.exists():
        return 0
    overrides = json.loads(MANUAL_OVERRIDES.read_text(encoding="utf-8"))
    for email, fields in overrides.items():
        email = email.strip().lower()
        merged = dict(cache.get(email) or {})
        merged.update({k: v for k, v in fields.items() if v is not None})
        merged["source"] = "manual_override"
        cache[email] = merged
    return len(overrides)


def main():
    cache: dict = {}
    n1 = parse_service_inventory(cache)
    n2 = parse_repo_config(cache)
    n3 = apply_manual_overrides(cache)

    CACHE_OUT.parent.mkdir(parents=True, exist_ok=True)
    CACHE_OUT.write_text(
        json.dumps(cache, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    complete = sum(1 for v in cache.values() if v.get("team") and v.get("name_en"))
    print(f"[DONE] service_inventory 매칭: {n1}건 / repo_config 매칭: {n2}건 / 수기 보정: {n3}건")
    print(f"[DONE] 캐시 총 {len(cache)}건 (완전 항목: {complete}건) -> {CACHE_OUT}")


if __name__ == "__main__":
    main()
