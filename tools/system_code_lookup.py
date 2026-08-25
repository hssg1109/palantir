#!/usr/bin/env python3
"""
system_code_lookup.py — docs/system_code_to_repo_20260729_v3.json 기반 공용 조회 모듈

build_system_code_scan_status.py / add_system_code_col_to_plan.py 가 공유한다.
"""
import json
import re
from pathlib import Path

PALANTIR_DIR = Path(__file__).parent.parent
SRC_JSON = PALANTIR_DIR / "docs" / "system_code_to_repo_20260729_v3.json"

# 상위 서비스군 분류 — 시스템명 접두어 기반 휴리스틱 (참고용, 100% 정확 보장 안 함)
_GROUP_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^(OCB이벤트|OCBpass|OKICK|OCB)"), "OCB"),
    (re.compile(r"^Syrup"), "Syrup"),
    (re.compile(r"^DI-"), "DI(데이터인프라)"),
    (re.compile(r"^BI서비스"), "BI"),
    (re.compile(r"^MGMT"), "인프라운영"),
    (re.compile(r"^PICASO"), "PICASO"),
    (re.compile(r"^Proxy-"), "Proxy"),
    (re.compile(r"^정보료과금"), "정보료과금"),
    (re.compile(r"^보안"), "보안"),
    (re.compile(r"^광고"), "광고플랫폼"),
]


def classify_group(system_name: str) -> str:
    """시스템명 접두어로 상위 서비스군을 휴리스틱 분류한다. 매칭 안 되면 '미분류'."""
    for pattern, label in _GROUP_RULES:
        if pattern.match(system_name):
            return label
    return "미분류"


def load_entries() -> list[dict]:
    return json.loads(SRC_JSON.read_text(encoding="utf-8"))


def build_repo_to_codes(entries: list[dict] | None = None) -> dict[str, list[str]]:
    """repo slug(마지막 경로 세그먼트) → 매핑된 system_code 목록 (중복 매핑 그대로 포함)."""
    if entries is None:
        entries = load_entries()
    rev: dict[str, list[str]] = {}
    for e in entries:
        code = e["system_code"]
        for repo_path in e.get("repos", []):
            slug = repo_path.rsplit("/", 1)[-1]
            rev.setdefault(slug, []).append(code)
    return rev
