#!/usr/bin/env python3
"""
site_config.py — 고객사·운영환경별 설정값 로더

공개 레포에 고객사 식별정보(프로젝트 키, Confluence 페이지 ID·제목, 서비스 분류 규칙 등)를
두지 않기 위해 해당 값은 gitignore된 config/site.local.json 에서 읽는다.
파일이 없으면 빈 기본값으로 동작한다. 키 목록은 config/site.example.json 참고.
"""
import json
from functools import lru_cache
from pathlib import Path

PALANTIR_DIR = Path(__file__).resolve().parent.parent
LOCAL_PATH = PALANTIR_DIR / "config" / "site.local.json"


@lru_cache(maxsize=1)
def load() -> dict:
    if LOCAL_PATH.exists():
        return json.loads(LOCAL_PATH.read_text(encoding="utf-8"))
    return {}


def get(key: str, default=None):
    return load().get(key, default)
