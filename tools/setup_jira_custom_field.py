#!/usr/bin/env python3
"""
setup_jira_custom_field.py — Jira 커스텀 필드 "조치기한" 생성 및 스크린 등록 (최초 1회)

사용법:
    python3 tools/setup_jira_custom_field.py [--screen-name SCREEN] [--dry-run]

동작:
  1. "조치기한" 날짜 커스텀 필드 존재 확인 → 없으면 생성 (관리자 권한 필요)
  2. 지정한 스크린 조회 (기본: "SECUFINDINGS" 포함 스크린 자동 탐지)
  3. 스크린 탭에 필드 추가
  4. .env 에 JIRA_REMEDIATION_DATE_FIELD_ID=customfield_XXXXX 저장

결과:
  - create_jira_ticket.py 가 자동으로 해당 커스텀 필드를 사용합니다.
"""

import argparse
import base64
import json
import re
import sys
from pathlib import Path

import requests

PALANTIR_DIR = Path(__file__).resolve().parent.parent
_ENV_PATH    = PALANTIR_DIR / ".env"

FIELD_NAME        = "조치기한"
FIELD_DESCRIPTION = "취약점 조치 기한일 (개발팀 조치 일자 확정 후 입력)"
FIELD_TYPE        = "com.atlassian.jira.plugin.system.customfieldtypes:datepicker"
FIELD_SEARCHER    = "com.atlassian.jira.plugin.system.customfieldtypes:daterange"
ENV_KEY           = "JIRA_REMEDIATION_DATE_FIELD_ID"


# ──────────────────────────────────────────────────────────────────────────────

def _load_env() -> dict:
    env: dict = {}
    if _ENV_PATH.exists():
        for line in _ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            v = re.sub(r"\s+#.*$", "", v)
            env[k.strip()] = v.strip()
    return env


def _jira_headers(env: dict) -> dict:
    token = env.get("JIRA_TOKEN", "")
    email = env.get("JIRA_EMAIL", "").strip()
    if email:
        creds = base64.b64encode(f"{email}:{token}".encode()).decode()
        return {"Authorization": f"Basic {creds}", "Content-Type": "application/json"}
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _update_env(field_id: str) -> None:
    """
    .env 파일에 JIRA_REMEDIATION_DATE_FIELD_ID 추가 또는 갱신.
    기존 키가 있으면 해당 줄만 교체한다.
    """
    content = _ENV_PATH.read_text(encoding="utf-8") if _ENV_PATH.exists() else ""
    new_line = f"{ENV_KEY}={field_id}"
    if re.search(rf"^{ENV_KEY}\s*=", content, re.MULTILINE):
        content = re.sub(rf"^{ENV_KEY}\s*=.*$", new_line, content, flags=re.MULTILINE)
    else:
        content = content.rstrip("\n") + f"\n{new_line}\n"
    _ENV_PATH.write_text(content, encoding="utf-8")
    print(f"[OK] .env 갱신 완료: {new_line}")


# ──────────────────────────────────────────────────────────────────────────────

def get_or_create_field(env: dict, jira_url: str, dry_run: bool) -> str | None:
    """
    "조치기한" 커스텀 필드 ID 반환.
    이미 존재하면 기존 ID, 없으면 생성 후 ID 반환.
    """
    resp = requests.get(
        f"{jira_url}/rest/api/2/field",
        headers=_jira_headers(env),
        timeout=15,
    )
    if resp.status_code != 200:
        print(f"[ERROR] 필드 목록 조회 실패 (HTTP {resp.status_code})")
        print(resp.text[:500])
        return None

    fields = resp.json()
    for f in fields:
        if f.get("name") == FIELD_NAME and f.get("custom"):
            field_id = f["id"]
            print(f"[INFO] 기존 커스텀 필드 발견: {FIELD_NAME} → {field_id}")
            return field_id

    # 존재하지 않음 → 생성
    print(f"[INFO] '{FIELD_NAME}' 커스텀 필드 없음 — 새로 생성합니다.")
    payload = {
        "name":        FIELD_NAME,
        "description": FIELD_DESCRIPTION,
        "type":        FIELD_TYPE,
        "searcherKey": FIELD_SEARCHER,
    }

    if dry_run:
        print(f"[DRY-RUN] POST /rest/api/2/field:\n{json.dumps(payload, ensure_ascii=False, indent=2)}")
        return "customfield_DRY_RUN"

    resp = requests.post(
        f"{jira_url}/rest/api/2/field",
        headers=_jira_headers(env),
        json=payload,
        timeout=15,
    )
    if resp.status_code in (200, 201):
        field_id = resp.json()["id"]
        print(f"[OK] 커스텀 필드 생성 완료: {FIELD_NAME} → {field_id}")
        return field_id

    print(f"[ERROR] 커스텀 필드 생성 실패 (HTTP {resp.status_code})")
    try:
        print(json.dumps(resp.json(), ensure_ascii=False, indent=2)[:800])
    except Exception:
        print(resp.text[:500])
    print()
    print("  ※ Jira 관리자 권한이 필요합니다.")
    print("  ※ 직접 생성 방법: Jira 관리(⚙) → Issues → Custom Fields → Add Custom Field")
    print(f"     → 종류: Date Picker / 필드명: {FIELD_NAME}")
    return None


def find_screen(env: dict, jira_url: str, screen_name_hint: str) -> tuple[str, str] | None:
    """
    스크린 목록에서 screen_name_hint 가 포함된 스크린을 찾아 (screen_id, tab_id) 반환.
    """
    resp = requests.get(
        f"{jira_url}/rest/api/2/screens",
        headers=_jira_headers(env),
        params={"maxResults": 200},
        timeout=15,
    )
    if resp.status_code != 200:
        print(f"[ERROR] 스크린 목록 조회 실패 (HTTP {resp.status_code})")
        print(resp.text[:300])
        return None

    screens = resp.json()
    # 'values' 키 또는 직접 리스트
    if isinstance(screens, dict):
        screens = screens.get("values", [])

    matched = [s for s in screens if screen_name_hint.upper() in s.get("name", "").upper()]
    if not matched:
        print(f"[WARN] '{screen_name_hint}' 포함 스크린 없음. 전체 목록:")
        for s in screens[:20]:
            print(f"  id={s['id']}  name={s['name']}")
        if len(screens) > 20:
            print(f"  ... 외 {len(screens)-20}개")
        return None

    screen = matched[0]
    screen_id = str(screen["id"])
    print(f"[INFO] 스크린 선택: id={screen_id}  name={screen['name']}")

    # 탭 조회 (기본 탭 첫 번째 사용)
    resp = requests.get(
        f"{jira_url}/rest/api/2/screens/{screen_id}/tabs",
        headers=_jira_headers(env),
        timeout=15,
    )
    if resp.status_code != 200:
        print(f"[ERROR] 탭 조회 실패 (HTTP {resp.status_code})")
        return None

    tabs = resp.json()
    if not tabs:
        print("[ERROR] 탭이 없는 스크린입니다.")
        return None

    tab_id = str(tabs[0]["id"])
    print(f"[INFO] 탭 선택: id={tab_id}  name={tabs[0]['name']}")
    return screen_id, tab_id


def add_field_to_screen(
    env: dict, jira_url: str,
    screen_id: str, tab_id: str,
    field_id: str, dry_run: bool,
) -> bool:
    """스크린 탭에 커스텀 필드를 추가한다. 이미 있으면 OK로 처리."""
    # 현재 탭 필드 확인
    resp = requests.get(
        f"{jira_url}/rest/api/2/screens/{screen_id}/tabs/{tab_id}/fields",
        headers=_jira_headers(env),
        timeout=15,
    )
    if resp.status_code == 200:
        existing_ids = {f["id"] for f in resp.json()}
        if field_id in existing_ids:
            print(f"[INFO] 필드 '{field_id}'는 이미 스크린에 등록되어 있습니다.")
            return True

    if dry_run:
        print(f"[DRY-RUN] POST screens/{screen_id}/tabs/{tab_id}/fields  fieldId={field_id}")
        return True

    resp = requests.post(
        f"{jira_url}/rest/api/2/screens/{screen_id}/tabs/{tab_id}/fields",
        headers=_jira_headers(env),
        json={"fieldId": field_id},
        timeout=15,
    )
    if resp.status_code in (200, 201):
        print(f"[OK] 스크린 탭에 '{FIELD_NAME}({field_id})' 추가 완료")
        return True

    print(f"[WARN] 스크린 필드 추가 실패 (HTTP {resp.status_code})")
    try:
        print(json.dumps(resp.json(), ensure_ascii=False, indent=2)[:400])
    except Exception:
        print(resp.text[:300])
    return False


# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=f"Jira 커스텀 필드 '{FIELD_NAME}' 생성 및 스크린 등록")
    parser.add_argument("--screen-name", default="SECUFINDINGS",
                        help="스크린 이름 검색 키워드 (기본: SECUFINDINGS)")
    parser.add_argument("--dry-run", action="store_true",
                        help="실제 변경 없이 payload 출력")
    args = parser.parse_args()

    env      = _load_env()
    jira_url = env.get("JIRA_URL", "").rstrip("/")

    if not jira_url:
        print("[ERROR] .env에 JIRA_URL이 없습니다.")
        sys.exit(1)
    if not env.get("JIRA_TOKEN"):
        print("[ERROR] .env에 JIRA_TOKEN이 없습니다.")
        sys.exit(1)

    print(f"\n=== Jira 커스텀 필드 설정: {FIELD_NAME} ===")
    print(f"Jira: {jira_url}")
    print()

    # Step 1. 필드 생성/조회
    field_id = get_or_create_field(env, jira_url, args.dry_run)
    if not field_id:
        sys.exit(1)

    # Step 2. 스크린에 추가
    screen_result = find_screen(env, jira_url, args.screen_name)
    if screen_result:
        screen_id, tab_id = screen_result
        add_field_to_screen(env, jira_url, screen_id, tab_id, field_id, args.dry_run)
    else:
        print(f"[WARN] 스크린 등록 생략 — 수동으로 '{FIELD_NAME}({field_id})' 필드를 스크린에 추가하세요.")

    # Step 3. .env 갱신
    if not args.dry_run:
        _update_env(field_id)
    else:
        print(f"[DRY-RUN] .env 갱신 예정: {ENV_KEY}={field_id}")

    print(f"\n{'='*50}")
    print(f"  커스텀 필드 ID: {field_id}")
    print(f"  .env 키:        {ENV_KEY}")
    print(f"  다음 실행부터 create_jira_ticket.py 가 자동으로 이 필드를 사용합니다.")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
