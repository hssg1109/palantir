#!/usr/bin/env python3
"""
fix_vision_assignee_id.py
vision DB에서 assignee 있고 assignee_id 없는 건을 찾아
Jira 계정 검색 후 Jenkins 등록 API로 assignee_id 보완.

동작:
  1. vision CSV 로드 → assignee 있고 assignee_id 없는 행 추출
  2. assignee 문자열에서 사번 파싱 시도 (내장 패턴)
  3. 파싱 실패 시 Jira 사용자 검색 (영문명 기반)
  4. 후보 목록 출력 후 확인 → Jenkins API 호출로 재등록

사용:
  python3 tools/fix_vision_assignee_id.py [--dry-run] [--project OCBPASS]
"""
import argparse
import csv
import json
import os
import re
import sys
import tempfile
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import date

from dotenv import load_dotenv

PALANTIR_DIR  = Path(__file__).resolve().parent.parent
GATEWAY_DIR   = PALANTIR_DIR.parent / "palantir-jira-gateway"
load_dotenv(GATEWAY_DIR / ".env")          # Jira 인증 (gateway 토큰 우선)
load_dotenv(PALANTIR_DIR / ".env", override=False)

VISION_BASE   = "https://vision.skplanet.com"
JENKINS_BASE  = "http://ssc.skplanet.com:9090"
JENKINS_JOB   = "/job/FORTIFY/job/" + urllib.parse.quote("미사용-레포-등록", safe="") + "/build"
JENKINS_USER  = "[REDACTED-JENKINS-USER]"
JENKINS_TOKEN = "[REDACTED-JENKINS-TOKEN]"
REPORTER      = "유성근"

JIRA_URL   = os.getenv("JIRA_URL", "").rstrip("/")
JIRA_USER  = os.getenv("JIRA_USER", "")
JIRA_TOKEN = os.getenv("JIRA_TOKEN", "")

# 수동 매핑: 영문명 → assignee_id (Jira 검색 결과 모호한 동명이인)
_MANUAL_ENG_MAP = {
    "[REDACTED-NAME]": "[REDACTED-ID]",  # SW/Syrup개발팀 (동명이인 1000063 재무구매팀과 구분)
}
# 수동 매핑: 한글 첫 세그먼트 → assignee_id (영문명 없는 assignee)
_MANUAL_HAN_MAP = {
    "[REDACTED-NAME]": "[REDACTED-ID]",
}


# ── 파싱 헬퍼 ─────────────────────────────────────────────────────────────────

def parse_embedded_id(assignee: str) -> str:
    """assignee 문자열에서 사번/계정ID 추출 시도.

    지원 패턴:
      "이름(영문)/팀/SKP/1001409"  → "1001409"  (끝이 순수 숫자)
      "이름(영문)/팀/SKP/1003009"  → "1003009"
      "1001111 홍길동 매니저"       → "1001111"  (앞이 숫자로 시작)
      "pp61341 <pp61341@sk.com>"  → "pp61341"  (소문자 계정명)
    조건: 순수 숫자(사번) 또는 소문자 시작(계정명) — SKP/OCB 등 대문자 단어 제외
    """
    # 패턴1: 끝 세그먼트가 순수 숫자 사번
    m = re.search(r'/(\d+)\s*$', assignee.strip())
    if m:
        return m.group(1)
    # 패턴2: 앞이 숫자로 시작 (사번 + 이름)
    m = re.match(r'^(\d+)\s+', assignee.strip())
    if m:
        return m.group(1)
    # 패턴3: <소문자계정@domain>
    m = re.search(r'<([a-z][^@\s]+)@', assignee)
    if m:
        return m.group(1)
    # 패턴4: 소문자+숫자 계정명으로 시작
    m = re.match(r'^([a-z][a-z0-9]+)\s+<', assignee.strip())
    if m:
        return m.group(1)
    return ""


def parse_english_name(assignee: str) -> str:
    """'이름(English Name)/팀' 형식에서 영문 이름 추출."""
    m = re.search(r'\(([^)]+)\)', assignee)
    return m.group(1).strip() if m else ""


# ── Jira 사용자 검색 ──────────────────────────────────────────────────────────

def jira_search_user(query: str) -> list[dict]:
    """Jira REST API /user/search — query로 계정 검색 (PAT Bearer 또는 Basic)."""
    if not JIRA_URL or not JIRA_TOKEN:
        return []
    try:
        email = os.getenv("JIRA_EMAIL", "").strip()
        if email:
            import base64
            cred = base64.b64encode(f"{email}:{JIRA_TOKEN}".encode()).decode()
            auth = f"Basic {cred}"
        else:
            auth = f"Bearer {JIRA_TOKEN}"
        params = urllib.parse.urlencode({"query": query, "maxResults": 5})
        req = urllib.request.Request(
            f"{JIRA_URL}/rest/api/2/user/picker?{params}",
            headers={"Authorization": auth, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
            # /user/picker 응답: {"users": [...]} 또는 직접 리스트
            return data.get("users", data) if isinstance(data, dict) else data
    except Exception as e:
        print(f"    [Jira 검색 오류] {e}")
        return []


# ── Jenkins 등록 API ──────────────────────────────────────────────────────────

def jenkins_register(prj: str, repo: str, use_yn: str, assignee_id: str,
                     assignee_text: str, reason_text: str, reason_dt: str,
                     dry_run: bool = False) -> bool:
    """Jenkins 미사용-레포-등록 API 호출 (multipart/form-data)."""
    import urllib.request
    import base64

    assignee_full = f"{assignee_id} {assignee_text}".strip() if assignee_id else assignee_text

    payload = json.dumps({
        "parameter": [
            {"name": "PRJ",         "value": prj},
            {"name": "REPO",        "value": repo},
            {"name": "USE_YN",      "value": use_yn},
            {"name": "ASSIGNEE",    "value": assignee_full},
            {"name": "REASON_TEXT", "value": reason_text or "assignee_id 보완 재등록"},
            {"name": "REASON_DT",   "value": reason_dt or str(date.today())},
            {"name": "REPORTER",    "value": REPORTER},
            {"name": "REASON_FILE", "file": "file0"},
        ]
    })

    if dry_run:
        print(f"    [DRY-RUN] Jenkins POST: PRJ={prj} REPO={repo} USE_YN={use_yn} ASSIGNEE={assignee_full}")
        return True

    # 임시 근거 파일 생성
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as tmp:
        tmp.write(f"assignee_id 보완 재등록\nreporter: {REPORTER}\ndate: {date.today()}")
        tmp_path = tmp.name

    try:
        boundary = "----PalantirBoundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file0"; filename="reason.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            + open(tmp_path, encoding='utf-8').read() +
            f"\r\n--{boundary}\r\n"
            f'Content-Disposition: form-data; name="json"\r\n\r\n'
            + payload +
            f"\r\n--{boundary}--\r\n"
        ).encode("utf-8")

        cred = base64.b64encode(f"{JENKINS_USER}:{JENKINS_TOKEN}".encode()).decode()
        req = urllib.request.Request(
            f"{JENKINS_BASE}{JENKINS_JOB}",
            data=body,
            headers={
                "Authorization": f"Basic {cred}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            status = r.status
        return status in (200, 201)
    except Exception as e:
        print(f"    [Jenkins 오류] {e}")
        return False
    finally:
        Path(tmp_path).unlink(missing_ok=True)


# ── 메인 ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="vision assignee_id 보완 도구")
    parser.add_argument("--dry-run", action="store_true", help="Jenkins API 호출 없이 출력만")
    parser.add_argument("--project", help="특정 프로젝트만 처리 (예: OCBPASS)")
    parser.add_argument("--csv", default=str(PALANTIR_DIR / "docs" / "vision_repo_status.csv"),
                        help="vision 전체 조회 CSV 경로")
    args = parser.parse_args()

    with open(args.csv, encoding="utf-8-sig") as f:
        all_rows = list(csv.DictReader(f))

    targets = [
        r for r in all_rows
        if r["assignee"].strip() and not r["assignee_id"].strip()
        and (not args.project or r["project"].upper() == args.project.upper())
    ]
    print(f"대상: {len(targets)}건 (assignee 있고 assignee_id 없음)\n")

    # 후보 테이블 구성
    candidates = []
    for r in targets:
        prj       = r["project"]
        repo      = r["repository"]
        use_yn    = r["use_yn"]   # '사용' or '미사용'
        assignee  = r["assignee"].strip()
        reason    = r["reason_text"].strip()
        reason_dt = r["reason_dt"].strip()

        # 0. 한글명 수동 매핑 (영문명 없는 assignee)
        han_seg = assignee.split('/')[0].strip()
        if han_seg in _MANUAL_HAN_MAP:
            mid = _MANUAL_HAN_MAP[han_seg]
            candidates.append({
                "prj": prj, "repo": repo, "use_yn": use_yn,
                "assignee_text": assignee, "reason": reason, "reason_dt": reason_dt,
                "assignee_id": mid, "source": "수동(한글)",
                "display": f"{mid}  ({assignee})",
            })
            continue

        # 1. 내장 ID 파싱 시도
        embedded = parse_embedded_id(assignee)
        if embedded:
            candidates.append({
                "prj": prj, "repo": repo, "use_yn": use_yn,
                "assignee_text": assignee, "reason": reason, "reason_dt": reason_dt,
                "assignee_id": embedded, "source": "파싱",
                "display": f"{embedded}  ({assignee})",
            })
            continue

        # 2. 영문명 추출 후 수동 매핑 또는 Jira 검색
        eng_name = parse_english_name(assignee)

        if eng_name in _MANUAL_ENG_MAP:
            mid = _MANUAL_ENG_MAP[eng_name]
            candidates.append({
                "prj": prj, "repo": repo, "use_yn": use_yn,
                "assignee_text": assignee, "reason": reason, "reason_dt": reason_dt,
                "assignee_id": mid, "source": f"수동(영문:{eng_name})",
                "display": f"{mid}  ({assignee})",
            })
            continue

        jira_hits = jira_search_user(eng_name) if eng_name else []
        if jira_hits:
            # displayName이 일치하는 사람 우선 (exact case-insensitive)
            best = next((u for u in jira_hits
                         if eng_name.lower() in u.get("displayName","").lower()), jira_hits[0])
            candidates.append({
                "prj": prj, "repo": repo, "use_yn": use_yn,
                "assignee_text": assignee, "reason": reason, "reason_dt": reason_dt,
                "assignee_id": best["name"],
                "source": f"Jira검색({best.get('displayName','')})",
                "display": f"{best['name']}  ({assignee})",
            })
        else:
            candidates.append({
                "prj": prj, "repo": repo, "use_yn": use_yn,
                "assignee_text": assignee, "reason": reason, "reason_dt": reason_dt,
                "assignee_id": "", "source": "미확인",
                "display": f"???  ({assignee})",
            })

    # 결과 출력
    print(f"{'#':<4} {'PROJECT':<16} {'REPO':<35} {'assignee_id(후보)':<20} {'출처':<20} assignee")
    print("-" * 120)
    ok, manual = [], []
    for i, c in enumerate(candidates, 1):
        mark = "✓" if c["assignee_id"] else "?"
        print(f"{i:<4} {c['prj']:<16} {c['repo']:<35} {(c['assignee_id'] or '???'):<20} {c['source']:<20} {c['assignee_text']}")
        (ok if c["assignee_id"] else manual).append(c)

    print(f"\n자동 확인: {len(ok)}건 / 수동 필요: {len(manual)}건")

    if manual:
        print("\n[수동 확인 필요]")
        for c in manual:
            print(f"  {c['prj']}/{c['repo']}  →  {c['assignee_text']}")

    if not ok:
        print("\n등록할 건 없음.")
        return

    if args.dry_run:
        print("\n[dry-run] 실제 등록 없이 종료.")
        return

    ans = input(f"\n자동 확인 {len(ok)}건을 Jenkins API로 재등록합니까? [y/N] ").strip().lower()
    if ans != "y":
        print("취소.")
        return

    success, fail = 0, 0
    for c in ok:
        print(f"  등록 중: {c['prj']}/{c['repo']} → {c['assignee_id']} ...", end=" ", flush=True)
        ok_flag = jenkins_register(
            prj=c["prj"], repo=c["repo"],
            use_yn=c["use_yn"], assignee_id=c["assignee_id"],
            assignee_text=c["assignee_text"],
            reason_text=c["reason"], reason_dt=c["reason_dt"],
            dry_run=args.dry_run,
        )
        if ok_flag:
            success += 1
            print("OK")
        else:
            fail += 1
            print("FAIL")

    print(f"\n완료: 성공 {success}건 / 실패 {fail}건")
    if args.dry_run:
        print("(dry-run 모드 — 실제 Jenkins 호출 없음)")


if __name__ == "__main__":
    main()
