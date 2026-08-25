#!/usr/bin/env python3
"""
post_jira_comment.py — Jira 이슈에 위키마크업 코멘트 게시 (+선택적 상태 전이)

브라우저의 코멘트 입력창(비주얼/ADF 에디터)은 {panel}/||table||/{color} 같은
위키마크업 문법을 파싱하지 않고 리터럴 텍스트로 그대로 삽입한다. 반면 REST API
(`/rest/api/2/issue/{key}/comment`)의 body 필드는 서버가 위키마크업으로 파싱해
렌더링하므로, create_jira_ticket.py가 티켓 본문을 만들 때와 동일한 경로로 코멘트도
게시해야 {panel}/{color}/표가 의도대로 보인다.

인증 주체 = 코멘트 작성자: REST API로 게시하는 코멘트는 항상 인증에 쓰인 계정 이름으로
남는다. .env의 JIRA_TOKEN이 공용/타인 계정 PAT이면 작성자가 그 사람으로 찍히므로,
JIRA_TOKEN_REMEDIATION에 실제 작성자 본인의 PAT를 넣으면 그 계정으로 게시된다
(미설정 시 JIRA_TOKEN으로 fallback).

Assignee 보존: Jira 워크플로 전이(transition)에 "현재 사용자에게 할당" 같은
post-function이 걸려있으면, 전이를 실행한 계정(=API 인증 주체)에게 담당자가
자동으로 바뀌어버릴 수 있다. 이를 막기 위해 --transition-name 사용 시 전이 전
담당자를 확보해두고, 전이 후 원래 담당자로 복원한다.

Assignee 개발자 재할당(--reassign-to-developer): 이행점검 워크플로에서는 전이 직전
담당자가 항상 감사자 본인이다 (개발자가 조치 완료 후 "이행점검대기"로 넘기면서 담당자를
감사자에게 handoff하고, 감사자가 검토하는 동안 담당자는 계속 감사자로 유지되기 때문).
따라서 "전이 직전 담당자로 복원"은 감사자 자신을 복원하는 것과 같아 아무 효과가 없다
(2026-07-16 SECUFINDINGS-2132에서 실제로 확인 — "담당자 유성근/보안진단실 유지됨"으로
찍혔으나 실제로 필요한 것은 개발자 재할당이었음, 1차에서는 이를 사람이 수동으로 고침).
이 옵션을 쓰면 복원 대신, 이슈 changelog에서 "현재(전이 직전) 담당자에게 넘어오기 직전
담당자"를 역추적해(= 개발자가 감사자에게 handoff한 그 순간의 이전 담당자) 그 사람에게
재할당한다. changelog에 해당 handoff 이력이 없으면(예: 최초 실행) 경고만 출력하고
기존 담당자 보존 동작으로 대체한다.

코멘트는 항상 전이와 별개의 POST로 남긴다: Jira REST의 "전이+코멘트 원자적 1콜"
(`update.comment.add.body`)은 해당 전이의 화면(screen)에 코멘트 필드가 구성되어
있지 않으면 요청이 200/204로 성공 응답을 반환하면서도 코멘트가 조용히 무시된다
(2026-07-15 SECUFINDINGS-2131 "잔여 취약점 없음(조치완료)"→Closed 전이에서 실제로
발생 — 전이는 성공했으나 코멘트가 이력에 남지 않음, 해당 전이 화면의 fields가 {}임을
`GET /transitions?expand=transitions.fields`로 확인). 따라서 이 스크립트는 코멘트를
먼저 `/comment` 엔드포인트로 별도 POST하고, 그다음에 `/transitions`를 별도 POST한다 —
어떤 전이 화면 구성에서도 코멘트 이력이 항상 남는다.

사용법:
    # 사용 가능한 전이 목록만 확인 (읽기 전용)
    python3 tools/post_jira_comment.py --ticket <KEY> --list-transitions

    # 코멘트만 게시
    python3 tools/post_jira_comment.py --ticket <KEY> --file <위키마크업.txt> [--dry-run]

    # 코멘트 게시 + 상태 전이 (코멘트 먼저 별도 POST, 그다음 전이 별도 POST — 담당자 자동 보존)
    python3 tools/post_jira_comment.py --ticket <KEY> --file <위키마크업.txt> \\
        --transition-name "이행점검 완료" [--dry-run]

    # 코멘트 게시 + 상태 전이 + 담당자를 개발자로 재할당 (감사자→개발자 handoff 워크플로 권장)
    python3 tools/post_jira_comment.py --ticket <KEY> --file <위키마크업.txt> \\
        --transition-name "이행점검 완료" --reassign-to-developer [--dry-run]

    # 이미 게시된 코멘트의 내용을 수정 (새 코멘트 POST 대신 PUT으로 교체)
    python3 tools/post_jira_comment.py --ticket <KEY> --file <위키마크업.txt> \\
        --edit-comment-id <COMMENT-ID> [--dry-run]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.jira_utils import load_env, jira_headers

PALANTIR_DIR = Path(__file__).resolve().parent.parent
_TOKEN_VAR = "JIRA_TOKEN_REMEDIATION"

# Jira 위키 렌더러는 {word} 또는 {word:params} 형태를 전부 매크로 토큰으로 파싱한다.
# 등록된 매크로(color/panel)가 아닌 임의의 {word}가 본문에 섞이면 — 예: 코드에서 그대로
# 옮겨적은 Spring 경로변수 "/{channel}/ad/banner" — 렌더러가 이를 미등록/미종료 매크로로
# 오인해 그 지점부터 표·리스트 파싱이 깨지고 이후 전체 내용이 직전 셀 하나에 뭉쳐 들어간다
# (2026-08-10 SECUFINDINGS-2117 코멘트에서 실제 발생 — 표가 깨지고 줄바꿈이 사라짐).
# {{ }}(모노스페이스)로 감싸는 것만으로는 부족하다 — 내부에 {word} 패턴이 있으면 매크로
# 스캐너가 모노스페이스 경계보다 먼저(또는 별도로) {word}를 macro로 인식해 똑같이 깨진다
# (1차 수정 시도 "/{{{channel}}}/ad/banner"로도 재현 확인). 대신 중괄호 자체를 HTML
# 엔티티(&#123; / &#125;)로 치환한다 — 위키 파서는 원시 "{"/"}" 문자만 매크로 델리미터로
# 인식하므로 엔티티 형태는 매크로로 파싱되지 않고, 최종 HTML을 브라우저가 렌더링할 때
# 엔티티가 "{"/"}"로 디코드되어 화면에는 원래 텍스트와 동일하게 보인다.
_ALLOWED_WIKI_MACROS = {"color", "panel"}
_BRACE_MACRO_RE = re.compile(r"(?<!\{)\{([A-Za-z][A-Za-z0-9_]*)(:[^{}\n]*)?\}(?!\})")


def _escape_unsafe_brace_macros(text: str) -> tuple[str, list[str]]:
    """{color}/{panel} 외의 {word} 패턴을 HTML 엔티티로 치환해 매크로 오인식을 방지한다."""
    escaped: list[str] = []

    def _repl(m: re.Match) -> str:
        if m.group(1) in _ALLOWED_WIKI_MACROS:
            return m.group(0)
        escaped.append(m.group(0))
        return "&#123;" + m.group(0)[1:-1] + "&#125;"

    return _BRACE_MACRO_RE.sub(_repl, text), escaped


def _get_transitions(jira_url: str, headers: dict, ticket: str) -> list[dict]:
    resp = requests.get(f"{jira_url}/rest/api/2/issue/{ticket}/transitions", headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json().get("transitions", [])


def _get_assignee(jira_url: str, headers: dict, ticket: str) -> dict | None:
    resp = requests.get(f"{jira_url}/rest/api/2/issue/{ticket}?fields=assignee", headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json().get("fields", {}).get("assignee")


def _set_assignee(jira_url: str, headers: dict, ticket: str, name: str) -> None:
    resp = requests.put(
        f"{jira_url}/rest/api/2/issue/{ticket}/assignee",
        headers=headers,
        json={"name": name},
        timeout=30,
    )
    resp.raise_for_status()


def _find_handoff_developer(jira_url: str, headers: dict, ticket: str, handoff_to_key: str) -> dict | None:
    """changelog에서 assignee가 handoff_to_key(현재/전이 직전 담당자)로 바뀐 가장 최근
    항목을 찾아, 그 직전 담당자(from)를 실제 username까지 resolve해 반환한다. 없으면 None.

    changelog의 assignee item은 from/to에 내부 key(예: JIRAUSER49223, 또는 순수 숫자 key)를
    담고 있어 assignee PUT이 요구하는 name(username)과 다를 수 있으므로 /user?key= 로 재조회한다.
    """
    resp = requests.get(
        f"{jira_url}/rest/api/2/issue/{ticket}",
        headers=headers,
        params={"expand": "changelog", "fields": "assignee"},
        timeout=30,
    )
    resp.raise_for_status()
    histories = resp.json().get("changelog", {}).get("histories", [])
    match = None
    for h in histories:  # 오래된 것부터 순서대로 오므로 마지막 일치가 최신
        for item in h.get("items", []):
            if item.get("field") == "assignee" and item.get("to") == handoff_to_key:
                match = item
    if not match or not match.get("from"):
        return None
    dev_key = match["from"]
    user_resp = requests.get(f"{jira_url}/rest/api/2/user", headers=headers, params={"key": dev_key}, timeout=30)
    if user_resp.status_code != 200:
        return None
    user = user_resp.json()
    return {"name": user["name"], "displayName": user.get("displayName") or match.get("fromString") or dev_key}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ticket", required=True, help="Jira 이슈 키 (예: SECUFINDINGS-2132)")
    ap.add_argument("--file", help="게시할 위키마크업 텍스트 파일 경로 (전이만 할 경우 생략 가능)")
    ap.add_argument("--edit-comment-id", help="새 코멘트를 POST하는 대신, 지정한 id의 기존 코멘트 body를 --file 내용으로 교체(PUT)")
    ap.add_argument("--transition-name", help="적용할 워크플로 전이 이름 (예: '이행점검 완료') — GET transitions 응답의 name과 정확히 일치해야 함")
    ap.add_argument("--list-transitions", action="store_true", help="사용 가능한 전이 목록만 조회하고 종료 (읽기 전용)")
    ap.add_argument("--no-preserve-assignee", action="store_true", help="전이 시 담당자 자동 보존을 끔 (워크플로의 재할당 결과를 그대로 둠)")
    ap.add_argument("--reassign-to-developer", action="store_true", help="전이 후 담당자를 '전이 직전 담당자(감사자)'로 복원하는 대신, changelog에서 역추적한 handoff 이전 담당자(개발자)에게 재할당")
    ap.add_argument("--dry-run", action="store_true", help="실제 POST 없이 요청 내용만 출력")
    args = ap.parse_args()

    env = load_env()
    jira_url = env.get("JIRA_URL", "").rstrip("/")
    if not jira_url:
        print("[오류] .env에 JIRA_URL 없음", file=sys.stderr)
        return 1
    headers = jira_headers(env, token_var=_TOKEN_VAR)
    if not env.get(_TOKEN_VAR, "").strip():
        print(f"[알림] .env에 {_TOKEN_VAR} 미설정 — JIRA_TOKEN(공용/타 계정)으로 게시됨. 본인 명의로 남기려면 {_TOKEN_VAR}에 개인 PAT 추가 필요.")

    if args.list_transitions:
        transitions = _get_transitions(jira_url, headers, args.ticket)
        for t in transitions:
            print(f"  name={t['name']!r:<28} -> to.name={t['to']['name']!r} (id={t['id']})")
        return 0

    body_text = None
    if args.file:
        body_path = Path(args.file)
        if not body_path.is_absolute():
            body_path = PALANTIR_DIR / body_path
        if not body_path.exists():
            print(f"[오류] 파일 없음: {body_path}", file=sys.stderr)
            return 1
        body_text = body_path.read_text(encoding="utf-8")
        body_text, escaped_tokens = _escape_unsafe_brace_macros(body_text)
        if escaped_tokens:
            print(f"[알림] 미등록 위키 매크로로 오인될 수 있는 패턴 {len(escaped_tokens)}건을 자동으로 {{{{ }}}}(모노스페이스)로 이스케이프함: {', '.join(sorted(set(escaped_tokens)))}")

    if not body_text and not args.transition_name:
        print("[오류] --file 또는 --transition-name 중 하나는 있어야 함", file=sys.stderr)
        return 1

    transition_id = None
    transition_to = None
    if args.transition_name:
        transitions = _get_transitions(jira_url, headers, args.ticket)
        match = next((t for t in transitions if t["name"] == args.transition_name), None)
        if not match:
            available = ", ".join(repr(t["name"]) for t in transitions)
            print(f"[오류] 전이 '{args.transition_name}' 를 찾을 수 없음. 현재 상태에서 가능한 전이: {available}", file=sys.stderr)
            return 1
        transition_id = match["id"]
        transition_to = match["to"]["name"]

    preserve_assignee = transition_id and not args.no_preserve_assignee
    reassign_to_developer = transition_id and args.reassign_to_developer
    original_assignee = None
    if preserve_assignee or reassign_to_developer:
        original_assignee = _get_assignee(jira_url, headers, args.ticket)

    developer_assignee = None
    if reassign_to_developer and original_assignee:
        developer_assignee = _find_handoff_developer(jira_url, headers, args.ticket, original_assignee["key"])
        if not developer_assignee:
            print("[알림] changelog에서 handoff 이전 담당자(개발자)를 찾지 못함 — 기존 담당자 보존 동작으로 대체", file=sys.stderr)

    comment_endpoint = f"{jira_url}/rest/api/2/issue/{args.ticket}/comment"
    if args.edit_comment_id:
        comment_endpoint = f"{comment_endpoint}/{args.edit_comment_id}"
    transition_endpoint = f"{jira_url}/rest/api/2/issue/{args.ticket}/transitions"

    if args.dry_run:
        if body_text:
            print(f"[dry-run] {'PUT' if args.edit_comment_id else 'POST'} {comment_endpoint}")
            print("──── comment body ────")
            print(body_text)
        if transition_id:
            print(f"[dry-run] POST {transition_endpoint}")
            print(f"[dry-run] 전이: {args.transition_name!r} (id={transition_id}) -> status {transition_to!r}")
            if developer_assignee:
                print(f"[dry-run] 전이 후 담당자 재할당 대상(개발자, changelog 역추적): {developer_assignee['displayName']}")
            elif preserve_assignee:
                who = original_assignee["displayName"] if original_assignee else "(미할당)"
                print(f"[dry-run] 전이 후 담당자 보존 대상: {who}")
        return 0

    comment_id = None
    if body_text:
        method = requests.put if args.edit_comment_id else requests.post
        resp = method(comment_endpoint, headers=headers, json={"body": body_text}, timeout=30)
        if resp.status_code not in (200, 201, 204):
            action = "수정" if args.edit_comment_id else "게시"
            print(f"[오류] 코멘트 {action} 실패 {resp.status_code}: {resp.text}", file=sys.stderr)
            return 1
        comment_id = args.edit_comment_id or resp.json().get("id", "?")
        verb = "수정됨" if args.edit_comment_id else "게시됨"
        print(f"[완료] 코멘트 {verb} — id={comment_id}")
        print(f"       {jira_url}/browse/{args.ticket}?focusedCommentId={comment_id}")

    if transition_id:
        resp = requests.post(transition_endpoint, headers=headers, json={"transition": {"id": transition_id}}, timeout=30)
        if resp.status_code not in (200, 201, 204):
            print(f"[오류] 상태 전이 실패 {resp.status_code}: {resp.text}", file=sys.stderr)
            return 1
        msg = f"[완료] 상태 전이됨: {args.transition_name!r} -> {transition_to!r}"
        if developer_assignee:
            current = _get_assignee(jira_url, headers, args.ticket)
            if not current or current.get("name") != developer_assignee.get("name"):
                _set_assignee(jira_url, headers, args.ticket, developer_assignee["name"])
                msg += f" | 담당자 {developer_assignee['displayName']}(개발자)로 재할당됨(changelog 역추적)"
            else:
                msg += f" | 담당자 {developer_assignee['displayName']}(개발자) 유지됨"
        elif preserve_assignee and original_assignee:
            current = _get_assignee(jira_url, headers, args.ticket)
            if not current or current.get("name") != original_assignee.get("name"):
                _set_assignee(jira_url, headers, args.ticket, original_assignee["name"])
                msg += f" | 담당자 {original_assignee['displayName']}로 복원됨(워크플로 재할당 감지)"
            else:
                msg += f" | 담당자 {original_assignee['displayName']} 유지됨"
        print(msg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
