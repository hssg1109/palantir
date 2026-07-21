#!/usr/bin/env python3
"""
fetch_jira_remediation_targets.py — 이행점검 대상 Jira 티켓 파싱

/sec-remediation-check skill의 Phase 0 담당 스크립트.
Jira Task 티켓(create_jira_ticket.py가 발행한 형식)의 description에서
"2.2 취약점 요약 표"를 파싱하고, comment에 개발자가 남긴 조치회신 표가
있으면 함께 병합해 이행점검 대상 목록(targets.json)을 만든다.

사용법:
    python3 shared/scripts/fetch_jira_remediation_targets.py --ticket <KEY> [--dry-run]

필요 환경변수(.env)는 tools/create_jira_ticket.py와 동일 (JIRA_URL, JIRA_TOKEN, ...).

출력: state/<repo>/remediation/<TICKET-KEY>/targets.json
  {
    "ticket": "OCBSEC-1234",
    "repo": "ocb-example",
    "status": "이행 점검 요청",
    "fetched_at": "...",
    "targets": [
      {
        "sub_no": "1-1",
        "result": "취약",
        "severity": "High",
        "title": "...",
        "category": "SQL Injection",
        "file_line": "UserService.java:42",
        "remediation_summary": "...",
        "dev_reply": {"조치 계획": "...", "조치 일자": "..."} | null
      },
      ...
    ]
  }
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import requests

PALANTIR_DIR = Path(__file__).resolve().parent.parent.parent
STATE_DIR    = PALANTIR_DIR / "state"

sys.path.insert(0, str(PALANTIR_DIR))
from tools.jira_utils import load_env, jira_headers


# ──────────────────────────────────────────────────────────────────────────────
# Jira 조회
# ──────────────────────────────────────────────────────────────────────────────

def _fetch_issue(env: dict, jira_url: str, ticket: str) -> dict:
    resp = requests.get(
        f"{jira_url}/rest/api/2/issue/{ticket}",
        headers=jira_headers(env),
        params={"fields": "summary,description,labels,status,comment"},
        timeout=20,
    )
    if resp.status_code != 200:
        print(f"[ERROR] 티켓 조회 실패 ({ticket}) — HTTP {resp.status_code}")
        try:
            print(json.dumps(resp.json(), ensure_ascii=False, indent=2)[:500])
        except Exception:
            print(resp.text[:500])
        sys.exit(1)
    return resp.json()


# ──────────────────────────────────────────────────────────────────────────────
# Jira wiki 표 파싱
# ──────────────────────────────────────────────────────────────────────────────

def _split_header_cells(line: str) -> list[str]:
    """'|| A || B || C ||' → ['A', 'B', 'C']"""
    body = line.strip()
    if body.startswith("||"):
        body = body[2:]
    if body.endswith("||"):
        body = body[:-2]
    return [c.strip() for c in body.split("||")]


def _split_data_cells(line: str) -> list[str]:
    """'| a | b | c |' → ['a', 'b', 'c']"""
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|"):
        body = body[:-1]
    return [c.strip() for c in body.split("|")]


def _find_wiki_tables(text: str, header_marker: str) -> list[tuple[list[str], list[list[str]]]]:
    """header_marker가 포함된 Jira wiki 표(|| ... ||)를 모두 찾아 (headers, rows) 리스트로 반환."""
    lines = text.splitlines()
    tables: list[tuple[list[str], list[list[str]]]] = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("||") and header_marker in line:
            headers = _split_header_cells(line)
            rows: list[list[str]] = []
            i += 1
            while i < len(lines) and lines[i].strip().startswith("|") and not lines[i].strip().startswith("||"):
                cells = _split_data_cells(lines[i])
                if len(cells) == len(headers):
                    rows.append(cells)
                i += 1
            tables.append((headers, rows))
        else:
            i += 1
    return tables


def _clean_cell_text(raw: str) -> str:
    text = html.unescape(raw)
    text = text.replace("\xa0", " ")
    return re.sub(r"\s+", " ", text).strip()


class _HtmlTableExtractor(HTMLParser):
    """Jira가 description/comment를 렌더링된 HTML(<table class="confluenceTable">)로
    반환하는 인스턴스 대응용 — <table> 블록을 (is_header_row, cells) 리스트로 추출."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[tuple[bool, list[str]]]] = []
        self._in_table = False
        self._in_row = False
        self._in_cell = False
        self._row_is_header = False
        self._cur_table: list[tuple[bool, list[str]]] = []
        self._cur_row: list[str] = []
        self._cell_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self._in_table = True
            self._cur_table = []
        elif tag == "tr" and self._in_table:
            self._in_row = True
            self._cur_row = []
            self._row_is_header = False
        elif tag in ("td", "th") and self._in_row:
            self._in_cell = True
            self._cell_parts = []
            if tag == "th":
                self._row_is_header = True

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th") and self._in_cell:
            self._cur_row.append(_clean_cell_text("".join(self._cell_parts)))
            self._in_cell = False
        elif tag == "tr" and self._in_row:
            if self._cur_row:
                self._cur_table.append((self._row_is_header, self._cur_row))
            self._in_row = False
        elif tag == "table" and self._in_table:
            self._in_table = False
            if self._cur_table:
                self.tables.append(self._cur_table)

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            self._cell_parts.append(data)


def _find_html_tables(text: str, header_marker: str) -> list[tuple[list[str], list[list[str]]]]:
    if "<table" not in text:
        return []
    parser = _HtmlTableExtractor()
    try:
        parser.feed(text)
    except Exception:
        return []
    result: list[tuple[list[str], list[list[str]]]] = []
    for table_rows in parser.tables:
        if not table_rows:
            continue
        header_idx = next((i for i, (is_h, _) in enumerate(table_rows) if is_h), 0)
        headers = table_rows[header_idx][1]
        if header_marker not in headers:
            continue
        data_rows = [cells for i, (_, cells) in enumerate(table_rows) if i != header_idx]
        norm_rows = [r for r in data_rows if len(r) == len(headers)]
        result.append((headers, norm_rows))
    return result


def _find_tables(text: str, header_marker: str = "Sub_No") -> list[tuple[list[str], list[list[str]]]]:
    """header_marker가 포함된 표를 모두 찾아 (headers, rows) 리스트로 반환.

    Jira wiki 마크업(|| ... ||)을 우선 탐색하고, 없으면 렌더링된 HTML(<table>)로 폴백한다 —
    Jira 인스턴스에 따라 description/comment 필드가 원본 wiki 텍스트가 아니라 렌더링된
    HTML로 반환되는 경우가 있다 (예: SECUFINDINGS-2132에서 confluenceTable로 확인됨).
    """
    if not text:
        return []
    wiki_tables = _find_wiki_tables(text, header_marker)
    if wiki_tables:
        return wiki_tables
    return _find_html_tables(text, header_marker)


def _rows_to_dicts(headers: list[str], rows: list[list[str]]) -> list[dict]:
    return [dict(zip(headers, row)) for row in rows]


# ──────────────────────────────────────────────────────────────────────────────
# targets 조립
# ──────────────────────────────────────────────────────────────────────────────

# create_jira_ticket.py의 _COMMENT_EXAMPLE에 박혀있는 더미 예시 행 — 실제 티켓에도 그대로
# 렌더링되어 남을 수 있어 target으로 오인하지 않도록 시그니처로 걸러낸다.
_EXAMPLE_TITLE     = "SQL Injection — 로그인 파라미터 미검증"
_EXAMPLE_FILE_LINE = "UserService.java:42"


def _extract_original_targets(description: str) -> dict[str, dict]:
    """description의 2.2 요약표(Sub_No/결과/위험도/제목/분류/파일:라인/조치 요약[/조치 계획/조치 일자]) 파싱.

    Jira 인스턴스에 따라 조치 계획/조치 일자 열이 이미 description 표에 병합되어(개발자가
    comment 대신 표를 직접 수정) 채워져 있는 경우가 있어, 그 값도 dev_reply로 함께 추출한다.
    """
    tables = _find_tables(description, header_marker="Sub_No")
    result: dict[str, dict] = {}
    for headers, rows in tables:
        # 원본 target 표의 구조적 시그니처 — 분류/파일:라인이 없으면 진단 요약표가 아님
        if "분류" not in headers or "파일:라인" not in headers:
            continue
        for d in _rows_to_dicts(headers, rows):
            sub_no = d.get("Sub_No", "").strip()
            if not sub_no:
                continue
            title     = d.get("제목", "")
            file_line = d.get("파일:라인", "")
            if title == _EXAMPLE_TITLE and file_line.strip() == _EXAMPLE_FILE_LINE:
                continue  # _COMMENT_EXAMPLE 더미 행 — 실제 target 아님

            dev_reply = None
            plan       = d.get("조치 계획", "").strip()
            fixed_date = d.get("조치 일자", "").strip()
            if plan or fixed_date:
                dev_reply = {
                    "조치 계획":        plan,
                    "조치 일자":        fixed_date,
                    "comment_author":  "",
                    "comment_created": "",
                    "source":          "description_table",
                }

            result[sub_no] = {
                "sub_no":               sub_no,
                "result":               d.get("결과", ""),
                "severity":             d.get("위험도", ""),
                "title":                title,
                "category":             d.get("분류", ""),
                "file_line":            file_line,
                "remediation_summary":  d.get("조치 요약", ""),
                "dev_reply":            dev_reply,
            }
    return result


def _extract_dev_replies(comments: list[dict]) -> dict[str, dict]:
    """comment 중 조치 계획/조치 일자 열이 포함된 회신 표를 파싱 (있는 comment만)."""
    replies: dict[str, dict] = {}
    for c in comments:
        body = c.get("body", "")
        tables = _find_tables(body, header_marker="Sub_No")
        for headers, rows in tables:
            if "조치 계획" not in headers:
                continue
            for d in _rows_to_dicts(headers, rows):
                sub_no = d.get("Sub_No", "").strip()
                if not sub_no:
                    continue
                replies[sub_no] = {
                    "조치 계획": d.get("조치 계획", ""),
                    "조치 일자": d.get("조치 일자", ""),
                    "comment_author":  (c.get("author") or {}).get("displayName", ""),
                    "comment_created": c.get("created", ""),
                }
    return replies


def _resolve_repo(labels: list[str]) -> str:
    """create_jira_ticket.py는 labels=[repo, ...기타 태그]로 발행하지만 순서를 보장하지
    않는 인스턴스가 있어(labels[0]이 스프린트/분류 태그인 경우 확인됨 — SECUFINDINGS-2132),
    기존에 진단 이력이 있는 state/<label>/ 디렉터리와 매칭되는 라벨을 우선한다."""
    for label in labels:
        if (STATE_DIR / label).is_dir():
            return label
    return labels[0] if labels else ""


def build_targets(issue: dict) -> dict:
    fields = issue.get("fields", {})
    labels = fields.get("labels", []) or []
    repo   = _resolve_repo(labels)
    status = (fields.get("status") or {}).get("name", "")
    description = fields.get("description", "") or ""
    comments = ((fields.get("comment") or {}).get("comments")) or []

    targets_by_sub_no = _extract_original_targets(description)
    if not targets_by_sub_no:
        print("[경고] description에서 '2.2 취약점 요약 표'(Sub_No 헤더)를 찾지 못했습니다.")

    dev_replies = _extract_dev_replies(comments)
    for sub_no, reply in dev_replies.items():
        if sub_no in targets_by_sub_no:
            targets_by_sub_no[sub_no]["dev_reply"] = reply

    targets = sorted(targets_by_sub_no.values(), key=lambda t: t["sub_no"])

    return {
        "ticket":     issue.get("key", ""),
        "repo":       repo,
        "status":     status,
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "targets":    targets,
    }


# ──────────────────────────────────────────────────────────────────────────────
# main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(prog="fetch_jira_remediation_targets.py")
    parser.add_argument("--ticket",  required=True, help="Jira 티켓 키 (예: OCBSEC-1234)")
    parser.add_argument("--output",  help="결과 파일 경로 (미지정 시 state/<repo>/remediation/<ticket>/targets.json)")
    parser.add_argument("--dry-run", action="store_true", help="파일로 저장하지 않고 stdout에만 출력")
    args = parser.parse_args()

    env      = load_env()
    jira_url = env.get("JIRA_URL", "").rstrip("/")
    if not jira_url:
        print("[ERROR] .env에 JIRA_URL이 없습니다.")
        sys.exit(1)
    if not env.get("JIRA_TOKEN"):
        print("[ERROR] .env에 JIRA_TOKEN이 없습니다.")
        sys.exit(1)

    print(f"[이행점검] 티켓 조회: {args.ticket}")
    issue = _fetch_issue(env, jira_url, args.ticket)
    result = build_targets(issue)

    if not result["repo"]:
        print("[경고] 티켓 labels에서 repo명을 찾지 못했습니다 — targets.json의 repo 필드가 빈 값입니다.")

    n = len(result["targets"])
    n_reply = sum(1 for t in result["targets"] if t["dev_reply"])
    print(f"[이행점검] 대상 {n}건 파싱 완료 (개발자 회신 있음: {n_reply}건, 없음: {n - n_reply}건)")

    print(json.dumps(result, ensure_ascii=False, indent=2))

    if args.dry_run:
        return

    if not result["repo"]:
        print("[ERROR] repo명을 확인할 수 없어 파일로 저장할 수 없습니다. --output으로 경로를 직접 지정하세요.")
        sys.exit(1)

    out_path = Path(args.output) if args.output else (
        STATE_DIR / result["repo"] / "remediation" / result["ticket"] / "targets.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[이행점검] 저장 완료 → {out_path}")


if __name__ == "__main__":
    main()
