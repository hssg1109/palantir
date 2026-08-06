#!/usr/bin/env python3
"""
create_jira_ticket.py — 보안 진단 보고서 → Jira 태스크 자동 생성

사용법:
    python3 tools/create_jira_ticket.py --repo <repo> [--project <key>] [--dry-run] [--force]

필요 환경변수 (.env):
    JIRA_URL           = https://jira.company.com
    JIRA_EMAIL         = user@company.com   # Cloud: email+token Basic Auth
                                             # Server/DC: 빈값 → PAT Bearer 방식
    JIRA_TOKEN         = <API Token or PAT>
    JIRA_PROJECT_KEY   = OCBSEC             # 기본 프로젝트 키
    CONFLUENCE_BASE_URL = https://wiki.skplanet.com
    CONFLUENCE_TOKEN   = <Bearer Token>

Jira 이슈 구성:
    type     : Task (고정)
    priority : Major (고정)
    title    : 보고서 제목 (# 첫 줄)
    labels   : [repo명]
    description:
        - 상단: Confluence 위키 보고서 링크
        - 섹션 1: 진단 개요
        - 섹션 2: 취약점 요약 (2.1 개요 + 2.2 요약표)
        - 하단: 티켓 처리 가이드 (5개 안내)
    attachments: Confluence PDF export (실패 시 생략)
"""

import argparse
import io
import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.jira_utils import (
    load_env, jira_headers, cf_headers, load_repo_project_map,
    find_fortify_ticket, create_issue_link,
)

# ──────────────────────────────────────────────────────────────────────────────
# 경로 설정
# ──────────────────────────────────────────────────────────────────────────────

PALANTIR_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR     = PALANTIR_DIR / "logs"
DOCS_DIR     = PALANTIR_DIR / "docs"

_CF_REGISTRY = DOCS_DIR / ".confluence_pages.json"

# ──────────────────────────────────────────────────────────────────────────────
# 고정 텍스트
# ──────────────────────────────────────────────────────────────────────────────

_TICKET_GUIDE = """\
{panel:title=티켓 처리 가이드|borderStyle=solid|borderColor=#3b73af|titleBGColor=#3b73af|titleColor=#ffffff|bgColor=#f0f4ff}
*아래 순서대로 처리 부탁드립니다.*

|| 번호 || 처리 사항 ||
| (1) | +해당 서비스 담당자가 아닐 경우+, 담당 매니저를 comment에 남겨 주시기 바랍니다. |
| (2) | 각 취약점별 {color:red}*조치 계획*{color} 및 {color:red}*조치 일자*{color}를 위 취약점 요약표에 작성하여 comment로 답신 바랍니다. |
| (3) | +예외처리 요청+ 시, 서브티켓 생성 후 comment에 답신 바랍니다. |
| (4) | 취약점 상세 내용 및 조치 권고사항은 위 {color:blue}*위키 링크*{color} 또는 {color:blue}*첨부 보고서*{color}를 참고하시기 바랍니다. |
| (5) | 조치 완료 시 {color:green}*"이행 점검 요청"*{color} 상태로 변경 처리 바랍니다. |
{panel}\
"""


# ──────────────────────────────────────────────────────────────────────────────
# 파일/레지스트리 조회
# ──────────────────────────────────────────────────────────────────────────────

def _find_latest_report(repo: str) -> Path | None:
    files = sorted(LOGS_DIR.glob(f"final_{repo}_*.md"))
    return files[-1] if files else None


def _find_confluence_page_id(repo: str) -> str | None:
    if not _CF_REGISTRY.exists():
        return None
    reg = json.loads(_CF_REGISTRY.read_text(encoding="utf-8"))
    prefix = f"logs/final_{repo}_"
    matches = [(k, v) for k, v in reg.items() if k.startswith(prefix)]
    if not matches:
        return None
    matches.sort(key=lambda x: x[0], reverse=True)
    return str(matches[0][1])


# ──────────────────────────────────────────────────────────────────────────────
# 마크다운 파싱 및 변환
# ──────────────────────────────────────────────────────────────────────────────

def _extract_sections_1_2(md_text: str) -> str:
    """## 1. 진단 개요 + ## 2.2 취약점 요약 표만 추출 (### 2.1 개요 제외)."""
    lines = md_text.splitlines()
    result = []
    in_target = False
    skip_21 = False
    for line in lines:
        if re.match(r"^## [12]\.", line):
            in_target = True
            skip_21 = False
        elif in_target and re.match(r"^## [3-9]", line):
            break
        # 2.1 취약점 개요 섹션 시작 → 스킵
        if in_target and re.match(r"^### 2\.1", line):
            skip_21 = True
        # 2.2 이후 subsection 도달 → 스킵 해제
        if skip_21 and re.match(r"^### 2\.[2-9]", line):
            skip_21 = False
        if in_target and not skip_21:
            result.append(line)
    return "\n".join(result)


def _md_to_jira_wiki(text: str) -> str:
    """Markdown → Jira Wiki markup 변환."""
    lines = text.splitlines()
    out = []
    i = 0
    in_summary_table = False  # 취약점 요약표 추적 (조치 계획/일자 열 추가 대상)

    while i < len(lines):
        line = lines[i]

        # Confluence {/color} → Jira {color} (닫기 태그 변환)
        # Jira 네이티브: {color:red}텍스트{color} — {/color} 는 Confluence 전용
        line = line.replace("{/color}", "{color}")

        # :::expand 블록 — 제목 줄만 제거
        if re.match(r"^:::", line):
            in_summary_table = False
            i += 1
            continue

        # 마크다운 구분선 (|---|---|) 스킵
        if re.match(r"^\|[\s\-:|]+\|$", line):
            i += 1
            continue

        # 제목 — Jira 헤딩으로 변환 (섹션 번호 원본 유지)
        if re.match(r"^#### ", line):
            line = "h4. " + line[5:]
            in_summary_table = False
        elif re.match(r"^### ", line):
            line = "h3. " + line[4:]
            in_summary_table = False
        elif re.match(r"^## ", line):
            line = "h2. " + line[3:]
            in_summary_table = False
        elif re.match(r"^# ", line):
            line = "h1. " + line[2:]
            in_summary_table = False

        # 마크다운 표 → Jira 표
        elif line.startswith("|"):
            is_header = (i + 1 < len(lines)) and re.match(r"^\|[\s\-:|]+\|$", lines[i + 1])
            cells = [c.strip() for c in line.split("|")[1:-1]]
            # 셀 내 **bold** 처리
            cells = [re.sub(r"\*\*(.+?)\*\*", r"*\1*", c) for c in cells]
            # 셀 내 `code` 처리
            cells = [re.sub(r"`([^`]+)`", r"{{\1}}", c) for c in cells]

            if is_header and "Sub_No" in cells:
                # 취약점 요약표 헤더 — "조치 계획" / "조치 일자" 열 추가
                in_summary_table = True
                cells += ["조치 계획", "조치 일자"]
                line = "|| " + " || ".join(cells) + " ||"
            elif is_header:
                in_summary_table = False
                line = "|| " + " || ".join(cells) + " ||"
            else:
                if in_summary_table:
                    cells += ["", ""]  # 데이터 행에 빈 열 2개 추가
                line = "| " + " | ".join(cells) + " |"

            out.append(line)
            i += 1
            continue
        else:
            if line.strip():
                in_summary_table = False

        # 인라인 변환 (표 외부)
        line = re.sub(r"\*\*(.+?)\*\*", r"*\1*", line)   # **bold** → *bold*
        line = re.sub(r"`([^`]+)`", r"{{\1}}", line)       # `code` → {{code}}
        line = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"[\1|\2]", line)  # [text](url) → [text|url]

        out.append(line)
        i += 1

    result = re.sub(r"\n{3,}", "\n\n", "\n".join(out))
    return result.strip()


_COMMENT_EXAMPLE = """\
{panel:title=조치 회신 comment 예시|borderStyle=dashed|borderColor=#f6c342|titleBGColor=#fff7d6|bgColor=#fffef0}
아래와 같이 각 취약점의 {color:red}*조치 계획*{color} 및 {color:red}*조치 일자*{color}를 작성하여 comment로 답신 바랍니다.

|| Sub_No || 결과 || 위험도 || 제목 || 분류 || 파일:라인 || 조치 요약 || 조치 계획 || 조치 일자 ||
| 1-1 | 취약 | High | SQL Injection — 로그인 파라미터 미검증 | SQL Injection | UserService.java:42 | PreparedStatement 미적용 | UserService.java 42번 라인 쿼리에 PreparedStatement 적용하여 파라미터 바인딩 방식으로 변경 조치하겠음 | 2026-07-31 |
{panel}\
"""


def _build_comment_example(sections_wiki: str) -> str:  # noqa: ARG001
    return _COMMENT_EXAMPLE


def _build_description(cf_page_url: str, sections_wiki: str) -> str:
    parts = [sections_wiki]
    _sp = "{color:#ffffff}.{color}"
    parts += [_sp, _sp, "----", "----", _sp, _sp]
    if cf_page_url:
        parts.append(f"h4. 자세한 내용 참고 — [위키 보고서|{cf_page_url}] 또는 첨부(pdf)")
        parts.append(_sp)
    parts.append(_TICKET_GUIDE)
    comment_example = _build_comment_example(sections_wiki)
    if comment_example:
        parts.append(_sp)
        parts.append(comment_example)
    return "\n".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
# Jira API 호출
# ──────────────────────────────────────────────────────────────────────────────

def _check_existing(env: dict, jira_url: str, project: str, repo: str) -> str | None:
    """동일 레포의 기존 Task 티켓 키 반환. 없으면 None."""
    jql = (
        f'project = "{project}" AND issuetype = Task '
        f'AND labels = "{repo}" ORDER BY created DESC'
    )
    try:
        resp = requests.get(
            f"{jira_url}/rest/api/2/search",
            headers=jira_headers(env),
            params={"jql": jql, "maxResults": 1, "fields": "summary,key"},
            timeout=15,
        )
        if resp.status_code == 200 and resp.json().get("total", 0) > 0:
            return resp.json()["issues"][0]["key"]
    except requests.exceptions.ConnectionError as e:
        print(f"[ERROR] Jira 연결 실패: {e}")
        sys.exit(1)
    return None


def _create_issue(
    env: dict,
    jira_url: str,
    project: str,
    summary: str,
    description: str,
    repo: str,
    dry_run: bool,
    assignee: str | None = None,
    remediation_date: str | None = None,
    extra_labels: list[str] | None = None,
) -> str | None:
    labels = [repo] + [l for l in (extra_labels or []) if l and l not in (repo,)]
    fields: dict = {
        "project":     {"key": project},
        "summary":     summary,
        "issuetype":   {"name": "Task"},
        "priority":    {"name": "Major"},
        "labels":      labels,
        "description": description,
    }
    # 커스텀 필드 "조치기한" — .env JIRA_REMEDIATION_DATE_FIELD_ID 가 있을 때만 사용
    remediation_field_id = env.get("JIRA_REMEDIATION_DATE_FIELD_ID", "").strip()
    if remediation_date and remediation_field_id:
        fields[remediation_field_id] = remediation_date
    if assignee:
        fields["assignee"] = {"name": assignee}   # Server/DC: name 필드 사용
    fields["reporter"] = {"name": "pc10315"}
    payload = {"fields": fields}

    if dry_run:
        print("\n[DRY-RUN] 생성될 Jira 이슈 payload (description 일부 생략):")
        preview = {**payload, "fields": {**payload["fields"], "description": description[:300] + " ..."}}
        print(json.dumps(preview, ensure_ascii=False, indent=2))
        return "DRY-RUN-KEY"

    resp = requests.post(
        f"{jira_url}/rest/api/2/issue",
        headers=jira_headers(env),
        json=payload,
        timeout=30,
    )
    if resp.status_code in (200, 201):
        key = resp.json()["key"]
        print(f"[OK] 이슈 생성 완료: {key}")
        return key

    print(f"[ERROR] 이슈 생성 실패 (HTTP {resp.status_code})")
    try:
        err = resp.json()
        print(json.dumps(err, ensure_ascii=False, indent=2)[:800])
    except Exception:
        print(resp.text[:500])
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Confluence PDF 추출 및 Jira 첨부
# ──────────────────────────────────────────────────────────────────────────────

def _export_confluence_pdf(env: dict, page_id: str) -> bytes | None:
    """
    Confluence Server/DC PDF export.
    1단계: pdfpageexport.action → 직접 PDF 또는 중간 HTML 반환
    2단계: HTML 내 /download/temp/ 경로 파싱 → 실제 PDF 다운로드
    """
    cf_base = env.get("CONFLUENCE_BASE_URL", "").rstrip("/")
    hdrs = {**cf_headers(env), "Accept": "application/pdf,text/html;q=0.9,*/*;q=0.8"}

    for endpoint in [
        f"{cf_base}/spaces/flyingpdf/pdfpageexport.action?pageId={page_id}",
        f"{cf_base}/spaces/flyingpdf/flyingpdf.action?pageId={page_id}",
    ]:
        try:
            resp = requests.get(endpoint, headers=hdrs, timeout=90, allow_redirects=True)
            ct = resp.headers.get("Content-Type", "")

            if resp.status_code == 200 and "pdf" in ct.lower():
                print(f"[INFO] PDF 직접 수신 ({len(resp.content):,} bytes)")
                return resp.content

            if resp.status_code == 200 and "html" in ct.lower():
                # Confluence가 중간 HTML 페이지 반환 — PDF 다운로드 경로 추출
                html = resp.text
                # 패턴 1: <meta http-equiv="Refresh" content="0; URL=/download/temp/...">
                m = re.search(r'URL=(/[^"\'<\s]*\.pdf[^"\'<\s]*)', html, re.IGNORECASE)
                if not m:
                    # 패턴 2: href="/download/..."
                    m = re.search(r'href="(/download/[^"\'<\s]+)"', html, re.IGNORECASE)
                if not m:
                    # 패턴 3: /download/temp/ 경로 (확장자 무관)
                    m = re.search(r'(/download/temp/[^"\'<\s?#]+)', html)

                if m:
                    pdf_url = cf_base + m.group(1)
                    print(f"[INFO] PDF redirect URL: {pdf_url}")
                    pdf_resp = requests.get(pdf_url, headers=hdrs, timeout=90, allow_redirects=True)
                    pdf_ct = pdf_resp.headers.get("Content-Type", "")
                    if pdf_resp.status_code == 200 and "pdf" in pdf_ct.lower():
                        print(f"[INFO] PDF 수신 완료 ({len(pdf_resp.content):,} bytes)")
                        return pdf_resp.content
                    print(f"[WARN] PDF redirect 실패 — HTTP {pdf_resp.status_code}, CT: {pdf_ct}")
                else:
                    # 디버그: HTML 앞부분 출력해서 패턴 파악
                    snippet = html[:500].replace("\n", " ")
                    print(f"[DEBUG] HTML snippet: {snippet}")

            else:
                print(f"[WARN] PDF endpoint 응답 — HTTP {resp.status_code}, CT: {ct}")

        except Exception as e:
            print(f"[WARN] PDF 추출 오류 ({endpoint}): {e}")

    print("[WARN] PDF 추출 실패 — 위키 링크로 대체됩니다.")
    return None


def _attach_pdf(env: dict, jira_url: str, issue_key: str, pdf_bytes: bytes, filename: str) -> bool:
    # Content-Type 헤더 제외 (multipart가 자동 설정)
    headers = {k: v for k, v in jira_headers(env).items() if k.lower() != "content-type"}
    headers["X-Atlassian-Token"] = "no-check"
    resp = requests.post(
        f"{jira_url}/rest/api/2/issue/{issue_key}/attachments",
        headers=headers,
        files={"file": (filename, io.BytesIO(pdf_bytes), "application/pdf")},
        timeout=60,
    )
    if resp.status_code in (200, 201):
        print(f"[OK] PDF 첨부 완료: {filename}")
        return True
    print(f"[WARN] PDF 첨부 실패 (HTTP {resp.status_code})")
    return False


# ──────────────────────────────────────────────────────────────────────────────
# main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="보안 진단 보고서 → Jira Task 생성")
    parser.add_argument("--repo",      required=True, help="레포 이름 (예: ocb-event-front)")
    parser.add_argument("--project",   help="Jira 프로젝트 키 (기본: .env JIRA_PROJECT_KEY)")
    parser.add_argument("--assignee",  default="pp61341", help="Jira 담당자 username (기본: pp61341)")
    parser.add_argument("--remediation-date", default=None,
                        help="조치기한 YYYY-MM-DD (기본: 공란 — 개발팀 확정 후 입력)")
    parser.add_argument("--due-days",  type=int, default=None,
                        help="오늘로부터 N일 후를 조치기한으로 설정")
    parser.add_argument("--dry-run",   action="store_true", help="실제 생성 없이 payload 출력")
    parser.add_argument("--force",     action="store_true", help="중복 티켓 있어도 새로 생성")
    args = parser.parse_args()

    env      = load_env()
    jira_url = env.get("JIRA_URL", "").rstrip("/")
    project  = args.project or env.get("JIRA_PROJECT_KEY", "")

    if not jira_url:
        print("[ERROR] .env에 JIRA_URL이 없습니다.")
        sys.exit(1)
    if not project:
        print("[ERROR] .env에 JIRA_PROJECT_KEY가 없거나 --project 미지정.")
        sys.exit(1)
    if not env.get("JIRA_TOKEN"):
        print("[ERROR] .env에 JIRA_TOKEN이 없습니다.")
        sys.exit(1)

    # ── 1. 보고서 파일 ────────────────────────────────────────────────────────
    report_path = _find_latest_report(args.repo)
    if not report_path:
        print(f"[ERROR] 보고서 없음 — logs/final_{args.repo}_*.md")
        sys.exit(1)
    print(f"[INFO] 보고서: {report_path.name}")
    md_text = report_path.read_text(encoding="utf-8")

    # ── 2. Confluence page ID / URL ───────────────────────────────────────────
    page_id = _find_confluence_page_id(args.repo)
    if page_id:
        cf_base     = env.get("CONFLUENCE_BASE_URL", "").rstrip("/")
        cf_page_url = f"{cf_base}/pages/viewpage.action?pageId={page_id}"
        print(f"[INFO] Confluence: {cf_page_url}")
    else:
        cf_page_url = ""
        print(f"[WARN] Confluence page ID 없음 — 링크 없이 진행")

    # ── 3. 보고서 제목 ────────────────────────────────────────────────────────
    title_match = re.match(r"^# (.+)", md_text)
    title = title_match.group(1).strip() if title_match else f"{args.repo}-진단결과"

    # ── 4. 섹션 1+2 추출 → Jira markup 변환 ──────────────────────────────────
    sections_md   = _extract_sections_1_2(md_text)
    sections_wiki = _md_to_jira_wiki(sections_md)

    # ── 5. description 조립 ───────────────────────────────────────────────────
    description = _build_description(cf_page_url, sections_wiki)

    # ── 6. 중복 체크 ──────────────────────────────────────────────────────────
    if not args.dry_run:
        existing_key = _check_existing(env, jira_url, project, args.repo)
        if existing_key and not args.force:
            print(f"[WARN] 기존 티켓 발견: {jira_url}/browse/{existing_key}")
            print("       재생성하려면 --force 옵션을 추가하세요.")
            sys.exit(0)
        if existing_key and args.force:
            print(f"[INFO] --force 모드 — 기존 티켓 {existing_key}가 있음에도 신규 생성합니다.")

    # ── 7. 조치기한 결정 ──────────────────────────────────────────────────────
    remediation_field_id = env.get("JIRA_REMEDIATION_DATE_FIELD_ID", "").strip()
    if args.remediation_date:
        remediation_date = args.remediation_date
    elif args.due_days is not None:
        remediation_date = (date.today() + timedelta(days=args.due_days)).strftime("%Y-%m-%d")
    else:
        remediation_date = None  # 기본 공란 — 조치 일자 확정 후 수동 입력

    if not remediation_field_id:
        print("[WARN] .env에 JIRA_REMEDIATION_DATE_FIELD_ID 없음 — 조치기한 필드 생략")
        print("       최초 1회: python3 tools/setup_jira_custom_field.py")
    elif remediation_date:
        print(f"[INFO] 조치기한: {remediation_date}  ({remediation_field_id})")
    else:
        print(f"[INFO] 조치기한: (공란 — 개발팀 조치 일자 확정 후 입력)  ({remediation_field_id})")

    # ── 8. 이슈 생성 ──────────────────────────────────────────────────────────
    print(f"[INFO] 담당자: {args.assignee}")
    repo_project_map = load_repo_project_map()
    project_key_label = repo_project_map.get(args.repo)
    if project_key_label:
        print(f"[INFO] 프로젝트 키 라벨: {project_key_label}")
    else:
        print(f"[WARN] docs/ocb_scan_plan.md §2 에서 프로젝트 키 매핑을 찾지 못함 — repo 라벨만 부여")
    issue_key = _create_issue(
        env, jira_url, project, title, description, args.repo, args.dry_run,
        assignee=args.assignee, remediation_date=remediation_date,
        extra_labels=[project_key_label] if project_key_label else None,
    )
    if not issue_key or args.dry_run:
        return

    # ── 8-1. Fortify 정기진단 이력 연동 (issue link) ─────────────────────────
    if project_key_label:
        fortify_key = find_fortify_ticket(env, jira_url, project_key_label, args.repo)
        if fortify_key:
            if create_issue_link(env, jira_url, issue_key, fortify_key):
                print(f"[OK] Fortify 이력 연동: {issue_key} <-> {fortify_key}")
            else:
                print(f"[WARN] Fortify 이력 연동 실패 — {issue_key} <-> {fortify_key} issue link 생성 안됨")
        else:
            print(f"[INFO] Fortify 정기진단 이력 없음 — {project_key_label}/{args.repo}")

    # ── 9. PDF 첨부 ───────────────────────────────────────────────────────────
    if page_id:
        print("[INFO] Confluence PDF 추출 시도...")
        pdf_bytes = _export_confluence_pdf(env, page_id)
        if pdf_bytes:
            filename = f"{args.repo}_보안진단보고서.pdf"
            _attach_pdf(env, jira_url, issue_key, pdf_bytes, filename)
        else:
            print("[INFO] PDF 첨부 생략 — 위키 링크로 대체됩니다.")

    # ── 10. 완료 ──────────────────────────────────────────────────────────────
    print(f"\n{'='*50}")
    print(f"  Jira 티켓: {jira_url}/browse/{issue_key}")
    if remediation_date:
        print(f"  조치기한:  {remediation_date}")
    if cf_page_url:
        print(f"  위키 링크: {cf_page_url}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
