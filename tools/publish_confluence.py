#!/usr/bin/env python3
"""
publish_confluence.py — 마크다운 문서를 Confluence 페이지로 게시/갱신합니다.

사용법:
    # 신규 생성 (--parent 지정)
    python3 tools/publish_confluence.py docs/ocb_scan_plan.md \
        --title "OCB 서비스 군 보안 진단 계획" \
        --parent 722832415

    # 기존 페이지 갱신 (page_id 레지스트리 자동 참조)
    python3 tools/publish_confluence.py docs/ocb_scan_plan.md

    # 강제 page_id 지정 갱신
    python3 tools/publish_confluence.py docs/ocb_scan_plan.md --page-id 123456789

환경변수 (.env):
    CONFLUENCE_BASE_URL  = https://wiki.skplanet.com
    CONFLUENCE_TOKEN     = ...  (Personal Access Token — Bearer 방식)

레지스트리:
    docs/.confluence_pages.json — {md_path: page_id} 매핑 로컬 저장
    게시 성공 시 자동 업데이트.

네트워크:
    wiki.skplanet.com은 사내망만 접근 가능 → Windows PowerShell 경유 실행.
    WSL에서 실행 시 powershell.exe를 자동으로 호출합니다.
"""

import argparse
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

PALANTIR_DIR = Path(__file__).parent.parent
REGISTRY_PATH = PALANTIR_DIR / "docs" / ".confluence_pages.json"

_ENV_PATH = PALANTIR_DIR / ".env"

# Jira 매크로 상수 (SKP 내부 Jira Application Link)
_JIRA_SERVER_NAME = "Jira"
_JIRA_SERVER_ID   = "66c70ce4-eb7d-3ce9-8070-9705b6b477fa"


def _load_env() -> dict:
    env: dict = {}
    if _ENV_PATH.exists():
        for line in _ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    return env


# ── 마크다운 → Confluence Storage Format (XHTML) ─────────────────────────────

# Confluence code macro가 인식하는 언어 값 목록 (InvalidValueException 방지)
# 2026-07-16: 사내 Confluence 인스턴스에서 "go"/"json"/"latex"/"tex"가 실제로는
# InvalidValueException을 유발함을 확인 (rest/api/contentbody/convert/view로 검증) — 제외.
_CF_VALID_LANGS = {
    "none", "java", "javascript", "sql", "xml", "bash", "python", "ruby",
    "php", "html", "css", "groovy", "scala", "yaml", "powershell",
    "perl", "c", "cpp", "vb", "actionscript", "applescript",
    "delphi", "erlang",
}
_CF_LANG_MAP = {
    "js":         "javascript",
    "ts":         "javascript",
    "typescript": "javascript",
    "tsx":        "javascript",
    "jsx":        "javascript",
    "kotlin":     "java",
    "kt":         "java",
    "py":         "python",
    "sh":         "bash",
    "shell":      "bash",
    "zsh":        "bash",
    "yml":        "yaml",
    "json":       "javascript",  # 이 인스턴스는 "json" 값 자체를 거부함 — js 하이라이터로 대체
    "text":       "none",
    "plain":      "none",
    "plaintext":  "none",
    "":           "none",
}


def _normalize_code_lang(lang: str) -> str:
    """마크다운 언어 태그를 Confluence code macro 허용 값으로 변환."""
    lang = lang.lower().strip()
    lang = _CF_LANG_MAP.get(lang, lang)
    return lang if lang in _CF_VALID_LANGS else "none"


def md_to_confluence(md: str) -> str:
    """
    마크다운을 Confluence Storage Format(XHTML)으로 변환.
    지원: 헤딩, 표, 코드블록, 체크박스(task), 목록, 굵기, 인라인코드, 수평선.
    """
    lines = md.splitlines()
    out: list[str] = []
    i = 0

    def _inline(text: str) -> str:
        # 1. 인라인 코드 및 Jira 매크로를 플레이스홀더로 먼저 교체 (XML 이스케이프 방지)
        code_spans: list[str] = []
        def _stash_code(m: re.Match) -> str:
            idx = len(code_spans)
            inner = m.group(1).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            code_spans.append(f'<code>{inner}</code>')
            return f'\x00CODE{idx}\x00'
        def _stash_jira(m: re.Match) -> str:
            key = m.group(1)
            idx = len(code_spans)
            code_spans.append(
                f'<ac:structured-macro ac:name="jira" ac:schema-version="1"'
                f' ac:macro-id="{uuid.uuid4()}">'
                f'<ac:parameter ac:name="server">{_JIRA_SERVER_NAME}</ac:parameter>'
                f'<ac:parameter ac:name="serverId">{_JIRA_SERVER_ID}</ac:parameter>'
                f'<ac:parameter ac:name="key">{key}</ac:parameter>'
                f'</ac:structured-macro>'
            )
            return f'\x00CODE{idx}\x00'
        text = re.sub(r'\[JIRA:([A-Z]+-\d+)\]', _stash_jira, text)
        text = re.sub(r'`([^`]+)`', _stash_code, text)
        # 2. XML 특수문자 이스케이프 (코드 스팬 제외한 나머지)
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;').replace('>', '&gt;')
        # 3. 굵기+기울임 (*** 3중 asterisk) — 반드시 ** / * 보다 먼저 처리해야 함
        # ***text*** → <strong><em>text</em></strong> 올바른 중첩 보장
        # ** 먼저 처리하면 ***X***가 <strong>*X</strong>* 로 분리되어 태그 역전 발생
        text = re.sub(r'\*{3}(.+?)\*{3}', r'<strong><em>\1</em></strong>', text)
        # 4. 굵기
        text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
        # 5. 기울임
        text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
        # 6. 링크 [text](url)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)',
                      r'<a href="\2">\1</a>', text)
        # 7. 색상 태그 {color:X}text{/color} → <span style="color:X">
        text = re.sub(r'\{color:([^}]+)\}(.*?)\{/color\}',
                      r'<span style="color:\1">\2</span>', text, flags=re.DOTALL)
        # 7. 플레이스홀더 복원
        for idx, span in enumerate(code_spans):
            text = text.replace(f'\x00CODE{idx}\x00', span)
        return text

    def _td_cell(cell: str) -> str:
        """테이블 셀 변환. {bg:#RRGGBB}content 패턴이면 배경색 적용."""
        m = re.match(r'\{bg:([^}]+)\}(.*)', cell.strip(), re.DOTALL)
        if m:
            color, content = m.group(1).strip(), m.group(2).strip()
            return f'<td style="background-color: {color};">{_inline(content)}</td>'
        return f'<td>{_inline(cell)}</td>'

    while i < len(lines):
        line = lines[i]

        # note/info/warning/tip 패널 매크로 (:::note ... :::)
        m_panel = re.match(r'^:::(note|info|warning|tip)(?:\s+(.*))?$', line)
        if m_panel:
            macro_name  = m_panel.group(1)
            panel_title = (m_panel.group(2) or "").strip()
            inner_lines = []
            i += 1
            while i < len(lines) and lines[i].strip() != ":::":
                inner_lines.append(lines[i])
                i += 1
            inner_html = md_to_confluence("\n".join(inner_lines))
            title_part = (
                f'<ac:parameter ac:name="title">{_inline(panel_title)}</ac:parameter>'
                if panel_title else ""
            )
            out.append(
                f'<ac:structured-macro ac:name="{macro_name}">'
                f'{title_part}'
                f'<ac:rich-text-body>{inner_html}</ac:rich-text-body>'
                f'</ac:structured-macro>'
            )
            i += 1  # skip closing :::
            continue

        # expand 매크로 (:::expand 제목 ... :::)
        if line.startswith(":::expand"):
            title = line[9:].strip()
            inner_lines = []
            i += 1
            while i < len(lines) and lines[i].strip() != ":::":
                inner_lines.append(lines[i])
                i += 1
            inner_html = md_to_confluence("\n".join(inner_lines))
            out.append(
                f'<ac:structured-macro ac:name="expand">'
                f'<ac:parameter ac:name="title">{_inline(title)}</ac:parameter>'
                f'<ac:rich-text-body>{inner_html}</ac:rich-text-body>'
                f'</ac:structured-macro>'
            )
            i += 1  # skip closing :::
            continue

        # 코드블록
        if line.startswith("```"):
            raw_lang = line[3:].strip().lower()
            lang = _normalize_code_lang(raw_lang)
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                code_lines.append(lines[i])
                i += 1
            code = "\n".join(code_lines)
            # Confluence code macro
            out.append(
                f'<ac:structured-macro ac:name="code">'
                f'<ac:parameter ac:name="language">{lang}</ac:parameter>'
                f'<ac:plain-text-body><![CDATA[{code}]]></ac:plain-text-body>'
                f'</ac:structured-macro>'
            )
            i += 1
            continue

        # 수평선
        if re.match(r'^---+$', line.strip()):
            out.append('<hr/>')
            i += 1
            continue

        # 헤딩
        m = re.match(r'^(#{1,6})\s+(.*)', line)
        if m:
            level = len(m.group(1))
            out.append(f'<h{level}>{_inline(m.group(2))}</h{level}>')
            i += 1
            continue

        # 테이블
        if '|' in line and line.strip().startswith('|'):
            table_lines = []
            while i < len(lines) and '|' in lines[i] and lines[i].strip().startswith('|'):
                table_lines.append(lines[i])
                i += 1
            # 구분선 제거 (|---|---| 형태)
            header = table_lines[0]
            rows   = [r for r in table_lines[1:]
                      if not re.match(r'^\s*\|[\s\-|:]+\|\s*$', r)]
            cells  = [c.strip() for c in header.strip().strip('|').split('|')]
            html   = ['<table><tbody>']
            html.append('<tr>' + ''.join(f'<th>{_inline(c)}</th>' for c in cells) + '</tr>')
            for row in rows:
                rcells = [c.strip() for c in row.strip().strip('|').split('|')]
                html.append('<tr>' + ''.join(_td_cell(c) for c in rcells) + '</tr>')
            html.append('</tbody></table>')
            out.append('\n'.join(html))
            continue

        # 체크박스 (task list)
        m = re.match(r'^(\s*)- \[([ xX])\]\s*(.*)', line)
        if m:
            checked = m.group(2).lower() == 'x'
            text    = m.group(3)
            state   = 'checked' if checked else 'unchecked'
            # Confluence task list macro
            out.append(
                f'<ac:task-list><ac:task>'
                f'<ac:task-status>{state}</ac:task-status>'
                f'<ac:task-body>{_inline(text)}</ac:task-body>'
                f'</ac:task></ac:task-list>'
            )
            i += 1
            continue

        # 순서 없는 목록
        m = re.match(r'^(\s*)[-*]\s+(.*)', line)
        if m:
            indent  = len(m.group(1)) // 2 + 1
            content = m.group(2)
            out.append(f'<ul><li>{_inline(content)}</li></ul>')
            i += 1
            continue

        # 순서 있는 목록 — 연속 항목을 하나의 <ol>로 묶어 번호가 1,1,1 되는 현상 방지
        if re.match(r'^(\s*)\d+\.\s+(.*)', line):
            ol_items = []
            while i < len(lines) and re.match(r'^(\s*)\d+\.\s+(.*)', lines[i]):
                m_ol = re.match(r'^(\s*)\d+\.\s+(.*)', lines[i])
                ol_items.append(_inline(m_ol.group(2)))
                i += 1
            out.append('<ol>' + ''.join(f'<li>{item}</li>' for item in ol_items) + '</ol>')
            continue

        # 인용(blockquote)
        if line.startswith('>'):
            content = line[1:].strip()
            out.append(f'<blockquote><p>{_inline(content)}</p></blockquote>')
            i += 1
            continue

        # 빈줄
        if not line.strip():
            out.append('<p></p>')
            i += 1
            continue

        # 일반 텍스트
        out.append(f'<p>{_inline(line)}</p>')
        i += 1

    return '\n'.join(out)


# ── 레지스트리 ────────────────────────────────────────────────────────────────

def _load_registry() -> dict:
    if REGISTRY_PATH.exists():
        return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    return {}


def _save_registry(reg: dict) -> None:
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY_PATH.write_text(json.dumps(reg, ensure_ascii=False, indent=2), encoding="utf-8")


# ── Confluence REST API 호출 (Python requests 직접 호출) ──────────────────────

def _confluence_request(method: str, url: str, token: str, body_json: str | None = None) -> tuple[int, dict]:
    """
    Confluence REST API 호출.
    Python requests → cron/WSL 환경 모두 동작 (powershell.exe 불필요).
    """
    if not _HAS_REQUESTS:
        raise RuntimeError("requests 패키지가 없습니다. pip install requests")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    kwargs: dict = {"headers": headers, "timeout": 30}
    if body_json:
        kwargs["data"] = body_json.encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"

    resp = _requests.request(method, url, **kwargs)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, {"raw": resp.text}


# ── 메인 로직 ─────────────────────────────────────────────────────────────────

def publish(
    md_path: Path,
    title: str | None,
    parent_id: str | None,
    page_id: str | None,
    space_key: str,
    base_url: str,
    token: str,
    dry_run: bool = False,
    force: bool = False,
) -> str | None:
    """마크다운을 Confluence에 게시/갱신. page_id 반환."""

    md_text  = md_path.read_text(encoding="utf-8")
    cf_body  = md_to_confluence(md_text)

    if dry_run:
        print(f"[DRY-RUN] 변환 완료 ({len(cf_body)} chars). API 호출 생략.")
        print(cf_body[:2000])
        return None

    if page_id:
        # ── 기존 페이지 갱신 ────────────────────────────────────────────
        print(f"[UPDATE] 페이지 갱신 중 (id={page_id}) ...")
        # 현재 버전 + 본문 조회 (덮어쓰기 전 데이터 유실 감지용)
        _, curr = _confluence_request("GET",
            f"{base_url}/rest/api/content/{page_id}?expand=version,body.storage",
            token)
        if "error" in curr:
            print(f"[ERROR] 현재 버전 조회 실패: {curr}", file=sys.stderr)
            return None
        version = curr.get("version", {}).get("number", 1) + 1
        # title=None → 기존 페이지 제목 유지 (사람이 직접 지정한 제목을 덮어쓰지 않음)
        title_to_use = title if title is not None else curr.get("title", "")

        # ── 데이터 유실(row 축소) 감지 가드 ──────────────────────────────
        # 로컬 파일(cf_body)이 라이브 페이지보다 표 row 수가 크게 적으면
        # 그대로 PUT 시 라이브에만 존재하던 데이터가 통째로 사라질 수 있음.
        # (2026-07-15 클렌징 레지스트리 데이터 유실 사고 재발 방지)
        live_body  = curr.get("body", {}).get("storage", {}).get("value", "")
        live_rows  = live_body.count("<tr>") + live_body.count("<tr ")
        new_rows   = cf_body.count("<tr>") + cf_body.count("<tr ")
        if not force and live_rows > 0 and new_rows < live_rows * 0.8:
            print(
                f"[BLOCKED] 라이브 페이지 표 row 수({live_rows}) 대비 "
                f"로컬 변환 결과 row 수({new_rows})가 크게 축소됨 — 덮어쓰기 시 "
                f"라이브에만 존재하는 데이터가 유실될 위험. "
                f"의도된 축소라면 --force 로 재실행하세요.",
                file=sys.stderr,
            )
            return None

        payload = json.dumps({
            "version": {"number": version},
            "title":   title_to_use,
            "type":    "page",
            "body":    {"storage": {"value": cf_body, "representation": "storage"}},
        }, ensure_ascii=False)

        status, resp = _confluence_request("PUT",
            f"{base_url}/rest/api/content/{page_id}", token, payload)
        if status == 200 and "id" in resp:
            print(f"[OK] 갱신 완료: {base_url}/pages/viewpage.action?pageId={page_id}")
            return page_id
        else:
            print(f"[ERROR] 갱신 실패 (HTTP {status}): {resp}", file=sys.stderr)
            return None

    else:
        # ── 신규 생성 ────────────────────────────────────────────────────
        if not parent_id:
            print("[ERROR] 신규 생성 시 --parent 필수.", file=sys.stderr)
            return None
        if not title:
            print("[ERROR] 신규 생성 시 title 필수 (title=None으로는 신규 페이지를 만들 수 없음).", file=sys.stderr)
            return None

        print(f"[CREATE] 신규 페이지 생성 (parent={parent_id}, title={title}) ...")
        payload = json.dumps({
            "type":   "page",
            "title":  title,
            "space":  {"key": space_key},
            "ancestors": [{"id": parent_id}],
            "body":   {"storage": {"value": cf_body, "representation": "storage"}},
        }, ensure_ascii=False)

        status, resp = _confluence_request("POST",
            f"{base_url}/rest/api/content", token, payload)
        if status == 200 and "id" in resp:
            new_id = resp["id"]
            print(f"[OK] 생성 완료 (id={new_id}): {base_url}/pages/viewpage.action?pageId={new_id}")
            return new_id
        else:
            print(f"[ERROR] 생성 실패 (HTTP {status}): {resp}", file=sys.stderr)
            return None


def main():
    parser = argparse.ArgumentParser(description="Confluence 페이지 게시/갱신 도구")
    parser.add_argument("md_file", help="게시할 마크다운 파일 경로")
    parser.add_argument("--title",   default=None, help="페이지 제목 (미지정 시 파일명 사용)")
    parser.add_argument("--parent",  default=None, help="부모 페이지 ID (신규 생성 시 필수)")
    parser.add_argument("--page-id", default=None, help="기존 페이지 ID (갱신 시)")
    parser.add_argument("--space",   default=None, help="Confluence Space Key (기본: .env CONFLUENCE_SPACE_KEY)")
    parser.add_argument("--dry-run", action="store_true", help="API 호출 없이 변환 결과만 출력")
    parser.add_argument("--force", action="store_true",
                        help="라이브 페이지 대비 row 축소 감지 가드를 무시하고 강제 덮어쓰기")
    args = parser.parse_args()

    env = _load_env()
    base_url  = env.get("CONFLUENCE_BASE_URL", "https://wiki.skplanet.com").rstrip("/")
    token     = env.get("CONFLUENCE_TOKEN", "")
    space_key = args.space or env.get("CONFLUENCE_SPACE_KEY", "SECDIG")

    if not token:
        print("[ERROR] CONFLUENCE_TOKEN이 .env에 없습니다.", file=sys.stderr)
        sys.exit(1)

    md_path = Path(args.md_file)
    if not md_path.exists():
        print(f"[ERROR] 파일 없음: {md_path}", file=sys.stderr)
        sys.exit(1)

    title   = args.title or md_path.stem.replace("_", " ").replace("-", " ")
    md_key  = str(md_path.relative_to(PALANTIR_DIR)) if md_path.is_absolute() else str(md_path)
    reg     = _load_registry()
    page_id = args.page_id or reg.get(md_key)

    new_id = publish(
        md_path  = md_path,
        title    = title,
        parent_id= args.parent,
        page_id  = page_id,
        space_key= space_key,
        base_url = base_url,
        token    = token,
        dry_run  = args.dry_run,
        force    = args.force,
    )

    if new_id and not args.dry_run:
        reg[md_key] = new_id
        _save_registry(reg)
        print(f"[레지스트리] docs/.confluence_pages.json 갱신 완료")


if __name__ == "__main__":
    main()
