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
import tempfile
from pathlib import Path

PALANTIR_DIR = Path(__file__).parent.parent
REGISTRY_PATH = PALANTIR_DIR / "docs" / ".confluence_pages.json"

_ENV_PATH = PALANTIR_DIR / ".env"


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
_CF_VALID_LANGS = {
    "none", "java", "javascript", "sql", "xml", "bash", "python", "ruby",
    "php", "html", "css", "groovy", "scala", "yaml", "json", "powershell",
    "perl", "go", "c", "cpp", "vb", "actionscript", "applescript",
    "delphi", "erlang", "latex", "tex",
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
        # 1. XML 특수문자 이스케이프 (태그 처리 전에 먼저)
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;').replace('>', '&gt;')
        # 2. 굵기
        text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
        # 3. 기울임
        text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
        # 4. 인라인 코드
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        # 5. 링크 [text](url)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)',
                      r'<a href="\2">\1</a>', text)
        # 6. 색상 태그 {color:X}text{/color} → <span style="color:X">
        text = re.sub(r'\{color:([^}]+)\}(.*?)\{/color\}',
                      r'<span style="color:\1">\2</span>', text, flags=re.DOTALL)
        return text

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
                html.append('<tr>' + ''.join(f'<td>{_inline(c)}</td>' for c in rcells) + '</tr>')
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


# ── PowerShell 경유 API 호출 ──────────────────────────────────────────────────

def _run_ps(script: str) -> tuple[int, str]:
    """PowerShell 스크립트를 실행하고 (returncode, stdout) 반환."""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return result.returncode, (result.stdout + result.stderr).strip()


def _confluence_request(method: str, url: str, token: str, body_json: str | None = None) -> tuple[int, dict]:
    """
    Confluence REST API 호출 (PowerShell Invoke-RestMethod 경유).
    body_json은 임시 파일로 전달해 이스케이프 문제를 회피한다.
    """
    if body_json:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json",
                                          mode="w", encoding="utf-8")
        tmp.write(body_json)
        tmp.close()
        # Windows 경로로 변환
        win_path = subprocess.check_output(
            ["wslpath", "-w", tmp.name], text=True).strip()
        ps_body = f"(Get-Content -Raw -Path '{win_path}' -Encoding UTF8)"
    else:
        ps_body = "$null"

    body_part = ""
    if body_json:
        body_part = f"""
$bodyStr = {ps_body}
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyStr)"""

    ps = f"""
$token = '{token}'
$headers = @{{ Authorization = "Bearer $token"; Accept = "application/json" }}{body_part}
try {{
    $r = Invoke-RestMethod -Method {method} -Uri '{url}' -Headers $headers {'-Body $bodyBytes -ContentType "application/json; charset=utf-8"' if body_json else ''} -TimeoutSec 30
    $r | ConvertTo-Json -Depth 10 -Compress
}} catch {{
    Write-Output "ERROR:$($_.Exception.Response.StatusCode.value__):$($_.Exception.Message)"
}}
"""
    rc, out = _run_ps(ps)
    if body_json:
        Path(tmp.name).unlink(missing_ok=True)

    if out.startswith("ERROR:"):
        parts = out.split(":", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 500
        return status, {"error": out}
    try:
        return 200, json.loads(out)
    except Exception:
        return 200, {"raw": out}


# ── 메인 로직 ─────────────────────────────────────────────────────────────────

def publish(
    md_path: Path,
    title: str,
    parent_id: str | None,
    page_id: str | None,
    space_key: str,
    base_url: str,
    token: str,
    dry_run: bool = False,
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
        # 현재 버전 조회
        _, curr = _confluence_request("GET",
            f"{base_url}/rest/api/content/{page_id}?expand=version",
            token)
        if "error" in curr:
            print(f"[ERROR] 현재 버전 조회 실패: {curr}", file=sys.stderr)
            return None
        version = curr.get("version", {}).get("number", 1) + 1

        payload = json.dumps({
            "version": {"number": version},
            "title":   title,
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
    )

    if new_id and not args.dry_run:
        reg[md_key] = new_id
        _save_registry(reg)
        print(f"[레지스트리] docs/.confluence_pages.json 갱신 완료")


if __name__ == "__main__":
    main()
