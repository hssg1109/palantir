#!/usr/bin/env python3
"""
build_service_history_table.py — OCB palantir 진단결과를 Confluence "신청이력 및
결과 현황" 양식(유형/진단월/서비스명(>프로젝트키)/서비스담당자/scm repo/branch/비고/
결과 공유현황)에 맞춰 Markdown 문서로 생성한다.

데이터 소스:
  - docs/ocb_scan_plan.md          : 레포별 [보고서]/Jira 티켓 존재 여부, 프로젝트 그룹
  - logs/final_<repo>_<date>.md    : 레포별 유형/scm/branch/담당자(커밋기준)/진단월
  - palantir-jira-gateway/data/repo_config.json : Jira 티켓팅 시점 담당자 매핑(우선 소스)

범위: [보고서] 링크가 있는 행 중 "전체양호"/"반려"가 아닌 레포만 포함.
결과: docs/ocb_service_history_confluence.md (Confluence storage 변환 전 Markdown,
      publish_confluence.py 의 :::expand / [JIRA:...] / 표 컨벤션을 그대로 사용).

향후 컬럼 추가 시: COLUMNS 리스트와 _row_cells()에 항목만 추가하고 재실행하면 됨.
"""
import json
import re
import sys
from pathlib import Path

PALANTIR_DIR = Path(__file__).parent.parent
SCAN_PLAN = PALANTIR_DIR / "docs" / "ocb_scan_plan.md"
LOGS_DIR = PALANTIR_DIR / "logs"
REPO_CONFIG_PATH = Path("/home/geunsolo/palantir-jira-gateway/data/repo_config.json")
OUT_PATH = PALANTIR_DIR / "docs" / "ocb_service_history_confluence.md"

PROJECT_LABELS = {
    "OCBWEBVIEW": "OCB Webview",
    "OCBSUGAR": "OCB Sugar/SOI",
    "OCBRWD": "참여적립",
    "LIVECM": "오라방 라이브커머스",
    "OCBE": "OCB 이벤트",
    "OEP": "OCB 이벤트",
    "OB": "OCB 이벤트",
    "OSA": "OCB 전시관리",
    "OCBX": "OCBX 블록체인",
    "OCBNFT": "OCB NFT",
    "OCBPASS": "OCB Pass",
    "OCBPU": "OCB Payment UI",
    "OKICK": "오킥",
}

CHECKLIST_RE = re.compile(
    r'^:::expand 진단 체크리스트 전체 현황.*?\n(.*?)\n:::\s*$',
    re.DOTALL | re.MULTILINE,
)
SECTION_RE = re.compile(r'^#### (P\d-[A-Z]): (.+?)(?: \(\d+개\))?$')


def _parse_checklist_rows():
    """ocb_scan_plan.md 체크리스트 블록에서 [보고서] 있는 행만 (전체양호/반려 제외) 추출."""
    text = SCAN_PLAN.read_text(encoding="utf-8")
    m = CHECKLIST_RE.search(text)
    if not m:
        print("[ERROR] 체크리스트 expand 블록을 찾을 수 없음", file=sys.stderr)
        sys.exit(1)
    block = m.group(1)

    rows = []
    section_key, section_label = None, None
    for line in block.splitlines():
        sm = SECTION_RE.match(line.strip())
        if sm:
            section_key, section_label = sm.group(1), sm.group(2)
            continue
        if line.strip().startswith("|") and "레포" not in line and not re.match(r'^\|[\s\-|]+\|$', line.strip()):
            cols = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cols) < 9:
                continue
            repo, io, inj, xss, file_, data, sca, report, jira = cols[:9]
            repo = repo.strip("`")
            if not report.startswith("[보고서]"):
                continue
            if "반려" in jira:
                continue
            report_url_m = re.search(r'\((https?://[^)]+)\)', report)
            rows.append({
                "section": f"{section_key}: {section_label}" if section_key else "",
                "repo": repo,
                "jira": jira.strip(),
                "report_url": report_url_m.group(1) if report_url_m else "",
            })
    return rows


def _latest_final_report(repo: str) -> Path | None:
    candidates = sorted(LOGS_DIR.glob(f"final_{repo}_*.md"))
    return candidates[-1] if candidates else None


def _parse_overview(report_path: Path) -> dict:
    text = report_path.read_text(encoding="utf-8")
    m = re.search(r'## 1\. 진단 개요\n\n(.*?)\n\n', text, re.DOTALL)
    table_text = m.group(1) if m else text
    fields = {}
    for line in table_text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cols) != 2 or cols[0] in ("항목", "------"):
            continue
        key = cols[0].lstrip("*").strip()
        fields[key] = cols[1]
    return fields


def _load_repo_config() -> dict:
    if not REPO_CONFIG_PATH.exists():
        return {}
    d = json.load(REPO_CONFIG_PATH.open(encoding="utf-8"))
    return {k: v for k, v in d.items() if not k.startswith("_")}


def _assignee_cell(repo: str, repo_config: dict, fallback_raw: str) -> tuple[str, bool]:
    """(표시텍스트, 커밋기준_추정여부) 반환."""
    cfg = repo_config.get(repo)
    if cfg:
        note = cfg.get("note", "")
        name_part = note.split(" — ")[0].strip() if " — " in note else note.strip()
        return name_part or f"사번:{cfg.get('assignee', '')}", False
    # fallback: final report의 *담당자 (최근 commit 기준 자동설정)
    name = re.sub(r'\s*<[^>]+>\s*$', '', fallback_raw).strip()
    return name, True


def build():
    rows = _parse_checklist_rows()
    repo_config = _load_repo_config()

    out_rows = []
    missing_report = []
    has_asterisk = False

    for r in rows:
        repo = r["repo"]
        fp = _latest_final_report(repo)
        if fp is None:
            missing_report.append(repo)
            continue
        ov = _parse_overview(fp)

        service_type = "정기(palantir)"
        project_key = ov.get("Bitbucket 프로젝트", "")
        scm_url = ov.get("소스코드 저장소", "")
        branch = ov.get("진단 브랜치", "")
        if not branch or branch == "None":
            meta_path = PALANTIR_DIR / "state" / repo / "repo_meta.json"
            if meta_path.exists():
                branch = json.loads(meta_path.read_text(encoding="utf-8")).get("branch", "")
        raw_assignee = ov.get("*담당자", ov.get("담당자", ""))
        gen_date = ov.get("보고서 생성일", "")
        scan_month = gen_date[:7] if len(gen_date) >= 7 else ""

        service_label = PROJECT_LABELS.get(project_key, project_key)
        service_cell = f"{service_label}(>{project_key})" if project_key else service_label

        assignee_cell, is_fallback = _assignee_cell(repo, repo_config, raw_assignee)
        if is_fallback:
            assignee_cell += "*"
            has_asterisk = True

        jira_m = re.search(r'\[JIRA:([A-Z]+-\d+)\]', r["jira"])
        if jira_m:
            result_cell = f"[JIRA:{jira_m.group(1)}]"
            remark = ""
        else:
            result_cell = "—"
            remark = "Jira 티켓 발행 예정"

        out_rows.append({
            "section": r["section"],
            "repo": repo,
            "type": service_type,
            "month": scan_month,
            "service": service_cell,
            "assignee": assignee_cell,
            "scm": scm_url,
            "branch": branch,
            "remark": remark,
            "result": result_cell,
        })

    if missing_report:
        print(f"[WARN] final report 없음 ({len(missing_report)}건): {missing_report}", file=sys.stderr)

    # 오래된 진단월이 위, 최신 진단월이 아래로 오도록 오름차순 정렬
    out_rows.sort(key=lambda x: x["month"])

    lines = []
    lines.append(":::expand OCB palantir 신청이력 및 결과 현황")
    lines.append("")
    lines.append("| 유형 | 진단월 | 서비스명(>프로젝트키) | 서비스담당자 | scm repo(bitbucket주소) | branch | 비고 | 결과 공유현황 |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for row in out_rows:
        scm_link = f"[{row['scm']}]({row['scm']})" if row["scm"] else ""
        lines.append(
            f"| {row['type']} | {row['month']} | {row['service']} | {row['assignee']} "
            f"| {scm_link} | {row['branch']} | {row['remark']} | {row['result']} |"
        )
    if has_asterisk:
        lines.append("")
        lines.append("*담당자는 repo clone 시 가장 최근 commit 한 개발자로 임의 설정되어 있습니다(Jira 티켓팅 시점 담당자 매핑에 없는 레포). 변경 필요시 담당팀에 확인 부탁드립니다.")
    lines.append("")
    lines.append(":::")

    OUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[저장] {OUT_PATH}  ({len(out_rows)}행)")


if __name__ == "__main__":
    build()
