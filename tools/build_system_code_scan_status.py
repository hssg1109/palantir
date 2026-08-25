#!/usr/bin/env python3
"""
build_system_code_scan_status.py — 전사 시스템코드별 보안진단 현황 문서 생성

데이터 소스:
  docs/system_code_to_repo_20260729_v3.json — 전사 CMDB 시스템코드 → repo 매핑 (297개 시스템코드)
  state/<repo_slug>/<skill>/<timestamp>/    — 실제 진단 이력 (repo slug = "PROJECT/repo"의 마지막 세그먼트)

완료 판정 로직은 tools/update_ocb_plan.py::sync_from_state()와 동일한 기준을 재사용한다
(SKILL_FINDINGS 파일명 + llm_checked + llm_check_failed.json 가드). 이 스크립트는 읽기 전용이며
docs/ocb_scan_plan.md나 .ocb_scan_status.json은 건드리지 않는다.

결과: docs/system_code_scan_status.md (Confluence storage 변환 전 Markdown,
      publish_confluence.py 의 :::expand 컨벤션을 그대로 사용).

사용법:
  python3 tools/build_system_code_scan_status.py
  python3 tools/publish_confluence.py docs/system_code_scan_status.md \
      --title "전사 시스템코드별 보안진단 현황" --parent 750459063
"""
import json
import re
import sys
from datetime import datetime
from pathlib import Path

PALANTIR_DIR = Path(__file__).parent.parent
SRC_JSON = PALANTIR_DIR / "docs" / "system_code_to_repo_20260729_v3.json"
STATE_DIR = PALANTIR_DIR / "state"
OUT_PATH = PALANTIR_DIR / "docs" / "system_code_scan_status.md"
EXCLUDED_PATH = PALANTIR_DIR / "docs" / "scan_status_excluded_repos.json"

sys.path.insert(0, str(PALANTIR_DIR / "tools"))
from update_ocb_plan import VALID_SKILLS, SKILL_FINDINGS, PLAN_MD, SKILL_COL_IDX  # noqa: E402
from system_code_lookup import build_repo_to_codes, classify_group  # noqa: E402

CORE_SKILLS = ["injection", "xss", "file", "data"]  # SCA는 완료 판정에서 제외 (feedback_sca_default_exclude)
SKILL_LABEL = {"injection": "INJ", "xss": "XSS", "file": "FILE", "data": "DATA", "sca": "SCA"}
ICON = {"done": "✅", "draft": "🔄", "none": "❌"}

_CHECKLIST_DATA_RE = re.compile(r"^\|\s*`([^`]+)`\s*\|")
_CELL_DATE_RE = re.compile(r"✅\s*(\d{4}-\d{2}-\d{2})")


def load_checklist_status() -> dict[str, dict[str, str | None]]:
    """docs/ocb_scan_plan.md 체크리스트에서 repo별 skill ✅ 여부 + 날짜(있으면)를 파싱한다.

    체크리스트는 /sec-review + approve_report.py + mark_all_clear() 등을 거쳐 사람이 확인한
    완료 기록(sticky)이므로, state/ 원본 재계산 결과보다 우선 적용한다 — state/에는 아직
    llm_check_failed.json 가드에 걸려 draft로 보이지만 실제로는 전체양호/sec-review 완료
    처리된 케이스(예: ocbws-frontend)를 놓치지 않기 위함. (SKILL_COL_IDX 컨벤션은
    update_ocb_plan.py::mark_done()과 동일하게 재사용)

    반환: {slug: {skill: date_str|None}}  (✅ 없는 skill은 키 자체가 없음)
    """
    text = PLAN_MD.read_text(encoding="utf-8")
    result: dict[str, dict[str, str | None]] = {}
    for line in text.splitlines():
        m = _CHECKLIST_DATA_RE.match(line)
        if not m:
            continue
        slug = m.group(1)
        cells = line.split("|")
        entry = result.setdefault(slug, {})
        for skill, idx in SKILL_COL_IDX.items():
            if idx >= len(cells):
                continue
            cell = cells[idx]
            if "✅" not in cell:
                continue
            dm = _CELL_DATE_RE.search(cell)
            date = dm.group(1) if dm else None
            if skill not in entry or (entry[skill] is None and date is not None):
                entry[skill] = date
    return result


def load_excluded_repos() -> dict[str, str]:
    """docs/scan_status_excluded_repos.json — 정기진단 비대상으로 확인된 repo 목록.

    state/에 산발적 스캔 산출물(예: injection만 단발 실행)이 남아있어도 이 목록에 있으면
    전체 skill을 미진단(none)으로 강제 처리한다. 반환: {slug: reason}
    """
    if not EXCLUDED_PATH.exists():
        return {}
    data = json.loads(EXCLUDED_PATH.read_text(encoding="utf-8"))
    return {r["slug"]: r.get("reason", "") for r in data.get("repos", [])}


def skill_status(repo_slug: str, skill: str) -> tuple[str, str | None]:
    """state/<repo_slug>/<skill>/ 를 sync_from_state()와 동일 기준으로 판정.

    반환: ("done"|"draft"|"none", 최근스캔일 YYYY-MM-DD|None)
    """
    skill_dir = STATE_DIR / repo_slug / skill
    if not skill_dir.exists():
        return "none", None

    ts_dirs = sorted([d for d in skill_dir.iterdir() if d.is_dir()], reverse=True)
    if not ts_dirs:
        return "none", None

    latest_ts = ts_dirs[0].name
    try:
        latest_date = f"{latest_ts[:4]}-{latest_ts[4:6]}-{latest_ts[6:8]}"
    except Exception:
        latest_date = None

    for ts_dir in ts_dirs:
        findings_path = None
        for fname in SKILL_FINDINGS[skill]:
            if (ts_dir / fname).exists():
                findings_path = ts_dir / fname
                break
        if findings_path is None:
            continue

        ts = ts_dir.name
        date_str = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"

        if (ts_dir / "llm_check_failed.json").exists():
            try:
                fdata = json.loads(findings_path.read_text(encoding="utf-8"))
                f_findings = fdata.get("findings", [])
                f_reviewed = sum(1 for f in f_findings if f.get("reviewed"))
                f_llm_checked = fdata.get("llm_checked", False)
                if not f_llm_checked or (len(f_findings) == 0 and f_reviewed == 0):
                    continue  # 이 타임스탬프는 불완전 — 더 과거 타임스탬프 탐색
            except Exception:
                continue
            return "done", date_str

        # llm_check_failed.json이 없으면 llm_checked 값과 무관하게 완료로 판정
        # (sync_from_state()와 동일 — 0건 탐지 시 llm_checked 필드 자체가 생략되는 케이스 대응)
        return "done", date_str

    # findings 파일은 못 찾았지만 Auto-Scan 산출물(타임스탬프 디렉터리)은 존재
    return "draft", latest_date


def main() -> int:
    entries = json.loads(SRC_JSON.read_text(encoding="utf-8"))
    repo_to_codes = build_repo_to_codes(entries)
    checklist_status = load_checklist_status()
    excluded_repos = load_excluded_repos()

    repo_status_cache: dict[str, dict[str, tuple[str, str | None]]] = {}

    def get_repo_status(slug: str) -> dict[str, tuple[str, str | None]]:
        if slug not in repo_status_cache:
            if slug in excluded_repos:
                # 정기진단 비대상 확인 레포 — state/ 산발 데이터 무시하고 전체 미진단 처리
                repo_status_cache[slug] = {s: ("none", None) for s in VALID_SKILLS}
            else:
                st = {s: skill_status(slug, s) for s in VALID_SKILLS}
                for skill, date in checklist_status.get(slug, {}).items():
                    if st[skill][0] != "done":
                        st[skill] = ("done", date or st[skill][1])
                repo_status_cache[slug] = st
        return repo_status_cache[slug]

    # ── 시스템코드별 요약 집계 ────────────────────────────────────────────────
    summary_rows = []
    detail_rows = []
    total_repo_pairs = 0
    codes_with_repo = 0
    codes_without_repo = 0
    unique_slugs: set[str] = set()

    for e in sorted(entries, key=lambda x: x["system_code"]):
        code = e["system_code"]
        name = e.get("시스템명", "")
        repos = e.get("repos", [])

        group = classify_group(name)

        if not repos:
            codes_without_repo += 1
            summary_rows.append({
                "group": group, "code": code, "name": name, "nrepo": 0,
                "done": 0, "partial": 0, "none": 0, "note": "레포 미확인", "has_repo": False,
                "code_complete": False,
            })
            continue

        codes_with_repo += 1
        done_n = partial_n = none_n = 0

        for repo_path in repos:
            slug = repo_path.rsplit("/", 1)[-1]
            unique_slugs.add(slug)
            total_repo_pairs += 1
            st = get_repo_status(slug)
            core_states = [st[s][0] for s in CORE_SKILLS]
            if all(s == "done" for s in core_states):
                done_n += 1
                bucket = "완료"
            elif any(s == "done" for s in core_states):
                partial_n += 1
                bucket = "부분"
            else:
                none_n += 1
                bucket = "미진단"

            dates = [st[s][1] for s in CORE_SKILLS if st[s][1]]
            latest = max(dates) if dates else "—"
            detail_rows.append({
                "code": code, "repo": repo_path, "st": st, "latest": latest, "bucket": bucket,
                "group": group,
            })

        summary_rows.append({
            "group": group, "code": code, "name": name, "nrepo": len(repos),
            "done": done_n, "partial": partial_n, "none": none_n, "note": "", "has_repo": True,
            "code_complete": done_n == len(repos),
        })

    # 기본 정렬: 상위 서비스군별 나열, 레포 미확인 시스템코드는 제일 하단으로 분리
    summary_rows.sort(key=lambda r: (not r["has_repo"], r["group"], r["code"]))

    # 진단완료(최근 스캔일 있는) repo를 최상단으로, 그 다음 상위 서비스군별 정렬
    detail_rows.sort(key=lambda r: (r["bucket"] != "완료", r["group"], r["code"], r["repo"]))

    # ── 전사 집계 ────────────────────────────────────────────────────────────
    repo_done = sum(
        1 for slug in unique_slugs
        if all(get_repo_status(slug)[s][0] == "done" for s in CORE_SKILLS)
    )
    repo_partial = sum(
        1 for slug in unique_slugs
        if any(get_repo_status(slug)[s][0] == "done" for s in CORE_SKILLS)
        and not all(get_repo_status(slug)[s][0] == "done" for s in CORE_SKILLS)
    )
    repo_none = len(unique_slugs) - repo_done - repo_partial

    # ── 다중 시스템코드 매핑 레포 ────────────────────────────────────────────────
    code_to_name = {e["system_code"]: e.get("시스템명", "") for e in entries}
    multi_map_repos = sorted(
        (slug, codes) for slug, codes in repo_to_codes.items() if len(codes) > 1
    )

    # ── 문서 생성 ────────────────────────────────────────────────────────────
    lines = []
    lines.append("# 전사 시스템코드별 Palantir 보안진단 현황")
    lines.append("")
    lines.append(":::info 문서 정보")
    lines.append(f"**작성일**: {datetime.now().strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append(f"**원본 데이터**: `docs/system_code_to_repo_20260729_v3.json` (전사 CMDB 시스템코드 매핑, {len(entries)}개)")
    lines.append(":::")
    lines.append("")
    lines.append(":::note")
    lines.append("⚙️ 본 현황은 **palantir 진단 도구**(`state/` 실행 이력) 기반 자동 집계이며, Fortify 등 타 도구 진단 이력은 포함하지 않음.")
    lines.append(":::")
    lines.append("")
    lines.append(":::tip")
    lines.append("🗂️ **상위 서비스군**은 시스템명 접두어 기반 휴리스틱 분류(`tools/system_code_lookup.py::classify_group()`) — 참고용이며 100% 정확을 보장하지 않음.")
    lines.append(":::")
    lines.append("")
    lines.append("## 0. 전사 집계 요약")
    lines.append("")
    lines.append(f"- 시스템코드: 전체 {len(entries)}개 (레포 매핑 있음 {codes_with_repo}개 / 레포 미확인 {codes_without_repo}개)")
    lines.append(f"- 레포: 시스템코드-레포 매핑 {total_repo_pairs}건 (고유 레포 {len(unique_slugs)}개, 동일 레포가 복수 시스템코드에 걸치는 경우 있음)")
    lines.append(f"- 고유 레포 기준 진단 현황: 진단완료 {repo_done}개 / 부분진단 {repo_partial}개 / 미진단 {repo_none}개")
    lines.append(f"- 1개 레포가 여러 시스템코드에 매핑된 경우: {len(multi_map_repos)}건 (§3 참조, 실제 소속 시스템코드 확인 필요)")
    lines.append("")
    code_complete_n = sum(1 for r in summary_rows if r["code_complete"])
    lines.append("## 1. 시스템코드별 요약")
    lines.append("")
    lines.append(f"> 🟢 **시스템코드 진단완료**(매핑된 레포 전체가 injection/xss/file/data 4종 모두 완료) {code_complete_n}개 — 아래 표의 색상 플래그 열 참조.")
    lines.append("")
    lines.append("| 상위 서비스군 | 시스템코드 | 시스템명 | 레포수 | 진단완료 | 부분진단 | 미진단 | 시스템 진단완료 | 비고 |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for r in summary_rows:
        flag = "{bg:#D4EDDA}🟢 완료" if r["code_complete"] else ""
        if r["has_repo"]:
            lines.append(
                f"| {r['group']} | `{r['code']}` | {r['name']} | {r['nrepo']} | "
                f"{r['done']} | {r['partial']} | {r['none']} | {flag} | {r['note']} |"
            )
        else:
            # 레포 미확인 시스템코드 — 전체 셀 회색 배경 처리
            g = "{bg:#E8E8E8}"
            lines.append(
                f"| {g}{r['group']} | {g}`{r['code']}` | {g}{r['name']} | {g}{r['nrepo']} | "
                f"{g}{r['done']} | {g}{r['partial']} | {g}{r['none']} | {g} | {g}{r['note']} |"
            )
    lines.append("")
    lines.append(f"## 2. 레포별 상세 진단현황 (전체 {total_repo_pairs}건)")
    lines.append("")
    lines.append(f':::expand 레포별 상세 진단현황 (전체 {total_repo_pairs}건, 클릭하여 펼치기)')
    lines.append("")
    lines.append("| 상위 서비스군 | 시스템코드 | 레포 | INJ | XSS | FILE | DATA | 최근스캔일 |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for row in detail_rows:
        st = row["st"]
        cells = " | ".join(ICON[st[s][0]] for s in CORE_SKILLS)
        lines.append(f"| {row['group']} | `{row['code']}` | `{row['repo']}` | {cells} | {row['latest']} |")
    lines.append(":::")
    lines.append("")
    lines.append(f"## 3. 다중 시스템코드 매핑 레포 (확인 필요, {len(multi_map_repos)}건)")
    lines.append("")
    lines.append("> 동일 레포가 CMDB 상 여러 시스템코드에 연결되어 있음 — 실제 소속 시스템코드를 담당자 확인 후 정리 필요.")
    lines.append("")
    lines.append(f':::expand 다중 시스템코드 매핑 레포 — 실제 매핑 확인 필요 ({len(multi_map_repos)}건, 클릭하여 펼치기)')
    lines.append("")
    lines.append("| 레포 | 매핑된 시스템코드 (N개) | 비고 |")
    lines.append("|---|---|---|")
    for slug, codes in multi_map_repos:
        codes_str = ", ".join(f"`{c}`({code_to_name.get(c, '')})" for c in codes)
        lines.append(f"| `{slug}` | {codes_str} ({len(codes)}개) | 확인 필요 |")
    lines.append(":::")
    lines.append("")

    OUT_PATH.write_text("\n".join(lines), encoding="utf-8")

    print(f"[OK] {OUT_PATH} 생성 완료")
    print(f"  시스템코드: {len(entries)}개 (레포 있음 {codes_with_repo} / 레포 미확인 {codes_without_repo})")
    print(f"  시스템코드-레포 매핑: {total_repo_pairs}건 (고유 레포 {len(unique_slugs)}개)")
    print(f"  고유 레포 진단현황: 완료 {repo_done} / 부분 {repo_partial} / 미진단 {repo_none}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
