#!/usr/bin/env python3
"""
list_ocb_repos.py — Bitbucket Server에서 OCB(OK Cashbag) 서비스 군 레포를 전수 조사합니다.

동작:
  1. 전체 프로젝트 목록 조회
  2. 프로젝트명 / 키에 OCB 관련 키워드가 포함된 프로젝트 식별
  3. 각 프로젝트 내 전체 레포 열거
  4. 레포명 / 설명에 OCB 관련 키워드 포함 시 추가 수집
  5. 결과를 JSON + 마크다운으로 출력

사용법:
    python3 tools/list_ocb_repos.py
    python3 tools/list_ocb_repos.py --projects OCBWEBVIEW OCB OKCHK   # 특정 프로젝트만
    python3 tools/list_ocb_repos.py --all-projects                    # 전체 프로젝트 검색
    python3 tools/list_ocb_repos.py --out docs/ocb_repo_list.md       # 파일로 저장

환경변수 (.env):
    BITBUCKET_BASE_URL  = https://code.skplanet.com
    CUSTOMER_BB_TOKEN   = BBDC-...
"""

import argparse
import json
import sys
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import datetime

# ── .env 로드 ─────────────────────────────────────────────────────────────────
_ENV_PATH = Path(__file__).parent.parent / ".env"

def _load_env() -> dict:
    env: dict = {}
    if not _ENV_PATH.exists():
        return env
    for line in _ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip()
    return env

_ENV = _load_env()
BASE_URL = _ENV.get("BITBUCKET_BASE_URL", "https://code.skplanet.com").rstrip("/")
TOKEN    = _ENV.get("CUSTOMER_BB_TOKEN", "")

# OCB 관련 키워드 (프로젝트 키/명, 레포명 매칭용)
OCB_KEYWORDS = [
    "ocb", "ok-cashbag", "okcashbag", "okchk", "okcb",
    "ocbwebview", "cashbag", "ok캐시백",
]

# ── Bitbucket REST API 헬퍼 ───────────────────────────────────────────────────

def _bb_get_paged(path: str, params: dict | None = None) -> list:
    """페이지네이션 처리하여 전체 결과 반환."""
    results = []
    start = 0
    limit = 100
    while True:
        p = dict(params or {})
        p["start"] = start
        p["limit"] = limit
        url = f"{BASE_URL}/rest/api/1.0{path}?" + urllib.parse.urlencode(p)
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as e:
            print(f"[ERROR] HTTP {e.code}: {e.reason} — {path}", file=sys.stderr)
            if e.code in (401, 403):
                print("  → CUSTOMER_BB_TOKEN 권한 부족 또는 만료", file=sys.stderr)
                sys.exit(1)
            break
        except Exception as e:
            print(f"[ERROR] 네트워크 오류: {e}", file=sys.stderr)
            print("  → VPN 연결 상태를 확인하세요.", file=sys.stderr)
            sys.exit(1)

        values = data.get("values", [])
        results.extend(values)
        if data.get("isLastPage", True):
            break
        start = data.get("nextPageStart", start + limit)
    return results


def _is_ocb(text: str) -> bool:
    """텍스트에 OCB 관련 키워드 포함 여부."""
    t = (text or "").lower()
    return any(kw in t for kw in OCB_KEYWORDS)


# ── 핵심 로직 ─────────────────────────────────────────────────────────────────

def list_all_projects() -> list[dict]:
    print("[1/3] 전체 프로젝트 목록 조회 중...", flush=True)
    projects = _bb_get_paged("/projects")
    print(f"  → {len(projects)}개 프로젝트 발견")
    return projects


def list_repos_in_project(project_key: str) -> list[dict]:
    return _bb_get_paged(f"/projects/{project_key}/repos")


def find_ocb_repos(
    target_projects: list[str] | None = None,
    all_projects: bool = False,
) -> dict:
    """
    OCB 관련 레포를 찾아 dict 반환.
    {
      "scanned_at": "...",
      "total_projects_checked": N,
      "ocb_projects": [...],
      "ocb_repos": [
        {"project_key": ..., "project_name": ..., "repo_slug": ..., "repo_name": ...,
         "clone_url": ..., "default_branch": ..., "match_reason": ...}
      ]
    }
    """
    if not TOKEN:
        print("[ERROR] CUSTOMER_BB_TOKEN이 .env에 설정되지 않았습니다.", file=sys.stderr)
        sys.exit(1)

    # 프로젝트 목록 확정
    if target_projects:
        # 직접 지정된 프로젝트만
        projects_to_check = [{"key": k, "name": k} for k in target_projects]
        print(f"[1/3] 지정된 프로젝트 {len(projects_to_check)}개 사용", flush=True)
    elif all_projects:
        projects_to_check = list_all_projects()
    else:
        # 기본: 알려진 OCB 프로젝트 + 전체 프로젝트 명칭 스캔
        all_projs = list_all_projects()
        ocb_projs = [p for p in all_projs
                     if _is_ocb(p.get("key", "")) or _is_ocb(p.get("name", ""))]

        # 알려진 OCB 프로젝트 키가 없으면 추가
        known_keys = {p["key"] for p in ocb_projs}
        for kk in ["OCBWEBVIEW", "OCB", "OKCHK", "OKCB"]:
            if kk not in known_keys:
                # 해당 프로젝트가 실제로 존재하는지 확인
                matched = [p for p in all_projs if p.get("key") == kk]
                if matched:
                    ocb_projs.extend(matched)

        projects_to_check = ocb_projs or all_projs  # OCB 프로젝트 없으면 전체 스캔
        print(f"  → OCB 관련 프로젝트 {len(ocb_projs)}개 식별", flush=True)

    # 레포 수집
    print(f"[2/3] 레포 목록 수집 중...", flush=True)
    ocb_repos = []
    ocb_projects_found = []

    for proj in projects_to_check:
        pk = proj.get("key", "")
        pn = proj.get("name", pk)
        repos = list_repos_in_project(pk)
        print(f"  [{pk}] {pn}: {len(repos)}개 레포")

        proj_is_ocb = _is_ocb(pk) or _is_ocb(pn)
        if proj_is_ocb:
            ocb_projects_found.append({"key": pk, "name": pn, "repo_count": len(repos)})

        for repo in repos:
            slug   = repo.get("slug", "")
            rname  = repo.get("name", slug)
            rdesc  = repo.get("description", "")

            # 매칭 이유 결정
            if proj_is_ocb:
                reason = f"프로젝트 [{pk}]가 OCB 서비스"
            elif _is_ocb(slug) or _is_ocb(rname) or _is_ocb(rdesc):
                reason = "레포명/설명에 OCB 키워드 포함"
            else:
                continue  # OCB 무관

            # HTTP clone URL
            clone_url = ""
            for link in repo.get("links", {}).get("clone", []):
                if link.get("name") == "http":
                    clone_url = link["href"]
                    break

            default_branch = repo.get("defaultBranch", {})
            if isinstance(default_branch, dict):
                default_branch = default_branch.get("displayId", "main")

            ocb_repos.append({
                "project_key":   pk,
                "project_name":  pn,
                "repo_slug":     slug,
                "repo_name":     rname,
                "description":   rdesc or "",
                "clone_url":     clone_url,
                "default_branch": default_branch,
                "match_reason":  reason,
            })

    return {
        "scanned_at":             datetime.now().isoformat(),
        "total_projects_checked": len(projects_to_check),
        "ocb_projects":           ocb_projects_found,
        "ocb_repos":              ocb_repos,
    }


# ── 출력 포맷 ─────────────────────────────────────────────────────────────────

def render_markdown(result: dict) -> str:
    lines = [
        "# OCB 서비스 군 — Bitbucket 레포 목록",
        "",
        f"> 조회 일시: {result['scanned_at']}  ",
        f"> 검색 프로젝트 수: {result['total_projects_checked']}  ",
        f"> OCB 관련 레포 수: {len(result['ocb_repos'])}",
        "",
        "---",
        "",
        "## OCB 프로젝트",
        "",
    ]
    for p in result["ocb_projects"]:
        lines.append(f"- `{p['key']}` — {p['name']} ({p['repo_count']}개 레포)")
    if not result["ocb_projects"]:
        lines.append("- (프로젝트 레벨 OCB 매칭 없음 — 레포명으로 수집)")

    lines += ["", "---", "", "## 레포 목록", ""]

    # 프로젝트별 그룹
    by_proj: dict[str, list] = {}
    for r in result["ocb_repos"]:
        by_proj.setdefault(r["project_key"], []).append(r)

    for pk, repos in sorted(by_proj.items()):
        pn = repos[0]["project_name"]
        lines += [f"### [{pk}] {pn}", ""]
        lines += ["| # | 레포 슬러그 | 설명 | 기본 브랜치 | 매칭 사유 |",
                  "|---|---|---|---|---|"]
        for i, r in enumerate(repos, 1):
            desc = (r["description"] or "")[:60]
            lines.append(
                f"| {i} | `{r['repo_slug']}` | {desc} "
                f"| `{r['default_branch']}` | {r['match_reason']} |"
            )
        lines.append("")

    lines += [
        "---",
        "",
        "## 진단 우선순위 분류 (초안)",
        "",
        "| 우선순위 | 레포 | 진단 필요 skill | 비고 |",
        "|---|---|---|---|",
    ]
    for i, r in enumerate(result["ocb_repos"], 1):
        lines.append(
            f"| P{min(i, 3)} | `{r['repo_slug']}` "
            f"| injection, xss, file, data, sca | — |"
        )

    lines += [
        "",
        "---",
        "",
        "## 다음 단계",
        "",
        "```bash",
        "# 각 레포 진단 시작",
        "python3 tools/new_scan.py <repo_slug> --clone <PROJECT_KEY> <REPO_SLUG>",
        "# skill 실행: /sec-scan-injection → /sec-scan-xss → /sec-scan-file → /sec-scan-data → /sec-scan-sca",
        "```",
    ]
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OCB 서비스 군 Bitbucket 레포 전수 조사")
    parser.add_argument(
        "--projects", nargs="*", metavar="KEY",
        help="조회할 Bitbucket 프로젝트 키 목록 (미지정 시 자동 탐색)"
    )
    parser.add_argument(
        "--all-projects", action="store_true",
        help="전체 프로젝트 탐색 (시간이 걸릴 수 있음)"
    )
    parser.add_argument(
        "--out", metavar="PATH",
        help="결과 마크다운 저장 경로 (예: docs/ocb_repos.md)"
    )
    parser.add_argument(
        "--json", metavar="PATH",
        help="결과 JSON 저장 경로 (예: docs/ocb_repos.json)"
    )
    args = parser.parse_args()

    result = find_ocb_repos(
        target_projects=args.projects,
        all_projects=args.all_projects,
    )

    print(f"\n[3/3] 수집 완료: OCB 관련 레포 {len(result['ocb_repos'])}개\n")

    md = render_markdown(result)
    print(md)

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        print(f"\n[저장] 마크다운: {out}")

    if args.json:
        jout = Path(args.json)
        jout.parent.mkdir(parents=True, exist_ok=True)
        jout.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[저장] JSON: {jout}")


if __name__ == "__main__":
    main()
