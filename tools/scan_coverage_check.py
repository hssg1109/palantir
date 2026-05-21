#!/usr/bin/env python3
"""
scan_coverage_check.py — 스캐너의 파일 커버리지(대상/제외) 빠른 점검 도구

목적:
  - repo에서 확장자별 파일 수를 집계
  - injection/xss 전역 스캔에서 사용하는 exclude 디렉터리 때문에 빠지는 상위 폴더를 요약

주의:
  - 실제 스캐너는 기능별로 확장자/제외 규칙이 조금씩 다릅니다.
  - 본 도구는 "대표 규칙"을 기준으로 빠르게 sanity check 하는 용도입니다.

사용 예:
  python3 tools/scan_coverage_check.py testbed/ocbwebview/ocb-community-api@master@7b76c77
  python3 tools/scan_coverage_check.py testbed/... --top 30
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


# injection: build_class_index / build_mybatis_index / global pattern scan 에서 쓰는 exclude 집합을 합집합으로 사용
_EXCLUDE_DIRS_INJECTION = {
    "node_modules", ".idea", "target", "build", ".git", "dist", "test",
}

# xss: scan_xss.py의 _EXCLUDE_DIRS (일부만 확인됨) + 흔한 빌드 산출물
_EXCLUDE_DIRS_XSS = {
    "node_modules", ".git", "__pycache__", "generated",
    "target", "build", ".idea", "dist",
}

# injection global scan에서 사용하는 대표 확장자(코드에서 확인된 것)
_INJECTION_GLOBAL_EXTS = {
    ".kt", ".java", ".xml", ".js", ".ts", ".jsx", ".tsx",
    ".php", ".py", ".cs", ".vb", ".groovy",
    ".html", ".shtml", ".stm", ".shtm", ".jsp", ".vue",
    ".ejs", ".njk", ".hbs",
}

# xss dom scan에서 사용하는 대표 확장자 + view 확장자 일부
_XSS_RELEVANT_EXTS = {
    ".kt", ".java", ".xml",
    ".js", ".ts", ".jsx", ".tsx", ".vue",
    ".jsp", ".html", ".htm",
}


@dataclass(frozen=True)
class ExcludeHit:
    exclude_dir: str
    top_folder: str


def _top_folder(rel: Path) -> str:
    parts = rel.parts
    return parts[0] if parts else "."


def _has_any_exclude(rel: Path, excludes: set[str]) -> str | None:
    for p in rel.parts:
        if p in excludes:
            return p
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="palantir 스캐너 커버리지(대상/제외) 빠른 점검")
    ap.add_argument("source_dir", type=Path, help="소스코드 루트 디렉터리 (testbed/... 경로)")
    ap.add_argument("--top", type=int, default=20, help="exclude 상위 폴더 요약 출력 개수 (기본 20)")
    args = ap.parse_args()

    source_dir: Path = args.source_dir
    if not source_dir.exists():
        raise SystemExit(f"Error: 소스 디렉터리 미존재: {source_dir}")

    # 전체 파일 walk (rglob는 빠르지만, 여기서는 파일 수 집계가 목적)
    files: list[Path] = [p for p in source_dir.rglob("*") if p.is_file()]

    # 확장자별 전체 분포 (스캔 대상이 아닌 파일도 참고용으로 포함)
    all_exts = Counter((p.suffix.lower() or "<noext>") for p in files)

    def count_target(exts: set[str], excludes: set[str]) -> tuple[int, Counter]:
        cnt = 0
        by_ext = Counter()
        for p in files:
            rel = p.relative_to(source_dir)
            if _has_any_exclude(rel, excludes):
                continue
            suf = p.suffix.lower()
            if suf in exts:
                cnt += 1
                by_ext[suf] += 1
        return cnt, by_ext

    inj_cnt, inj_by_ext = count_target(_INJECTION_GLOBAL_EXTS, _EXCLUDE_DIRS_INJECTION)
    xss_cnt, xss_by_ext = count_target(_XSS_RELEVANT_EXTS, _EXCLUDE_DIRS_XSS)

    # exclude로 빠지는 상위 폴더(최상위 디렉터리) 집계
    def exclude_summary(excludes: set[str]) -> tuple[Counter, dict[ExcludeHit, int]]:
        top_counts = Counter()
        hit_counts: dict[ExcludeHit, int] = defaultdict(int)
        for p in files:
            rel = p.relative_to(source_dir)
            ex = _has_any_exclude(rel, excludes)
            if not ex:
                continue
            top = _top_folder(rel)
            top_counts[top] += 1
            hit_counts[ExcludeHit(exclude_dir=ex, top_folder=top)] += 1
        return top_counts, hit_counts

    inj_top, inj_hits = exclude_summary(_EXCLUDE_DIRS_INJECTION)
    xss_top, xss_hits = exclude_summary(_EXCLUDE_DIRS_XSS)

    # 출력
    print("[coverage] source_dir:", str(source_dir))
    print("[coverage] total_files:", len(files))
    print()

    print("[all files] ext distribution (top 15):")
    for ext, n in all_exts.most_common(15):
        print(f"  - {ext}: {n}")
    print()

    print("[injection-like] target exts:", ", ".join(sorted(_INJECTION_GLOBAL_EXTS)))
    print("[injection-like] exclude dirs:", ", ".join(sorted(_EXCLUDE_DIRS_INJECTION)))
    print("[injection-like] included target files:", inj_cnt)
    for ext, n in inj_by_ext.most_common():
        print(f"  - {ext}: {n}")
    print()

    print("[xss-like] target exts:", ", ".join(sorted(_XSS_RELEVANT_EXTS)))
    print("[xss-like] exclude dirs:", ", ".join(sorted(_EXCLUDE_DIRS_XSS)))
    print("[xss-like] included target files:", xss_cnt)
    for ext, n in xss_by_ext.most_common():
        print(f"  - {ext}: {n}")
    print()

    print(f"[excluded (injection-like)] top folders by excluded file count (top {args.top}):")
    for top, n in inj_top.most_common(args.top):
        print(f"  - {top}: {n}")
    if inj_top:
        print("  (breakdown by exclude_dir within top folders, top 25)")
        for hit, n in sorted(inj_hits.items(), key=lambda kv: kv[1], reverse=True)[:25]:
            print(f"    - {hit.top_folder} / {hit.exclude_dir}: {n}")
    print()

    print(f"[excluded (xss-like)] top folders by excluded file count (top {args.top}):")
    for top, n in xss_top.most_common(args.top):
        print(f"  - {top}: {n}")
    if xss_top:
        print("  (breakdown by exclude_dir within top folders, top 25)")
        for hit, n in sorted(xss_hits.items(), key=lambda kv: kv[1], reverse=True)[:25]:
            print(f"    - {hit.top_folder} / {hit.exclude_dir}: {n}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

