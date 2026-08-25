"""
secret_scan_gate.py — Bitbucket(palantir_result) 업로드 직전 최후 방어선.

2026-08-07 ocb-nft-batch AWS Access Key ID 노출 사고 재발방지용.
사고 원인: 상류(scan_data_protection.py의 자동 마스킹, generate_final_report.py의
:::expand 마스킹)가 Python 레포의 LLM 수동진단 경로나 메인 증거 코드블록을
거치지 않아, AWS_ACCESS_KEY_ID=AKIA... 값이 원문 그대로 findings_*.json /
final_*.md에 남은 채 push_audit_result.py가 아무 검사 없이 그대로 업로드했다.

이 모듈은 push 직전 실제로 전송될 파일들을 대상으로, 상류 마스킹이 다시
깨지거나 새 시크릿 유형을 놓치더라도 업로드 자체를 막는 하드 게이트다.

실제 탐지 로직은 shared/scripts/secret_gate.py (공용 모듈)로 이관됨 —
이 파일은 파일 목록을 받아 스캔하는 얇은 wrapper만 유지한다.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared" / "scripts"))
import secret_gate  # noqa: E402


def scan_paths(paths: list[Path]) -> list[str]:
    """업로드 대상 파일들을 검사해 사람이 읽을 에러 메시지 목록 반환 (빈 리스트=통과)."""
    messages: list[str] = []
    for p in paths:
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for label, line_no in secret_gate.scan_text_with_lines(text):
            messages.append(f"  [SECRET DETECTED] {p}:{line_no} — {label} (업로드 차단)")
    return messages
