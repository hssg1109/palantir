"""
secret_scan_gate.py — Bitbucket(palantir_result) 업로드 직전 최후 방어선.

2026-08-07 ocb-nft-batch AWS Access Key ID 노출 사고 재발방지용.
사고 원인: 상류(scan_data_protection.py의 자동 마스킹, generate_final_report.py의
:::expand 마스킹)가 Python 레포의 LLM 수동진단 경로나 메인 증거 코드블록을
거치지 않아, AWS_ACCESS_KEY_ID=AKIA... 값이 원문 그대로 findings_*.json /
final_*.md에 남은 채 push_audit_result.py가 아무 검사 없이 그대로 업로드했다.

이 모듈은 push 직전 실제로 전송될 파일들을 대상으로, 상류 마스킹이 다시
깨지거나 새 시크릿 유형을 놓치더라도 업로드 자체를 막는 하드 게이트다.
"""

from __future__ import annotations

import re
from pathlib import Path

# 값 포맷 자체로 식별 가능한 시크릿 (키 이름과 무관 — 오탐 위험이 매우 낮음)
_VALUE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key ID / STS Session Key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("PEM Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
]

# key = value / key: "value" 형태에서, 시크릿성 key 이름 뒤에 마스킹되지 않은
# 원문 값이 남아있는지 검사. _REDACTED로 시작하는 값은 이미 마스킹된 것으로 간주.
_KV_SECRET_RE = re.compile(
    r'(?i)\b(?P<key>password|passwd|pwd|secret|token|apikey|api[_-]key|'
    r'access[_-]?key(?:[_-]id)?|secret[_-]?key|client[_-]secret|'
    r'private[_-]key|signing[_-]key|hmac[_-]key|auth[_-]key)'
    r'\s*[=:]\s*(?P<quote>["\']?)(?P<value>[^\s"\',\]}]{6,})(?P=quote)'
)
_PLACEHOLDER_PREFIX_RE = re.compile(r"(?i)^\[?redact|^\*{3,}|^n/?a$|^null$|^none$|^true$|^false$")


def _scan_text(text: str) -> list[tuple[str, int]]:
    """text에서 발견된 위반 목록 [(label, line_no)] 반환."""
    hits: list[tuple[str, int]] = []
    for label, pattern in _VALUE_PATTERNS:
        for m in pattern.finditer(text):
            hits.append((label, text.count("\n", 0, m.start()) + 1))
    for m in _KV_SECRET_RE.finditer(text):
        value = m.group("value")
        if _PLACEHOLDER_PREFIX_RE.match(value):
            continue
        hits.append((f"미마스킹 자격증명 ({m.group('key')})", text.count("\n", 0, m.start()) + 1))
    return hits


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
        for label, line_no in _scan_text(text):
            messages.append(f"  [SECRET DETECTED] {p}:{line_no} — {label} (업로드 차단)")
    return messages
