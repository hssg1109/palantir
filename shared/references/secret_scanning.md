# Secret Scanning

Primary tool: **Gitleaks**

Usage (preferred — external tool, run directly in shell):
```bash
gitleaks detect --source /path/to/repo --report-format json --report-path state/<prefix>/seed_gitleaks.json --redact --exit-code 0
```

Notes:
- `--redact`: 리포트에 실제 시크릿 값이 노출되지 않도록 마스킹. 항상 사용.
- `--exit-code 0`: findings가 있어도 CI/자동화가 실패하지 않도록. 항상 사용.
- Gitleaks 미설치 시 → `scan_data_protection.py`의 내장 패턴 탐지로 폴백 (Semgrep config-based checks).
