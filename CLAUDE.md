# sec-scan-skills

Claude Code 보안 진단 모듈 모음 — 취약점 유형별 독립 실행 가능한 SAST skill.

## HARD RULE — 자율 완주

**모든 skill 실행 중 다음을 절대 하지 말 것:**
- "Do you want to proceed?" 출력 금지
- "계속 진행할까요?" 출력 금지
- Phase 사이, Task 사이, 스크립트 실행 전후 **어떤 형태의 확인 질문도 금지**

**대신:**
- 오류 발생 시 → fallback 자동 적용 후 다음 단계 즉시 진행
- 유일한 예외: 토큰/자격증명 누락 등 사람만 해결 가능한 blocking 오류 → 보고 후 대기

## 레포 구조

```
sec-scan-skills/
├── shared/
│   ├── references/          # 모든 skill이 공유하는 진단 기준, 스키마, 정책
│   │   └── task_prompts/    # 공통 task 프롬프트 (task_11 자산 식별 등)
│   └── scripts/             # 공유 Python 스캐너 스크립트
├── sec-scan-injection/      # SQL / OS Command / SSI Injection
├── sec-scan-xss/            # Persistent / Reflected / DOM / Redirect XSS
├── sec-scan-file/           # File Upload / Download / LFI / RFI
├── sec-scan-data/           # CORS / Secrets / JWT / Cryptography / PII Logging
└── sec-scan-sca/            # 오픈소스 라이브러리 CVE (Gradle / npm)
```

## Available Skills

| Skill | 진단 항목 | 스크립트 |
|---|---|---|
| `/sec-scan-injection` | SQL/OS Command/SSI Injection | `shared/scripts/scan_injection_enhanced.py` |
| `/sec-scan-xss` | XSS 4종 (Persistent/Reflected/DOM/Redirect) | `shared/scripts/scan_xss.py` |
| `/sec-scan-file` | 파일 처리 취약점 (Upload/Download/LFI/RFI) | `shared/scripts/scan_file_processing.py` |
| `/sec-scan-data` | 데이터 보호 (CORS/Secrets/JWT/Crypto/PII) | `shared/scripts/scan_data_protection.py` |
| `/sec-scan-sca` | 오픈소스 CVE 취약점 | `shared/scripts/scan_sca_gradle_tree.py` |

## Quick Start

1. 대상 소스코드를 `testbed/<project>/` 에 위치시킴
2. 원하는 skill 실행 (예: `/sec-scan-injection`)
3. 결과는 `state/<prefix>/` 에 저장됨

## 관련 레포

- `sec-audit-playbook` (private): 전체 파이프라인 오케스트레이션, Confluence 게시, 고객사 설정
