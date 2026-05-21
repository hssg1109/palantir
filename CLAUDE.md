# palantir

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
palantir/
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

## Quick Start — 단일 레포 진단 절차

1. **Clone** (Windows PowerShell에서 실행 — WSL 불가):
   `python3 tools/clone_repo.py <PROJECT> <REPO>`
   - 소스코드 → `testbed/<repo>/`

2. **SAST 진단** — 5개 skill 순차 실행 (각각 `/sec-scan-injection` 등):
   - 자율 완주: 자산 식별 → Auto-Scan → LLM-Check → Summary 생성
   - `testbed/<repo>/` 소스코드는 보존 (보고서 검토 시 참조)

3. **인터랙티브 리뷰** — 5개 skill 완료 후 `/sec-review` 실행:
   ```
   /sec-review <RUN_ID> <repo>
   ```
   - finding별 정탐/오탐 판정 (`1`=정탐, `0`=오탐, `s`=스킵)

4. **최종 보고서 생성 + Confluence 게시**:
   ```bash
   python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo> --publish
   # → logs/final_<repo>_<RUN_ID>.md  (Confluence :::expand 매크로 포함)
   ```

> **진행 방향**: skill 단위로 전체 repo를 순차 진단 (injection 전체 → xss 전체 → ...)

## 관련 레포

| 레포 | 경로 | 역할 |
|---|---|---|
| palantir | `~/palantir/` | 진단 도구 및 skill (현재 레포) |
| palantir-testbed | `testbed/` | 고객사 소스코드 clone 저장소 |
| palantir-state | `state/` | 진단 결과 JSON / 보고서 저장소 |
| palantir-reports | `~/palantir-reports/` | 서비스별 1차보고서(final) 누적 저장소 |
| sec-audit-playbook | (private) | 전체 파이프라인 오케스트레이션, Confluence 게시 |
