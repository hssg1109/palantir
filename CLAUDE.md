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

## BOUNDARY RULE — Skill 실행 범위 제한

**자율 완주 규칙은 명시적으로 호출된 skill 내부에만 적용된다.**

### 1. Skill 간 자동 연결 금지

각 skill은 독립 실행 단위이며, 완료 후 다음 단계로 자동 이행하지 않는다.

| 금지 행위 | 올바른 동작 |
|-----------|------------|
| `/sec-scan-*` 완료 후 `/sec-review` 자동 실행 | skill 완료 요약 출력 후 대기 |
| 5개 scan skill 중 하나 완료 후 다음 scan skill 자동 실행 | 완료 요약 출력 후 대기 |

> **근거**: 각 skill 완료 후 사용자가 결과를 검토하고 다음 단계를 직접 지시해야 한다.

**예외 (2026-08-25, 사용자 명시적 지시)**: `/sec-review`는 인터랙티브 판정(§4~§5b) 완료 후,
`retroactive_cleanse.py`(testbed 삭제 + 클렌징 레지스트리 Confluence 게시) →
`approve_report.py --publish`(최종 보고서 생성 + Confluence 게시)까지 **자동으로 이어서 실행**한다.
이 구간(cleansing~report publish)은 findings 정탐/오탐 판정처럼 사람 판단이 필요한 단계가 아니라
이미 확정된 판정 결과를 기계적으로 반영하는 후속 처리이므로, 자율 완주 규칙의 정상 적용 대상으로
취급한다. 상세 절차는 `.claude/commands/sec-review.md` §5e/§6 참조.

### 2. Context Compaction 후 자동 재개 금지

Auto-compact에 의해 새 세션이 시작된 경우, compaction summary의 "Pending Tasks" 또는 "Optional Next Step"을 자동 실행하지 않는다.

**금지 행위:**
- Compaction summary의 pending tasks를 보고 자율 실행
- "이전 세션에서 진행 중이었으므로" 이유로 skill/script 자동 시작
- 사용자 메시지 없이 compaction 직후 즉시 작업 재개

**올바른 동작:**
- 새 세션 시작 시 중단 상태를 **요약만** 출력하고 다음 지시 대기
- 사용자가 명시적으로 재개 지시를 내릴 때까지 대기

**예외 (자동 재개 허용):**
- 사용자가 해당 세션에서 직접 skill을 호출하고, skill 실행 **도중**(Phase 중간)에 compaction이 발생한 경우  
  → 해당 skill의 현재 Phase만 재개 (다른 skill/단계로 이행 금지)

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
├── sec-scan-auth/           # 인증/인가/어뷰징 (Auth Bypass / IDOR / Mass Assignment / Rate Limit)
└── sec-scan-sca/            # 오픈소스 라이브러리 CVE (Gradle / npm)
```

## Available Skills

| Skill | 진단 항목 | 스크립트 |
|---|---|---|
| `/sec-scan-injection` | SQL/OS Command/SSI Injection | `shared/scripts/scan_injection_enhanced.py` |
| `/sec-scan-xss` | XSS 4종 (Persistent/Reflected/DOM/Redirect) | `shared/scripts/scan_xss.py` |
| `/sec-scan-file` | 파일 처리 취약점 (Upload/Download/LFI/RFI) | `shared/scripts/scan_file_processing.py` |
| `/sec-scan-data` | 데이터 보호 (CORS/Secrets/JWT/Crypto/PII) | `shared/scripts/scan_data_protection.py` |
| `/sec-scan-auth` | 인증/인가/어뷰징 (Auth Bypass/IDOR/Mass Assignment/Rate Limit/멱등성) | `shared/scripts/scan_auth_baseline.py` (판정 없는 후보 태깅, 최종 판정은 LLM-Check 전담) |
| `/sec-scan-sca` | 오픈소스 CVE 취약점 | `shared/scripts/scan_sca_gradle_tree.py` |

## Quick Start — 단일 레포 진단 절차

1. **Clone** (Windows PowerShell에서 실행 — WSL 불가):
   `python3 tools/clone_repo.py <PROJECT> <REPO>`
   - 소스코드 → `testbed/<repo>/`

2. **SAST 진단** — 5개 skill 순차 실행 (각각 `/sec-scan-injection` 등):
   - 자율 완주: 자산 식별 → Auto-Scan → LLM-Check → Summary 생성
   - `testbed/<repo>/` 소스코드는 보존 (보고서 검토 시 참조)

3. **인터랙티브 리뷰 → 클렌징 → 보고서 생성/게시** — 5개 skill 완료 후 `/sec-review` 실행:
   ```
   /sec-review <RUN_ID> <repo>
   ```
   - finding별 정탐/오탐 판정 (AskUserQuestion으로 클릭 선택)
   - 판정 완료 후 클렌징(`retroactive_cleanse.py`)과 최종 보고서 생성+Confluence 게시
     (`approve_report.py --publish`)까지 **자동으로 이어서 실행**됨(2026-08-25 갱신) —
     별도로 4번 단계를 수동 실행할 필요 없음

4. (참고) 필요 시 수동으로 보고서만 재생성하려면:
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
