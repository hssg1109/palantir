# palantir — Release Notes

> 보안 진단 모듈 모음 (SAST + SCA). 취약점 유형별 독립 실행 가능한 Claude Code skill.

---

## v0.3.0 — 2026-04-14

### Breaking Changes
- **Phase 명칭 통일**: `Phase 2` → `Auto-Scan Phase`, `Phase 3` → `LLM-Check Phase`
  - 5개 SKILL.md, 관련 참조 문서, task_prompt 파일 전체 반영

### New Features
- **severity 통일** (`shared/references/severity_criteria.md` 전면 재작성)
  - 기준: 주요 정보통신기반시설 보호지침 (과학기술정보통신부 고시 제2021-28호)
  - 단일 체계: `Critical / High / Medium / Low / Informational` (5등급)
  - 기존 `Risk 1~5` 혼용 완전 제거
  - 매핑 미존재 항목은 LLM 판단

- **finding 정규화 — `auto_findings[]` / `evidence_trail[]`** (5개 스크립트 전체 적용)
  - 취약점 1건 = JSON 객체 1개 (`findings_*.json` 저장 단위)
  - `auto_findings[]`: 취약/정보 finding (`/sec-review` 판정 대상)
  - `evidence_trail[]`: 양호 항목 증적 (감사 trail 보존, 리뷰 제외)
  - F/N 처리: `fn_detected: true` + `source: "llm-check(fn-detected)"`
  - `scope.type`: `endpoint / file / config / dependency / global`

- **`findings_<skill>.json` 표준 스키마 정의** (`shared/references/output_schemas.md`)
  - 7단계 생성 절차 명시
  - FP 처리: `fp_corrected: true` + `result: "양호(FP)"` (삭제 금지)
  - finding_id 체계: `INJ-001`, `XSS-001`, `FILE-001`, `DATA-001`, `SCA-001`

- **5개 LLM 프롬프트에 `findings_<skill>.json` 생성 절차 추가**
  - `task_22_injection_review.md` → `findings_INJ.json`
  - `task_23_xss_review.md` → `findings_XSS.json`
  - `task_24_file_handling.md` → `findings_FILE.json`
  - `task_25_data_protection.md` → `findings_DATA.json`
  - `task_sca_llm_review.md` → `findings_SCA.json`

### Changed
- `scan_xss.py`: `"Info"` → `"Informational"` (4건)
- `scan_file_processing.py`: `"Info"` → `"Informational"` (6건)
- `scan_data_protection.py`: `"Info"` → `"Informational"` (14건)
- `scan_injection_enhanced.py`: `"Risk 5"` → `"Critical"`, `"Risk 4"` → `"High"`, `"Risk 2"` → `"Low"`

---

## v0.2.0 — 2026-04-07

### New Features
- `scan_injection_enhanced.py` — SQL/OS Command/SSI Injection 자동 진단 스크립트
- `scan_xss.py` — XSS 4종 (Reflected/View/Persistent/Redirect/DOM) 진단
- `scan_file_processing.py` — 파일 업로드/다운로드/RFI/SSRF 진단
- `scan_data_protection.py` — CORS/Secrets/JWT/Crypto/PII Logging 진단
- `scan_sca_gradle_tree.py` — Gradle/npm 의존성 CVE 진단 (OSV.dev 연동)
- LLM 교차검증 프롬프트 5종 (task_22~25 + task_sca_llm_review)

### Structure
- `shared/references/` — 공통 진단 기준, 스키마, severity 정책
- `shared/scripts/` — 공유 Python 스캐너 스크립트
- 5개 독립 skill 모듈 (sec-scan-injection/xss/file/data/sca)
- `.claude/commands/` — slash command 등록 (5종)

---

## v0.1.0 — 2026-03-31

### Initial Release
- `sec-scan-skills` → `palantir` 레포 명칭 확정
- 기본 디렉터리 구조 정립
- `shared/references/workflow.md`, `severity_criteria.md`, `output_schemas.md` 초안

---

## Upcoming

→ [ROADMAP.md](ROADMAP.md) 참조
