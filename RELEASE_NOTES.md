# palantir — Release Notes

> 보안 진단 모듈 모음 (SAST + SCA). 취약점 유형별 독립 실행 가능한 Claude Code skill.

---

## v0.6.0 — 2026-06-18

### New Features

- **`/sec-review` Step 1b — 서비스 특징 분석 + 추가 진단 여부 입력**
  - 리뷰 시작 전 Claude가 `testbed/<repo>/` 소스를 분석하여 기술 스택·서비스 특징 도출
  - 진단자가 추가 진단 필요 여부 `y`/`n` 직접 입력 (자율 완주 예외 — 반드시 auditor 입력 대기)
  - `state/<repo>/review_meta.json`에 `service_characteristics` · `additional_diagnosis_needed` 저장
  - 기존 `review_meta.json`이 있으면 경로 B 분기 (재확인 or 스킵 선택)

- **진단 보고서 진단 개요 행 추가** (`generate_final_report.py`)
  - "서비스 특징": `review_meta.json` → `service_characteristics` 출력
  - "추가 진단 필요 여부": `additional_diagnosis_needed` → 필요/불필요 출력

- **`vuln_registry.json` v2.0 — 1 repo = 1 누적 JSON** (`tools/audit_utils.py`)
  - `schema_version: "2.0"`, `service_meta: {}`, `runs: []`, `findings: []`
  - `load_vuln_registry()`: v1.0 파일 자동 마이그레이션 (하위 호환)
  - `update_service_meta()`: `scan_meta.json` + `review_meta.json` → `service_meta` 동기화
  - `add_run_entry()`: 보고서 생성 시마다 `runs[]`에 기록 (run_id, confluence_url, finding_counts, report_path)

- **Jira 티켓 라벨 자동 생성** (`palantir-jira-gateway/lambda/jira_client.py`)
  - `_build_labels(repo, project)` → `[YYYY-MM, YYMM, "PALANTIR", project_key, "정기"]` 5개 자동 부여

- **Jira 티켓 본문 구조 전면 개편** (`palantir-jira-gateway/lambda/converter.py`)
  - 섹션 순서: 진단 개요(sec1) → [필수 회신] 안내 → 취약점 요약(sec2) → 참조 진단절차
  - `_split_sections()`: `## 1.x` / `## 2.x` 분리, `### 2.1` 개요 행 제외
  - [필수 회신] h2 헤딩: `{color:red}*필수 회신*{color}` 빨간 강조

- **Jira 티켓 처리 가이드 텍스트 개편** (`_TICKET_GUIDE`)
  - 패널 타이틀 제거, 색상 정리 (빨간색은 조치기한/조치계획만)
  - (2)번: "조치시작" 상태 변경 + 조치기한/조치계획 입력 안내
  - (3)번: 예외처리 방법 (담당자 협의 + 현업부서장 승인 경로)

- **신규 도구**
  - `tools/update_vuln_registry.py`: vuln_registry 수동 갱신/마이그레이션 CLI
  - `tools/ihaeng_compare.py`: 이행 점검 — 이전 진단 vs 최신 findings 비교

### Changed

- **`approve_report.py`**: 보고서 생성 후 `update_service_meta()` + `add_run_entry()` 자동 호출
- **`tools/audit_utils.py`** (신규 파일): `load_vuln_registry`, `update_service_meta`, `add_run_entry`, `log_report_published`, `update_registry_from_findings` 통합

### Bug Fixes

- **소스코드 저장소 URL 이중 출력** 수정
  - `generate_final_report.py`: `[URL](URL)` 마크다운 링크 → `URL` 평문으로 변경
  - `converter.py`: 테이블 셀 내 링크 변환 시 `continue`로 건너뛰던 버그 수정 → `[text|url]` 정상 변환

---

## v0.5.0 — 2026-05-08

### New Features

- **`approve_report.py` — Jira 직접 API → palantir-jira-gateway POST 방식 전환**
  - 로컬 FastAPI 서버(`palantir-jira-gateway`) 경유 티켓 생성
  - Markdown → Jira Wiki Markup 자동 변환 (`converter.py`)
  - 커스텀 필드(`조치회신 예시`) Wiki Markup description 지원

- **SCA findings 라이브러리 그룹핑** (`/sec-review` §4b)
  - 동일 `groupId:artifactId` 여러 CVE → 대표 finding 1건 + `group_cves[]` 병합
  - `review_status: "그룹병합"` — 보고서에서 자동 제외, 대표 finding 표로 통합 출력

- **`scan_sca_gradle_tree.py` 대폭 개선**
  - Gradle dependency tree 파싱 (간접 의존성 포함)
  - OSV.dev batch API 활용, 중복 제거 로직 강화
  - `llm_checked: true` 플래그 → `/sec-review` 일괄 자동 처리 연동

- **배치 진단 파이프라인** (`tools/pipeline_runner.py`)
  - `trigger/scan_targets.yaml` 기반 다수 레포 일괄 진단 자동화

### Changed

- `scan_injection_enhanced.py`: Taint-flow 추적 정확도 개선, False Positive 감소
- `task_25_data_protection.md`: PII 로그 위험도 기준 명시 (운영LOG=High, debugLOG=Medium, `@ToString`=Medium)

---

## v0.4.0 — 2026-04-27

### New Features

- **`/sec-review` — 인터랙티브 리뷰 skill 구현** (`.claude/commands/sec-review.md`)
  - 판정 루프: `1`=정탐 / `0`=오탐 / `s`=스킵 / `q`=종료
  - 정탐 후 결과 판정(취약/정보) + 위험도 조정 지원
  - 의견/질문 입력 시 `testbed/<repo>/` 소스코드 직접 확인·분석
  - `§4a` 지시사항 자동 실행 — `review_note` 내 "목록화 필요" 등 패턴 감지 시 codebase 탐색 후 실제 데이터로 교체
  - `§4b` SCA 일괄 처리 — `llm_checked: true` findings 자동 일괄 정탐 처리
  - Phase 2: 정탐 finding별 `report_expand` (보고서 상세 분석 블록) 자동 생성

- **`tools/approve_report.py` — 보고서 생성 + 배포 통합**
  - 오탐 필터링 → `generate_final_report.py` 호출 → Confluence 게시 → Jira 생성 → audit 업로드

- **`tools/generate_final_report.py` — Markdown 보고서 자동 생성**
  - 진단 개요 테이블, 취약점 목록, 상세 분석 (`:::expand` 블록) 자동 구성
  - 취약점 개요(2.1절) LLM 자동 생성

- **`tools/audit_utils.py` — 진단이력 JSON 관리 기반 마련**
  - `audit_log.json`: 전역 진단 이력 기록
  - `vuln_registry.json` v1.0: finding 누적 관리 기초

- **`push_audit_result.py` / `bulk_push_audit_result.py`**: Bitbucket `audit_result` 레포 업로드 자동화

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

- **이행 점검 자동화** (`ihaeng_compare.py` 고도화): 1차 진단 vs 재진단 결과 비교 보고서
- **배치 보고서 생성**: `pipeline_runner.py` → 다수 레포 일괄 approve_report 지원
- **vuln_registry 집계 대시보드**: 전체 레포 취약 현황 요약 출력

→ [ROADMAP.md](ROADMAP.md) 참조
