---
name: sec-scan-file
description: Modularized SAST skill for File Handling vulnerability diagnosis — File Upload, Download, LFI (Local File Inclusion), and RFI (Remote File Inclusion). Runs scan_file_processing.py then LLM cross-verification. Use when asked to run file handling scan, 파일 처리 진단, or 파일 업로드/다운로드 취약점 분석 on a target in testbed/. Part of the broader sec-audit-static pipeline; future updates will include Jira integration.
tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
---

# Sec Scan File

## Overview
이 skill은 `sec-audit-static` 전체 파이프라인에서 **파일 처리 취약점(Upload / Download / LFI / RFI)** 진단만을 담당하는 모듈입니다.

독립 실행 가능: `sec-scan-file/` + `shared/scripts/scan_file_processing.py`

향후 Jira 연동 기능이 추가될 예정입니다.

## Workflow

### Step 1: Load references

**로컬 (이 skill 전용)**
- `shared/references/task_prompts/task_11_asset_identification.md` - 자산 식별 절차
- `references/task_prompts/task_24_file_handling.md` - 파일 처리 LLM 검토 절차 (Upload/Download/LFI/RFI 판정기준 + 4종 수동진단 프롬프트)

**공유 (shared/)**
- `shared/references/workflow.md` - Phase/Task 실행 맵, 보안 정책
- `shared/references/output_schemas.md` - JSON 출력 스키마
- `shared/references/severity_criteria.md` - 위험도 매핑
- `shared/references/cross_verification.md` - Phase 3-1 교차검증 + Phase 3-2 LLM 수동 심층진단 절차
- `shared/references/manual_review_prompt.md` - LLM 수동진단 페르소나, 진단기준, 답변원칙
- `shared/references/taint_tracking.md` - Source→Sink 추적
- `shared/references/finding_writing_guide.md` - finding 품질 기준 (code_snippet 필수, 한국어 설명)
- `shared/references/tooling.md` - 코드 브라우저 도구 (rg/ctags)
- `shared/references/seed_usage.md` - Semgrep/Joern seed 규칙
- `shared/references/poc_policy.md` - PoC 생성 규칙
- `shared/references/large_repo_multi_module.md` - 대형 repo / 멀티 모듈 진단 전략
- `shared/references/unsupported_lang_targets.md` - 자동 스캔 미지원 언어 (PHP 등)

### 실행 원칙 (CRITICAL — 반드시 준수)

> **자율 완주 (Autonomous Execution)**: 실행 중에는
> "do you want to proceed?", "계속할까요?", "다음 단계로 진행할까요?" 등
> **어떠한 확인 질문도 하지 않는다.**
>
> - Phase 1 → Phase 2 → Phase 3 전 구간을 중단 없이 진행한다.
> - 스크립트 실패·빌드 오류·파일 없음 등 예상 범위 내 오류는 fallback을 자동 적용하고 계속 진행한다.
> - 예외: 토큰/자격증명 누락처럼 사람만 해결할 수 있는 blocking 오류 발생 시에만 보고 후 대기한다.

### Step 2: Execute tasks

**Phase 1**: 자산 식별.
- `shared/references/task_prompts/task_11_asset_identification.md` 절차 실행
- frontend/backend 판별, 언어/프레임워크 확인, 멀티 모듈 여부 확인
- PHP 등 미지원 언어이면 Phase 2 skip 후 기록

**Phase 2**: 파일 처리 취약점 정적 분석.

```bash
# scan_file_processing.py는 --modules 미지원 → 항상 전체 repo 스캔
# 모듈 범위 제한이 있는 경우 task_24_file_handling.md "Step 0: in-scope 필터링" 필수
python3 shared/scripts/scan_file_processing.py <src> \
    -o state/<prefix>/file.json
```

> **API 인벤토리 불필요**: 소스코드에서 `MultipartFile`, `FileInputStream`, `transferTo` 등
> 파일 처리 패턴을 직접 탐색하므로 `scan_api.py` 선행 실행 없이 단독 실행 가능합니다.

스크립트가 Upload / Download / LFI / RFI 엔드포인트를 감지하고 `needs_review` 플래그를 출력.
`needs_review: true` 항목에 대해 `references/task_prompts/task_24_file_handling.md`의 4종 LLM 프롬프트 템플릿 적용:
1. 프롬프트 1 — 다운로드 권한 검증 (IDOR/BOLA)
2. 프롬프트 2 — 업로드 검증 우회 (이중 확장자/Null Byte/MIME 스푸핑)
3. 프롬프트 3 — 파일 무해화 (Sanitization)
4. 프롬프트 4 — LFI/RFI View Resolver / Whitelist 우회

출력: `state/<prefix>/file.json` + `state/<prefix>/task24_llm.json` (LLM 보완)

**Phase 3**: 교차검증 + LLM 수동 심층진단.
- **Phase 3-1** (자동판정 "취약" 건): `shared/references/cross_verification.md` Phase 3-1 절차
  - 파일 경로 조작 가능성, 확장자 검증 우회, 서버 저장 위치 검증
  - FP는 `diagnosis_method: "교차검증(수동)"` 으로 재분류
- **Phase 3-2** ("정보/수동검토" 건): `shared/references/cross_verification.md` Phase 3-2 + `manual_review_prompt.md`
  - 대상: `result: "정보"` + `needs_review: true`, `taint_confirmed: null`
  - 출력: `diagnosis_method: "수동진단(LLM)"` + `manual_review_note`

### Step 3: Output validation
- 모든 task 출력에 `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules` 포함 필수.
- JSON을 `shared/references/output_schemas.md` 스키마로 검증.

### Step 4: Summary 출력

Phase 3 완료 후 `state/<prefix>/summary_file.md` 를 생성한다.

**읽을 파일**:
- `state/<prefix>/file.json` — 스크립트 자동 판정 결과 (`upload_diagnoses`, `download_diagnoses`, `rfi_diagnoses`)
- `state/<prefix>/task24_llm.json` — LLM 수동진단 보완 findings (존재하는 경우)

**출력 형식**:

```markdown
# 파일 처리 취약점 진단 결과 요약 — <repo명>

진단일: YYYY-MM-DD | 대상: <source_repo_url> | LLM 검증: 완료

## 결과 통계

| 카테고리 | 취약 | 정보 | 양호 |
|---|---|---|---|
| 파일 업로드 | N | N | N |
| 파일 다운로드 | N | N | N |
| LFI / RFI | N | N | N |
| **합계** | **N** | **N** | **N** |

## Finding 목록

| ID | 제목 | 심각도 | 카테고리 | 파일:라인 | 판정 | 진단방법 |
|---|---|---|---|---|---|---|
| FILE-001 | 파일 업로드 — 확장자 검증 누락 | High | Upload | src/.../FileController.java:55 | 취약 | 자동스캔(SAST) |

> 양호 항목은 목록에서 제외. 취약·정보만 기재.

## 소스 파일
- `state/<prefix>/file.json`
- `state/<prefix>/task24_llm.json` _(LLM 보완, 없으면 생략)_
```

**작성 규칙**:
- Finding 목록은 심각도 내림차순 (Critical → High → Medium → Low → Info)
- 카테고리는 Upload / Download / LFI / RFI 로 구분
- `evidence.file` + `evidence.lines` 에서 파일:라인 추출
- LLM 보완 findings(`task24_llm.json`)가 있으면 목록 하단에 이어 붙임
- 양호는 통계에만 포함, 목록에는 미기재

## Resources

### 로컬 (이 skill 폴더 내)
- `shared/references/task_prompts/task_11_asset_identification.md`
- `references/task_prompts/task_24_file_handling.md`

### 공유 (shared/references/)
#### Workflow & Policy
- `workflow.md`, `output_schemas.md`, `severity_criteria.md`

#### Diagnosis Criteria
- `cross_verification.md`, `manual_review_prompt.md`, `taint_tracking.md`

#### Tooling & Rules
- `tooling.md`, `seed_usage.md`, `poc_policy.md`
- `large_repo_multi_module.md`, `unsupported_lang_targets.md`
- `rules/joern/taint_queries.sc`
