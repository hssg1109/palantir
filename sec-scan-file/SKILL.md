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
- `shared/references/large_repo_multi_module.md` - 대형 repo / 멀티 모듈 진단 전략
- `shared/references/unsupported_lang_targets.md` - 자동 스캔 미지원 언어 (PHP 등)

### ⚠️ 사전 필수 — 소스코드 Clone

> testbed/ 에 소스코드가 없으면 진단을 시작할 수 없다.
> **WSL에서 직접 아래 명령을 실행한다.** clone_repo.py가 자동으로 PowerShell(Windows git)을 경유하여 Bitbucket에 접근한다.

```bash
# WSL(Ubuntu) 터미널에서 실행
python3 tools/clone_repo.py <PROJECT> <REPO>
# 예: python3 tools/clone_repo.py OCBWEBVIEW ocb-community-api
```

실행 결과로 출력되는 `state/<repo>/file/<YYYYMMDD_HHMM>/` 경로를 skill 실행 시 입력할 것.

testbed/ 에 소스코드가 없으면 **위 명령을 직접 실행하고 clone 완료 후 진단을 이어서 진행**한다.

---

### 실행 원칙 (CRITICAL — 반드시 준수)

> **자율 완주 (Autonomous Execution)**: 실행 중에는
> "do you want to proceed?", "계속할까요?", "다음 단계로 진행할까요?" 등
> **어떠한 확인 질문도 하지 않는다.**
>
> - 자산 식별 → Auto-Scan → LLM-Check 전 구간을 중단 없이 진행한다.
> - 스크립트 실패·빌드 오류·파일 없음 등 예상 범위 내 오류는 fallback을 자동 적용하고 계속 진행한다.
> - 예외: 토큰/자격증명 누락처럼 사람만 해결할 수 있는 blocking 오류 발생 시에만 보고 후 대기한다.

### Step 2: Execute tasks

**Phase 1 — 자산 식별 (Asset Identification)**
- `shared/references/task_prompts/task_11_asset_identification.md` 절차 실행
- frontend/backend 판별, 언어/프레임워크 확인, 멀티 모듈 여부 확인
- PHP 등 미지원 언어이면 `task_11_asset_identification.md` §1-5에 따라 `/sec-scan-php`로 위임 실행(최초 1회, idempotent) 후 이 skill의 Auto-Scan Phase는 skip 후 기록
- Python이면 `task_11_asset_identification.md` §1-6에 따라 `python_diagnosis_criteria.md` §2-3(File) 기준으로 이 skill이 직접 수동 진단(전담 위임 skill 없음, Auto-Scan skip)

**Phase 1 → Auto-Scan 분기 결정**

| 레포 유형 | 판별 기준 | Auto-Scan 동작 |
|-----------|-----------|----------------|
| 순수 백엔드 (Java/Kotlin) | `.java`/`.kt` ≥ 5개, `package.json` 없음 | 기존 Java 스캔 실행 (Upload/Download/LFI/RFI/Config) |
| 순수 프론트엔드 (TS/JS) | `.java`/`.kt` < 5개 + `package.json` 존재 | `scan_uploads_frontend()` + `scan_downloads_frontend()` 실행 (FormData/FileReader/Blob) |
| 풀스택 (Java + TS) | `.java`/`.kt` ≥ 5개 + `package.json` 존재 | Java 스캔 실행 (현재) — 추후 양쪽 스캔으로 확장 예정 |
| PHP / 미지원 언어 | `.php` 주요 파일 존재 | Auto-Scan skip, `/sec-scan-php`로 위임(§1-5, 최초 1회) 후 기록 |

> **스크립트 자동 감지**: `_is_frontend_repo()` 함수가 Java/Kotlin 파일 수와 `package.json` 존재 여부를 자동 판별하므로 `scan_file_processing.py` 실행 시 별도 플래그 불필요.

**Auto-Scan Phase — 파일 처리 취약점 정적 분석 (Python 스크립트)**

```bash
# scan_file_processing.py는 --modules 미지원 → 항상 전체 repo 스캔
# 모듈 범위 제한이 있는 경우 task_24_file_handling.md "Step 0: in-scope 필터링" 필수
python3 shared/scripts/scan_file_processing.py <src> \
    -o state/<prefix>/file.json
```

> **API 인벤토리 불필요**: 소스코드에서 `MultipartFile`, `FileInputStream`, `transferTo` 등
> 파일 처리 패턴을 직접 탐색하므로 `scan_api.py` 선행 실행 없이 단독 실행 가능합니다.

스크립트가 Upload / Download / LFI / RFI 엔드포인트를 감지하고 `needs_review` 플래그를 출력.

**백엔드 모드** — `needs_review: true` 항목에 대해 `references/task_prompts/task_24_file_handling.md`의 4종 LLM 프롬프트 템플릿 적용:
1. 프롬프트 1 — 다운로드 권한 검증 (IDOR/BOLA)
2. 프롬프트 2 — 업로드 검증 우회 (이중 확장자/Null Byte/MIME 스푸핑)
3. 프롬프트 3 — 파일 무해화 (Sanitization)
4. 프롬프트 4 — LFI/RFI View Resolver / Whitelist 우회

**프론트엔드 모드** — `needs_review: true` 항목에 대해 `task_24_file_handling.md`의 [Frontend] 섹션 판정 기준 적용:
- FormData MIME/크기 미검증 → Medium 정보
- FileReader → innerHTML/eval 위험 싱크 → High 취약
- `<input type="file">` accept 미설정 → Low 정보
- Blob URL 다운로드 파일명 미검증 → Low 정보

출력: `state/<prefix>/file.json` + `state/<prefix>/task24_llm.json` (LLM 보완)

**LLM-Check Phase — 교차검증 + 수동 심층진단 (LLM)**
- **LLM-Check Phase 1** (자동판정 "취약" 건): `shared/references/cross_verification.md` LLM-Check Phase 1 절차
  - 파일 경로 조작 가능성, 확장자 검증 우회, 서버 저장 위치 검증
  - FP는 `diagnosis_method: "교차검증(수동)"` 으로 재분류
- **LLM-Check Phase 2** ("정보/수동검토" 건): `shared/references/cross_verification.md` LLM-Check Phase 2 + `manual_review_prompt.md`
  - 대상: `result: "정보"` + `needs_review: true`, `taint_confirmed: null`
  - 출력: `diagnosis_method: "수동진단(LLM)"` + `manual_review_note`

### Step 3: Output validation
- 모든 task 출력에 `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules` 포함 필수.
- JSON을 `shared/references/output_schemas.md` 스키마로 검증.

### Step 4: Summary 출력

LLM-Check Phase 완료 후 `state/<prefix>/summary_file.md` 를 생성한다.

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

| ID | 제목 | 위험도 | 카테고리 | 파일:라인 | 판정 | 진단방법 |
|---|---|---|---|---|---|---|
| FILE-001 | 파일 업로드 — 확장자 검증 누락 | 5 매우위험 | Upload | src/.../FileController.java:55 | 취약 | 자동스캔(SAST) |

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

### Step 4-1: LLM-Check 완료 확인 — sec-review 전 필수 확인

> **HARD RULE**: `task24_llm.json` 미존재 상태로 sec-review 진행 금지.
> LLM-Check Phase 없이는 FP/FN 미검증 finding이 그대로 리뷰 대상에 포함된다.
> `findings_FILE.json` 생성 시 반드시 `llm_checked: true` 설정.

확인 스크립트:
```bash
python3 -c "
import pathlib, sys
prefix = 'state/<prefix>'
has_llm = pathlib.Path(f'{prefix}/task24_llm.json').exists()
findings = pathlib.Path(f'{prefix}/findings_FILE.json')
if not has_llm:
    print('[BLOCK] task24_llm.json 없음 — LLM-Check 먼저 수행', file=sys.stderr); sys.exit(1)
if findings.exists():
    import json
    d = json.loads(findings.read_text())
    if not d.get('llm_checked', False):
        print('[BLOCK] findings_FILE.json llm_checked=false', file=sys.stderr); sys.exit(1)
print('[OK] LLM-Check 완료 확인')
"
```

통과 조건 충족 후 Phase C-1을 수행한다.

### Step 4-2: 사람 판정 필드 침범 금지 (HARD RULE)

> **HARD RULE**: 이 skill(Auto-Scan/LLM-Check 어느 단계도)은 `reviewed`/`review_status` 필드를 직접 설정하지 않는다.
> 이 두 필드는 `/sec-review` §4의 사람 판정에서만 부여되며, `tools/audit_utils.py log-review` 호출로 `state/audit_log.json`에 기록되는 것만이 유효한 판정 경로다.
> LLM-Check가 TP로 확정한 finding이라도 `llm_verdict: "TP"` / `manual_review_note` 까지만 기록하고 `reviewed`/`review_status`는 미기재 상태로 남겨, 예외 없이 `/sec-review`를 거치도록 한다.
> (2026-08-03 displayadmin_server XSS-001 — LLM-Check 판정이 사람 판정 필드에 유출되어 `/sec-review`를 우회한 채 보고서에 반영된 사고 재발 방지. `/sec-review` §1a가 audit_log 대조로 이런 유출을 탐지·재편입하지만, 애초에 이 skill 단계에서 설정하지 않는 것이 원칙이다.)

---

### Step C: Phase C-1 — LLM 데이터 접근 로그 업데이트

> **정책**: `shared/references/llm_data_cleansing_policy.md` | **절차**: `shared/references/phase_c_cleansing.md`

LLM-Check 완료 직후 수행. **testbed는 이 단계에서 삭제하지 않는다** (이후 data/sca 진단에 필요).  
testbed 삭제 + Confluence 등록은 `/sec-review` 완료 시 Phase C-2에서 수행.

**수행**:

1. 이 세션에서 `testbed/<repo>/` 경로를 Read 도구로 접근한 파일 목록 정리 (Phase 1 / Phase 3 구분)
2. `state/<repo>/llm_data_access_log.json` 생성(없으면) 또는 `skills[]` 배열에 file 항목 append:
   ```json
   {
     "skill": "file",
     "scan_dir": "state/<repo>/file/<YYYYMMDD_HHMM>",
     "scanned_at": "<진단 시작 ISO8601 +09:00>",
     "llm_accessed_files": [
       { "phase": "Phase 1 - Asset Identification", "purpose": "자산 식별", "files": ["testbed/<repo>/build.gradle", "..."] },
       { "phase": "Phase 3 - LLM-Check", "purpose": "교차검증", "files": ["testbed/<repo>/src/..."] }
     ]
   }
   ```
3. 신규 생성 시 `project`는 `state/<repo>/20*/scan_meta.json`의 `bb_project` 값 사용 (없으면 `"?"`)
4. `cleansing_completed: false` 유지

**완료 출력**:
```
[Phase C-1] llm_data_access_log.json 업데이트 완료
  skill  : file
  접근파일: N건 (Phase 1: N / Phase 3: N)
  로그   : state/<repo>/llm_data_access_log.json
  [다음] /sec-review 완료 시 testbed 삭제 + Confluence 레지스트리 등록 수행
```

### Step C-1b: 전사 진단현황 위키 갱신 (필수 — 매 skill 완료마다)

> **정책**: 야간 배치뿐 아니라 주간 인터랙티브 세션에서 `/sec-scan-*`를 실행한 경우도 예외
> 없이 이 단계를 수행한다. 두 스크립트 모두 `state/`(및 `docs/ocb_scan_plan.md` 체크리스트)를
> 다시 읽어 재계산하는 읽기 전용 집계이므로 `/sec-review` 판정 완료 여부와 무관하게 즉시
> 실행 가능하다 (2026-09-08 ONEIDPASS 배치 후 위키 미갱신 사고 재발 방지, 2026-09-08 재수정 —
> 최초 버전이 실제 정책상 추적 페이지가 아닌 부차적 집계 페이지만 갱신하던 오류 수정).

> **⚠️ 두 페이지 모두 갱신 필수 — 하나만 갱신하면 안 됨**:
> - `docs/ocb_scan_plan.md` → Confluence pageId `750459063` — **실제 진단현황 갱신·추적이
>   진행되는 정책상 원본(authoritative) 페이지**. `update_ocb_plan.py --auto`가 `state/`를
>   스캔해 레포별 skill 체크리스트(❌→✅)를 갱신하고 곧바로 이 페이지에 동기화한다.
> - `docs/system_code_scan_status.md` → Confluence pageId `771074589` — 전사 297개
>   시스템코드 단위의 더 넓은 집계 뷰. `750459063`의 체크리스트를 우선(sticky) 참조하므로
>   반드시 **`update_ocb_plan.py --auto`를 먼저 실행한 뒤** 재생성해야 최신 상태가 반영된다.

**수행 (반드시 이 순서로)**:

```bash
python3 tools/update_ocb_plan.py --auto
python3 tools/build_system_code_scan_status.py
python3 tools/publish_confluence.py docs/system_code_scan_status.md
```

- 1번째 명령은 `docs/ocb_scan_plan.md`에 해당 레포 행이 있을 때만 체크리스트를 갱신하고
  `750459063`에 자동 동기화한다(레포가 체크리스트에 없으면 이 부분은 조용히 no-op).
- 3번째 명령은 `docs/.confluence_pages.json`에 등록된 기존 page_id(`771074589`)로 자동
  갱신한다 (최초 게시가 아니라면 `--parent`/`--title` 불필요).
- Confluence 접근 실패(네트워크/토큰) 시 → 에러 원문을 출력하고 계속 진행(blocking 아님).
  단, 실패 원인이 `.env`의 `CONFLUENCE_TOKEN` 누락처럼 사람만 해결 가능한 경우는 보고 후 대기.

**완료 출력**:
```
[Step C-1b] 전사 진단현황 위키 갱신 완료
  체크리스트 : docs/ocb_scan_plan.md → pageId 750459063
  전사집계   : docs/system_code_scan_status.md → pageId 771074589
```

Step C-1b 완료 후 `/sec-review` 로 인터랙티브 정/오탐 판정을 진행한다.

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
- `tooling.md`, `seed_usage.md`
- `large_repo_multi_module.md`, `unsupported_lang_targets.md`
- `rules/joern/taint_queries.sc`
