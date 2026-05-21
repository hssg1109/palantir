---
name: sec-scan-injection
description: Modularized SAST skill for SQL Injection, OS Command Injection, and SSI Injection diagnosis on Spring/Kotlin/Java backends. Runs scan_injection_enhanced.py then LLM cross-verification. Use when asked to run injection scan, 인젝션 진단, or SQL/Command/SSI 취약점 분석 on a target in testbed/. Part of the broader sec-audit-static pipeline; future updates will include Jira integration.
tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
---

# Sec Scan Injection

## Overview
이 skill은 `sec-audit-static` 전체 파이프라인에서 **인젝션 취약점(SQL / OS Command / SSI)** 진단만을 담당하는 모듈입니다.

독립 실행 가능: `sec-scan-injection/` + `shared/scripts/scan_injection_enhanced.py`

향후 Jira 연동 기능이 추가될 예정입니다.

## Workflow

### Step 1: Load references

**로컬 (이 skill 전용)**
- `shared/references/task_prompts/task_11_asset_identification.md` - 자산 식별 절차
- `references/task_prompts/task_22_injection_review.md` - 인젝션 LLM 검토 절차 (SQL/OS Command/SSI)
- `references/injection_diagnosis_criteria.md` - 프레임워크별 인젝션 진단기준 (MyBatis/JPA/JDBC/Kotlin/R2DBC)

**공유 (shared/)**
- `shared/references/workflow.md` - Phase/Task 실행 맵, 보안 정책
- `shared/references/output_schemas.md` - JSON 출력 스키마
- `shared/references/severity_criteria.md` - 위험도 매핑
- `shared/references/cross_verification.md` - Phase 3-1 교차검증 + Phase 3-2 LLM 수동 심층진단 절차
- `shared/references/manual_review_prompt.md` - LLM 수동진단 페르소나, 진단기준, 답변원칙
- `shared/references/taint_tracking.md` - Source→Sink 추적 (Kotlin 패턴 포함)
- `shared/references/global_filters.md` - 글로벌 필터/인터셉터 검증
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
python3 tools/new_scan.py <repo> --skill injection --clone <PROJECT> <REPO>
# 예: python3 tools/new_scan.py ocb-community-api --skill injection --clone OCBWEBVIEW ocb-community-api
```

실행 결과로 출력되는 `state/<repo>/injection/<YYYYMMDD_HHMM>/` 경로를 skill 실행 시 입력할 것.

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
- PHP 등 미지원 언어이면 Auto-Scan Phase skip 후 기록

**Auto-Scan Phase — 인젝션 정적 분석 (Python 스크립트)**

> **scan_injection_enhanced.py는 `--api-inventory` 필수 인자**입니다.
> `scan_api.py`로 엔드포인트 목록을 먼저 추출해야 스크립트가 동작하며,
> 이 목록을 기반으로 **모든 API 엔드포인트를 빠짐없이 순회하며** Controller → Service → Repository 흐름을 추적합니다.
> API 인벤토리 없이는 per-endpoint 진단 자체가 불가합니다.

```bash
# Step 0: API 엔드포인트 목록 추출 (injection 스캔 필수 선행 작업)
python3 shared/scripts/scan_api.py <src> \
    -o state/<prefix>/api_scan.json

# Auto-Scan: 인젝션 스캔 (API 인벤토리 필수)
python3 shared/scripts/scan_injection_enhanced.py <src> \
    --api-inventory state/<prefix>/api_scan.json \
    -o state/<prefix>/injection.json
```

스크립트 자동 수행 항목:
- `api_scan.json`의 전체 endpoint를 순회 → **누락 없이** 1건씩 판정
- Controller → Service → Repository 호출 흐름 추적
- endpoint별 SQL Injection 양호/취약/정보 판정
- OS Command Injection, SSI Injection 전역 스캔 (endpoint 무관)

추가 옵션:
- Kotlin 코드베이스: Kotlin SQL Builder 5-method 감지 (`references/injection_diagnosis_criteria.md` 참조)
- 멀티 모듈: `--modules <모듈명>` 으로 범위 제한 가능
- Joern 흐름 기반 검증 사용 (CodeQL 사용 금지)
- 글로벌 필터/인터셉터 확인 (`shared/references/global_filters.md`)

출력: `state/<prefix>/injection.json` (endpoint별 취약/양호/정보 판정 포함)

LLM 검토 절차는 `references/task_prompts/task_22_injection_review.md` 전체 절차 준수.

**LLM-Check Phase — 교차검증 + 수동 심층진단 (LLM)**
- **LLM-Check Phase 1** (자동판정 "취약" 건): `shared/references/cross_verification.md` LLM-Check Phase 1 절차
  - Controller → Service → Repository → SQL Builder 데이터 흐름 추적
  - FP는 `diagnosis_method: "교차검증(수동)"` 으로 재분류
- **LLM-Check Phase 2** ("정보/수동검토" 건): `shared/references/cross_verification.md` LLM-Check Phase 2 + `manual_review_prompt.md`
  - 대상: `result: "정보"` + `needs_review: true`, `taint_confirmed: null`, `[잠재] 취약한 쿼리 구조`
  - 출력: `diagnosis_method: "수동진단(LLM)"` + `manual_review_note`

### Step 3: Output validation
- 모든 task 출력에 `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules` 포함 필수.
- JSON을 `shared/references/output_schemas.md` 스키마로 검증.

### Step 4: Summary 출력

LLM-Check Phase 완료 후 `state/<prefix>/summary_injection.md` 를 생성한다.

**읽을 파일**:
- `state/<prefix>/injection.json` — 스크립트 자동 판정 결과 (`endpoint_diagnoses`, `global_findings`)
- `state/<prefix>/task22_llm.json` — LLM 보완 findings (존재하는 경우)

**출력 형식**:

```markdown
# 인젝션 취약점 진단 결과 요약 — <repo명>

진단일: YYYY-MM-DD | 대상: <source_repo_url> | LLM 검증: 완료

## 결과 통계

| 판정 | 건수 |
|---|---|
| 취약 | N |
| 정보 | N |
| 양호 | N |
| 해당없음(DB접근없음) | N |
| **전체 endpoint** | **N** |

글로벌 스캔 — OS Command: N건 / SSI: N건

## Finding 목록

| ID | 제목 | 위험도 | 파일:라인 | 판정 | 진단방법 |
|---|---|---|---|---|---|
| INJ-001 | SQL Injection — OrderBy 동적 파라미터 | 5 매우위험 | src/.../Repo.java:120 | 취약 | 교차검증(수동) |

> 양호·해당없음 항목은 목록에서 제외. 취약·정보만 기재.

## 소스 파일
- `state/<prefix>/injection.json`
- `state/<prefix>/task22_llm.json` _(LLM 보완, 없으면 생략)_
```

**작성 규칙**:
- Finding 목록은 심각도 내림차순 (Critical → High → Medium → Low → Info)
- `affected_files` 또는 `evidence.file` + `evidence.lines` 에서 파일:라인 추출
- LLM 보완 findings(`task22_llm.json`)가 있으면 목록 하단에 이어 붙임
- 양호/해당없음은 통계에만 포함, 목록에는 미기재

### Step 4-1: LLM-Check 완료 확인 — 업로드 전 필수 게이트

> **HARD RULE**: `needs_review > 0` 이면서 `task22_llm.json` 미존재 상태로 업로드 금지.
> FN(오탐 누락) 위험이 있으므로 반드시 LLM-Check Phase 2를 먼저 완료할 것.

업로드 전 아래 명령으로 확인:

```bash
python3 -c "
import json, pathlib, sys
prefix = 'state/<prefix>'
s = json.load(open(f'{prefix}/injection_llm_summary.json'))
n = s.get('statistics', {}).get('needs_review', 0)
has_llm = pathlib.Path(f'{prefix}/task22_llm.json').exists()
if n > 0 and not has_llm:
    print(f'[BLOCK] needs_review={n}건인데 task22_llm.json 없음 — LLM-Check 먼저 수행', file=sys.stderr)
    sys.exit(1)
print(f'[OK] needs_review={n}  task22_llm={has_llm}')
"
```

통과 조건: `needs_review == 0` OR `task22_llm.json 존재`.

통과 조건 충족 후 `/sec-review` 로 인터랙티브 정/오탐 판정을 진행한다.

## Resources

### 로컬 (이 skill 폴더 내)
- `shared/references/task_prompts/task_11_asset_identification.md`
- `references/task_prompts/task_22_injection_review.md`
- `references/injection_diagnosis_criteria.md`

### 공유 (shared/references/)
#### Workflow & Policy
- `workflow.md`, `output_schemas.md`, `severity_criteria.md`

#### Diagnosis Criteria
- `cross_verification.md`, `manual_review_prompt.md`, `taint_tracking.md`, `global_filters.md`

#### Tooling & Rules
- `tooling.md`, `seed_usage.md`
- `large_repo_multi_module.md`, `unsupported_lang_targets.md`
- `rules/semgrep/kotlin-sql-string-template.yaml`
- `rules/semgrep/sql-string-format.yaml`
- `rules/semgrep/sql-utils-tosql.yaml`
- `rules/semgrep/elasticsearch-query-annotation.yaml`
- `rules/semgrep/entitymanager-native-query-concat.yaml`
- `rules/joern/taint_queries.sc`
